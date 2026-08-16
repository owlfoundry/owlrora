use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use uuid::Uuid;

use crate::{adapters::coordinator::TargetHealthCategory, runtime::CircuitPolicySnapshot};

use super::Candidate;

const MAX_TRACKED_DOMAINS: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TargetProtectionError {
    CircuitOpen,
    CapacityExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LocalTargetHealth {
    pub category: TargetHealthCategory,
    pub cooldown_remaining: Option<Duration>,
    pub recovery_elapsed: Option<Duration>,
    pub health_epoch: Uuid,
}

#[derive(Debug)]
pub(crate) struct TargetProtectionState {
    global: Arc<Semaphore>,
    endpoint: CapacityDomain,
    credential: CapacityDomain,
    deployment: CapacityDomain,
    circuits: Arc<Mutex<CircuitStates>>,
}

#[derive(Debug)]
struct CapacityDomain {
    limit: usize,
    entries: Mutex<HashMap<Uuid, Arc<Semaphore>>>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum CircuitDomain {
    Endpoint {
        id: Uuid,
        client_binding: [u8; 32],
    },
    Credential {
        id: Uuid,
        state_identity_version: u64,
        secret_version: i64,
        client_binding: [u8; 32],
    },
    Deployment {
        id: Uuid,
        config_version: u64,
        client_binding: [u8; 32],
    },
}

#[derive(Debug, Default)]
struct CircuitStates {
    entries: HashMap<CircuitDomain, CircuitEntry>,
}

#[derive(Debug)]
struct CircuitEntry {
    consecutive_failures: u64,
    consecutive_successes: u64,
    open_until: Option<Instant>,
    half_open_in_flight: u64,
    recovery_started_at: Option<Instant>,
    recovery_until: Option<Instant>,
    reopen_count: u32,
    health_epoch: Uuid,
    last_touched: Instant,
}

pub(crate) struct TargetAttemptPermit {
    circuits: Arc<Mutex<CircuitStates>>,
    circuit_domains: [CircuitDomain; 3],
    circuit_tokens: [Option<Instant>; 3],
    circuit_policy: CircuitPolicySnapshot,
    capacity_permits: Vec<OwnedSemaphorePermit>,
    observed: bool,
}

impl std::fmt::Debug for TargetAttemptPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TargetAttemptPermit")
            .field("circuit_domains", &self.circuit_domains)
            .field("capacity_permits", &self.capacity_permits.len())
            .field("observed", &self.observed)
            .finish_non_exhaustive()
    }
}

impl TargetProtectionState {
    #[must_use]
    pub(crate) fn new(
        global_limit: usize,
        endpoint_limit: usize,
        credential_limit: usize,
        deployment_limit: usize,
    ) -> Self {
        Self {
            global: Arc::new(Semaphore::new(global_limit)),
            endpoint: CapacityDomain::new(endpoint_limit),
            credential: CapacityDomain::new(credential_limit),
            deployment: CapacityDomain::new(deployment_limit),
            circuits: Arc::new(Mutex::new(CircuitStates::default())),
        }
    }

    pub(crate) fn try_acquire_global(&self) -> Result<OwnedSemaphorePermit, TargetProtectionError> {
        Arc::clone(&self.global)
            .try_acquire_owned()
            .map_err(|_| TargetProtectionError::CapacityExhausted)
    }

    pub(crate) fn try_acquire_target(
        &self,
        candidate: &Candidate,
        policy: &CircuitPolicySnapshot,
    ) -> Result<TargetAttemptPermit, TargetProtectionError> {
        let domains = circuit_domains(candidate);
        let circuit_tokens = acquire_circuits(&self.circuits, &domains, policy)?;

        let capacity = [
            self.endpoint
                .try_acquire(candidate.deployment.endpoint_id.as_uuid()),
            self.credential
                .try_acquire(candidate.deployment.credential_id.as_uuid()),
            self.deployment
                .try_acquire(candidate.deployment.id.as_uuid()),
        ];
        let mut permits = Vec::with_capacity(capacity.len());
        for result in capacity {
            match result {
                Ok(permit) => permits.push(permit),
                Err(error) => {
                    release_unobserved_circuits(&self.circuits, &domains, &circuit_tokens);
                    return Err(error);
                }
            }
        }
        Ok(TargetAttemptPermit {
            circuits: Arc::clone(&self.circuits),
            circuit_domains: domains,
            circuit_tokens,
            circuit_policy: policy.clone(),
            capacity_permits: permits,
            observed: false,
        })
    }

    pub(crate) fn local_health(&self, candidate: &Candidate) -> LocalTargetHealth {
        let domains = circuit_domains(candidate);
        let now = Instant::now();
        let mut states = self.circuits.lock().expect("circuit state mutex poisoned");
        for domain in &domains {
            if let Some(entry) = states.entries.get_mut(domain) {
                finish_recovery_if_elapsed(entry, now);
            }
        }
        let entries = domains
            .iter()
            .filter_map(|domain| states.entries.get(domain))
            .collect::<Vec<_>>();
        let cooldown_remaining = entries
            .iter()
            .filter_map(|entry| entry.open_until)
            .filter(|until| *until > now)
            .map(|until| until.duration_since(now))
            .max();
        let recovery = entries
            .iter()
            .filter_map(|entry| {
                entry
                    .recovery_started_at
                    .map(|started| (started, entry.health_epoch))
            })
            .max_by_key(|(started, _)| *started);
        let category = if cooldown_remaining.is_some() {
            TargetHealthCategory::Open
        } else if entries.iter().any(|entry| entry.open_until.is_some()) || recovery.is_some() {
            TargetHealthCategory::Recovering
        } else if entries.iter().any(|entry| entry.consecutive_failures > 0) {
            TargetHealthCategory::Degraded
        } else if entries.is_empty() {
            TargetHealthCategory::Unavailable
        } else {
            TargetHealthCategory::Healthy
        };
        let (recovery_elapsed, recovery_epoch) = recovery
            .map_or((None, None), |(started, epoch)| {
                (Some(now.duration_since(started)), Some(epoch))
            });
        let health_epoch = recovery_epoch.unwrap_or_else(|| {
            entries
                .iter()
                .map(|entry| entry.health_epoch)
                .max()
                .unwrap_or_else(Uuid::nil)
        });
        LocalTargetHealth {
            category,
            cooldown_remaining,
            recovery_elapsed,
            health_epoch,
        }
    }
}

fn circuit_domains(candidate: &Candidate) -> [CircuitDomain; 3] {
    [
        CircuitDomain::Endpoint {
            id: candidate.deployment.endpoint_id.as_uuid(),
            client_binding: candidate.client_build_fingerprint,
        },
        CircuitDomain::Credential {
            id: candidate.deployment.credential_id.as_uuid(),
            state_identity_version: candidate.deployment.credential_state_identity_version,
            secret_version: candidate.deployment.credential_secret_version,
            client_binding: candidate.client_build_fingerprint,
        },
        CircuitDomain::Deployment {
            id: candidate.deployment.id.as_uuid(),
            config_version: candidate.deployment.config_version,
            client_binding: candidate.client_build_fingerprint,
        },
    ]
}

impl CapacityDomain {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn try_acquire(&self, id: Uuid) -> Result<OwnedSemaphorePermit, TargetProtectionError> {
        let semaphore = {
            let mut entries = self.entries.lock().expect("capacity state mutex poisoned");
            if !entries.contains_key(&id) && entries.len() >= MAX_TRACKED_DOMAINS {
                entries.retain(|_, semaphore| Arc::strong_count(semaphore) > 1);
            }
            if !entries.contains_key(&id) && entries.len() >= MAX_TRACKED_DOMAINS {
                return Err(TargetProtectionError::CapacityExhausted);
            }
            Arc::clone(
                entries
                    .entry(id)
                    .or_insert_with(|| Arc::new(Semaphore::new(self.limit))),
            )
        };
        semaphore
            .try_acquire_owned()
            .map_err(|_| TargetProtectionError::CapacityExhausted)
    }
}

impl TargetAttemptPermit {
    pub(crate) fn success(mut self) {
        observe_circuits(
            &self.circuits,
            &self.circuit_domains,
            &self.circuit_tokens,
            &self.circuit_policy,
            true,
        );
        self.observed = true;
    }

    pub(crate) fn failure(mut self) {
        observe_circuits(
            &self.circuits,
            &self.circuit_domains,
            &self.circuit_tokens,
            &self.circuit_policy,
            false,
        );
        self.observed = true;
    }
}

impl Drop for TargetAttemptPermit {
    fn drop(&mut self) {
        if !self.observed {
            release_unobserved_circuits(
                &self.circuits,
                &self.circuit_domains,
                &self.circuit_tokens,
            );
        }
    }
}

fn acquire_circuits(
    states: &Arc<Mutex<CircuitStates>>,
    domains: &[CircuitDomain; 3],
    policy: &CircuitPolicySnapshot,
) -> Result<[Option<Instant>; 3], TargetProtectionError> {
    let now = Instant::now();
    let mut states = states.lock().expect("circuit state mutex poisoned");
    if states.entries.len() >= MAX_TRACKED_DOMAINS {
        states.entries.retain(|_, entry| {
            entry.half_open_in_flight > 0
                || entry.open_until.is_some_and(|until| until > now)
                || now.duration_since(entry.last_touched) < Duration::from_secs(300)
        });
    }
    if domains
        .iter()
        .any(|domain| !states.entries.contains_key(domain))
        && states.entries.len().saturating_add(domains.len()) > MAX_TRACKED_DOMAINS
    {
        return Err(TargetProtectionError::CircuitOpen);
    }

    let mut tokens = [None; 3];
    let initial_epoch = Uuid::now_v7();
    for (index, domain) in domains.iter().enumerate() {
        let entry = states
            .entries
            .entry(*domain)
            .or_insert_with(|| CircuitEntry {
                consecutive_failures: 0,
                consecutive_successes: 0,
                open_until: None,
                half_open_in_flight: 0,
                recovery_started_at: None,
                recovery_until: None,
                reopen_count: 0,
                health_epoch: initial_epoch,
                last_touched: now,
            });
        finish_recovery_if_elapsed(entry, now);
        entry.last_touched = now;
        if let Some(until) = entry.open_until {
            if until > now || entry.half_open_in_flight >= policy.half_open_max_requests {
                release_circuit_tokens(&mut states, domains, &tokens, now);
                return Err(TargetProtectionError::CircuitOpen);
            }
            entry.half_open_in_flight = entry.half_open_in_flight.saturating_add(1);
            tokens[index] = Some(until);
        }
    }
    Ok(tokens)
}

fn release_unobserved_circuits(
    states: &Arc<Mutex<CircuitStates>>,
    domains: &[CircuitDomain; 3],
    tokens: &[Option<Instant>; 3],
) {
    let now = Instant::now();
    let mut states = states.lock().expect("circuit state mutex poisoned");
    release_circuit_tokens(&mut states, domains, tokens, now);
}

fn release_circuit_tokens(
    states: &mut CircuitStates,
    domains: &[CircuitDomain; 3],
    tokens: &[Option<Instant>; 3],
    now: Instant,
) {
    for (domain, token) in domains.iter().zip(tokens) {
        if let Some(entry) = states.entries.get_mut(domain) {
            entry.last_touched = now;
            if token.is_some() && entry.open_until == *token {
                entry.half_open_in_flight = entry.half_open_in_flight.saturating_sub(1);
            }
        }
    }
}

fn observe_circuits(
    states: &Arc<Mutex<CircuitStates>>,
    domains: &[CircuitDomain; 3],
    tokens: &[Option<Instant>; 3],
    policy: &CircuitPolicySnapshot,
    success: bool,
) {
    let now = Instant::now();
    let failure_epoch = (!success).then(Uuid::now_v7);
    let mut states = states.lock().expect("circuit state mutex poisoned");
    for (domain, token) in domains.iter().zip(tokens) {
        let Some(entry) = states.entries.get_mut(domain) else {
            continue;
        };
        finish_recovery_if_elapsed(entry, now);
        entry.last_touched = now;
        let half_open = token.is_some();
        if half_open {
            if entry.open_until != *token {
                continue;
            }
            entry.half_open_in_flight = entry.half_open_in_flight.saturating_sub(1);
        } else if entry.open_until.is_some() {
            continue;
        }
        if success {
            entry.consecutive_failures = 0;
            entry.consecutive_successes = entry.consecutive_successes.saturating_add(1);
            if half_open && entry.consecutive_successes >= policy.success_threshold {
                entry.open_until = None;
                entry.half_open_in_flight = 0;
                entry.consecutive_successes = 0;
                entry.recovery_started_at = Some(now);
                entry.recovery_until =
                    Some(now + Duration::from_millis(policy.recovery_duration_ms));
            } else if !half_open {
                entry.consecutive_successes = 0;
            }
        } else {
            let recovering = entry.recovery_until.is_some_and(|until| until > now);
            entry.consecutive_successes = 0;
            entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
            if half_open || recovering || entry.consecutive_failures >= policy.failure_threshold {
                entry.open_until = Some(now + circuit_cooldown(policy, entry.reopen_count));
                entry.half_open_in_flight = 0;
                entry.recovery_started_at = None;
                entry.recovery_until = None;
                entry.reopen_count = entry.reopen_count.saturating_add(1);
                entry.health_epoch = failure_epoch.expect("failure epoch is present");
                entry.consecutive_failures = 0;
            }
        }
    }
}

fn circuit_cooldown(policy: &CircuitPolicySnapshot, reopen_count: u32) -> Duration {
    let multiplier = 1_u128 << reopen_count.min(63);
    let millis = u128::from(policy.open_duration_ms)
        .saturating_mul(multiplier)
        .min(u128::from(policy.max_open_duration_ms));
    Duration::from_millis(u64::try_from(millis).expect("cooldown is policy bounded"))
}

fn finish_recovery_if_elapsed(entry: &mut CircuitEntry, now: Instant) {
    if entry.recovery_until.is_some_and(|until| until <= now) {
        entry.recovery_started_at = None;
        entry.recovery_until = None;
        entry.reopen_count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn circuit_policy() -> CircuitPolicySnapshot {
        CircuitPolicySnapshot {
            failure_threshold: 2,
            success_threshold: 1,
            open_duration_ms: 25,
            max_open_duration_ms: 100,
            half_open_max_requests: 1,
            recovery_duration_ms: 25,
        }
    }

    fn test_domains() -> [CircuitDomain; 3] {
        [
            CircuitDomain::Endpoint {
                id: Uuid::now_v7(),
                client_binding: [1; 32],
            },
            CircuitDomain::Credential {
                id: Uuid::now_v7(),
                state_identity_version: 1,
                secret_version: 1,
                client_binding: [1; 32],
            },
            CircuitDomain::Deployment {
                id: Uuid::now_v7(),
                config_version: 1,
                client_binding: [1; 32],
            },
        ]
    }

    #[test]
    fn capacity_domain_enforces_and_releases_local_limit() {
        let domain = CapacityDomain::new(1);
        let id = Uuid::now_v7();
        let permit = domain.try_acquire(id).unwrap();
        assert_eq!(
            domain.try_acquire(id).unwrap_err(),
            TargetProtectionError::CapacityExhausted
        );
        drop(permit);
        assert!(domain.try_acquire(id).is_ok());
    }

    #[test]
    fn retired_client_failure_domains_cannot_open_the_current_binding() {
        let states = Arc::new(Mutex::new(CircuitStates::default()));
        let old_domains = test_domains();
        let current_domains = old_domains.map(|domain| match domain {
            CircuitDomain::Endpoint { id, .. } => CircuitDomain::Endpoint {
                id,
                client_binding: [2; 32],
            },
            CircuitDomain::Credential {
                id,
                state_identity_version,
                secret_version,
                ..
            } => CircuitDomain::Credential {
                id,
                state_identity_version: state_identity_version + 1,
                secret_version: secret_version + 1,
                client_binding: [2; 32],
            },
            CircuitDomain::Deployment {
                id, config_version, ..
            } => CircuitDomain::Deployment {
                id,
                config_version: config_version + 1,
                client_binding: [2; 32],
            },
        });
        let policy = CircuitPolicySnapshot {
            failure_threshold: 1,
            ..circuit_policy()
        };
        let old_tokens = acquire_circuits(&states, &old_domains, &policy).unwrap();
        observe_circuits(&states, &old_domains, &old_tokens, &policy, false);
        assert_eq!(
            acquire_circuits(&states, &old_domains, &policy).unwrap_err(),
            TargetProtectionError::CircuitOpen
        );
        let current_tokens = acquire_circuits(&states, &current_domains, &policy).unwrap();
        release_unobserved_circuits(&states, &current_domains, &current_tokens);
    }

    #[tokio::test]
    async fn circuit_opens_then_allows_one_half_open_success() {
        let states = Arc::new(Mutex::new(CircuitStates::default()));
        let domains = test_domains();
        let policy = circuit_policy();

        for _ in 0..2 {
            let tokens = acquire_circuits(&states, &domains, &policy).unwrap();
            observe_circuits(&states, &domains, &tokens, &policy, false);
        }
        assert_eq!(
            acquire_circuits(&states, &domains, &policy).unwrap_err(),
            TargetProtectionError::CircuitOpen
        );

        tokio::time::sleep(Duration::from_millis(30)).await;
        let tokens = acquire_circuits(&states, &domains, &policy).unwrap();
        assert_eq!(
            acquire_circuits(&states, &domains, &policy).unwrap_err(),
            TargetProtectionError::CircuitOpen
        );
        observe_circuits(&states, &domains, &tokens, &policy, true);
        let tokens = acquire_circuits(&states, &domains, &policy).unwrap();
        release_unobserved_circuits(&states, &domains, &tokens);
    }

    #[test]
    fn repeated_failures_use_bounded_exponential_cooldown() {
        let policy = circuit_policy();
        assert_eq!(circuit_cooldown(&policy, 0), Duration::from_millis(25));
        assert_eq!(circuit_cooldown(&policy, 1), Duration::from_millis(50));
        assert_eq!(circuit_cooldown(&policy, 2), Duration::from_millis(100));
        assert_eq!(circuit_cooldown(&policy, 63), Duration::from_millis(100));
    }

    #[tokio::test]
    async fn recovering_failure_reopens_immediately_with_longer_cooldown() {
        let states = Arc::new(Mutex::new(CircuitStates::default()));
        let domains = test_domains();
        let policy = CircuitPolicySnapshot {
            failure_threshold: 1,
            recovery_duration_ms: 100,
            ..circuit_policy()
        };
        let tokens = acquire_circuits(&states, &domains, &policy).unwrap();
        observe_circuits(&states, &domains, &tokens, &policy, false);
        tokio::time::sleep(Duration::from_millis(30)).await;
        let tokens = acquire_circuits(&states, &domains, &policy).unwrap();
        observe_circuits(&states, &domains, &tokens, &policy, true);
        let tokens = acquire_circuits(&states, &domains, &policy).unwrap();
        observe_circuits(&states, &domains, &tokens, &policy, false);

        let now = Instant::now();
        let states = states.lock().unwrap();
        for domain in domains {
            let entry = &states.entries[&domain];
            assert!(entry.recovery_started_at.is_none());
            assert_eq!(entry.reopen_count, 2);
            let remaining = entry.open_until.unwrap().duration_since(now);
            assert!(!remaining.is_zero());
            assert!(remaining <= circuit_cooldown(&policy, 1));
        }
    }

    #[tokio::test]
    async fn successful_half_open_evidence_starts_and_completes_recovery() {
        let states = Arc::new(Mutex::new(CircuitStates::default()));
        let domains = test_domains();
        let policy = CircuitPolicySnapshot {
            failure_threshold: 1,
            recovery_duration_ms: 25,
            ..circuit_policy()
        };
        let tokens = acquire_circuits(&states, &domains, &policy).unwrap();
        observe_circuits(&states, &domains, &tokens, &policy, false);
        tokio::time::sleep(Duration::from_millis(30)).await;
        let tokens = acquire_circuits(&states, &domains, &policy).unwrap();
        observe_circuits(&states, &domains, &tokens, &policy, true);
        {
            let states = states.lock().unwrap();
            for domain in domains {
                let entry = &states.entries[&domain];
                assert!(entry.open_until.is_none());
                assert!(entry.recovery_started_at.is_some());
                assert!(entry.recovery_until.is_some());
                assert_ne!(entry.health_epoch, Uuid::nil());
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
        let tokens = acquire_circuits(&states, &domains, &policy).unwrap();
        release_unobserved_circuits(&states, &domains, &tokens);
        let states = states.lock().unwrap();
        assert!(domains.iter().all(|domain| {
            let entry = &states.entries[domain];
            entry.recovery_started_at.is_none()
                && entry.recovery_until.is_none()
                && entry.reopen_count == 0
        }));
    }

    #[tokio::test]
    async fn late_half_open_success_cannot_close_a_reopened_circuit() {
        let states = Arc::new(Mutex::new(CircuitStates::default()));
        let domains = test_domains();
        let policy = CircuitPolicySnapshot {
            failure_threshold: 1,
            success_threshold: 2,
            open_duration_ms: 25,
            max_open_duration_ms: 100,
            half_open_max_requests: 2,
            recovery_duration_ms: 25,
        };

        let tokens = acquire_circuits(&states, &domains, &policy).unwrap();
        observe_circuits(&states, &domains, &tokens, &policy, false);
        tokio::time::sleep(Duration::from_millis(30)).await;

        let first = acquire_circuits(&states, &domains, &policy).unwrap();
        let late = acquire_circuits(&states, &domains, &policy).unwrap();
        observe_circuits(&states, &domains, &first, &policy, false);
        observe_circuits(&states, &domains, &late, &policy, true);

        assert_eq!(
            acquire_circuits(&states, &domains, &policy).unwrap_err(),
            TargetProtectionError::CircuitOpen
        );
    }
}
