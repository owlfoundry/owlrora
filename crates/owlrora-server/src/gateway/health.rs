use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use http::{Method, header};
use reqwest::StatusCode;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tokio::{
    sync::{Mutex as AsyncMutex, watch},
    task::{JoinHandle, JoinSet},
    time::{Instant, timeout, timeout_at},
};
use uuid::Uuid;

use crate::{
    adapters::coordinator::{RedisCoordinator, TargetHealthCategory, TargetHealthSummary},
    domain::{RouteId, TargetId, TransportKind},
    runtime::{
        CredentialClient, CredentialInjection, ProbePolicySnapshot, ReliabilityPolicySnapshot,
        RouteSnapshot, RuntimeGeneration, RuntimePublisher,
    },
};

use super::{
    Candidate, TargetProtectionState,
    protection::{LocalTargetHealth, TargetProtectionError},
};

const PLAN_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const MAX_CONCURRENT_PROBES: usize = 16;

#[derive(Clone, Debug, Serialize)]
pub(crate) struct TargetProbeObservation {
    pub summary: TargetHealthSummary,
    pub route_id: Uuid,
    pub latency_millis: u64,
    pub http_status: Option<u16>,
    pub outcome: &'static str,
    #[serde(skip)]
    fresh_until: Instant,
    #[serde(skip)]
    recovery_started_at: Option<Instant>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct TargetProbeRun {
    pub requested: usize,
    pub eligible: usize,
    pub completed: usize,
}

#[derive(Debug)]
pub(crate) struct TargetProbeWorker {
    runtime: Arc<RuntimePublisher>,
    coordinator: Arc<RedisCoordinator>,
    protection: Arc<TargetProtectionState>,
    node_instance_id: String,
    plan: Mutex<ProbePlan>,
    observations: Mutex<HashMap<TargetId, TargetProbeObservation>>,
    shutdown: watch::Sender<bool>,
    task: AsyncMutex<Option<JoinHandle<()>>>,
}

#[derive(Debug)]
struct ProbePlan {
    runtime_revision: i64,
    specs: HashMap<TargetId, ProbeSpec>,
}

#[derive(Clone, Copy, Debug)]
struct ScheduledProbe {
    binding_fingerprint: [u8; 32],
    next_due: Instant,
}

#[derive(Clone, Debug)]
struct ProbeSpec {
    runtime_revision: i64,
    route_id: RouteId,
    binding_fingerprint: [u8; 32],
    candidate: Candidate,
    reliability: ReliabilityPolicySnapshot,
    client: Arc<CredentialClient>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeRequestOutcome {
    Success(StatusCode),
    HttpFailure(StatusCode),
    NoEvidence,
    AuthenticationFailure,
    TransportFailure,
    Timeout,
    InvalidConfiguration,
}

impl TargetProbeWorker {
    pub(crate) fn new(
        runtime: Arc<RuntimePublisher>,
        coordinator: Arc<RedisCoordinator>,
        protection: Arc<TargetProtectionState>,
        node_instance_id: String,
    ) -> Arc<Self> {
        let (shutdown, _) = watch::channel(false);
        Arc::new(Self {
            runtime,
            coordinator,
            protection,
            node_instance_id,
            plan: Mutex::new(ProbePlan {
                runtime_revision: i64::MIN,
                specs: HashMap::new(),
            }),
            observations: Mutex::new(HashMap::new()),
            shutdown,
            task: AsyncMutex::new(None),
        })
    }

    pub(crate) async fn start(self: &Arc<Self>) {
        let mut task = self.task.lock().await;
        if task.is_some() {
            return;
        }
        let worker = Arc::clone(self);
        let receiver = self.shutdown.subscribe();
        *task = Some(tokio::spawn(async move {
            worker.run(receiver).await;
        }));
    }

    pub(crate) async fn shutdown(&self) {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.lock().await.take() {
            let _ = task.await;
        }
    }

    pub(crate) fn observations(&self) -> Vec<TargetProbeObservation> {
        let Ok(observations) = self.observations.lock() else {
            return Vec::new();
        };
        let mut observations = observations.values().cloned().collect::<Vec<_>>();
        observations.sort_by_key(|observation| observation.summary.target_id);
        observations
    }

    pub(crate) async fn probe_now(self: &Arc<Self>, target_ids: &[TargetId]) -> TargetProbeRun {
        self.refresh_probe_plan();
        let mut unique = HashSet::new();
        let specs = target_ids
            .iter()
            .copied()
            .filter(|target_id| unique.insert(*target_id))
            .filter_map(|target_id| self.probe_spec(target_id))
            .collect::<Vec<_>>();
        let run = TargetProbeRun {
            requested: unique.len(),
            eligible: specs.len(),
            completed: 0,
        };
        let mut probes = JoinSet::new();
        let mut next = specs.into_iter();
        let mut completed = 0_usize;
        loop {
            while probes.len() < MAX_CONCURRENT_PROBES {
                let Some(spec) = next.next() else {
                    break;
                };
                let worker = Arc::clone(self);
                probes.spawn(async move {
                    worker.execute_probe(spec).await;
                });
            }
            let Some(result) = probes.join_next().await else {
                break;
            };
            if result.is_ok() {
                completed = completed.saturating_add(1);
            }
        }
        TargetProbeRun { completed, ..run }
    }

    pub(crate) fn allows_candidate(
        &self,
        generation: &RuntimeGeneration,
        route: &RouteSnapshot,
        candidate: &Candidate,
        reliability: &ReliabilityPolicySnapshot,
        affinity_hash: [u8; 32],
    ) -> bool {
        let Some(client) = generation
            .credential_clients
            .clients
            .get(&candidate.deployment.client_key())
        else {
            return false;
        };
        let binding = probe_binding_fingerprint(route, reliability, candidate, client);
        let recovery_duration =
            Duration::from_millis(reliability.circuit_policy.recovery_duration_ms);
        let local = self.protection.local_health(candidate);
        if let Some(allows) = local_health_decision(
            local,
            candidate.target.id.as_uuid(),
            affinity_hash,
            recovery_duration,
        ) {
            return allows;
        }
        let Ok(observations) = self.observations.lock() else {
            return true;
        };
        let Some(observation) = observations.get(&candidate.target.id) else {
            return true;
        };
        observation_allows_candidate(
            observation,
            binding,
            affinity_hash,
            Duration::from_millis(reliability.circuit_policy.recovery_duration_ms),
            Instant::now(),
        )
    }

    fn store_observation(&self, target_id: TargetId, observation: TargetProbeObservation) {
        if let Ok(mut observations) = self.observations.lock() {
            match observations.entry(target_id) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(observation);
                }
                std::collections::hash_map::Entry::Occupied(mut entry)
                    if observation_replaces(entry.get(), &observation, Instant::now()) =>
                {
                    entry.insert(observation);
                }
                std::collections::hash_map::Entry::Occupied(_) => {}
            }
        }
    }

    async fn run(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let mut scheduled_revision = i64::MIN;
        let mut schedule = HashMap::<TargetId, ScheduledProbe>::new();
        let mut due = BinaryHeap::<Reverse<(Instant, TargetId)>>::new();
        let mut in_flight = HashSet::<TargetId>::new();
        let mut probes = JoinSet::<TargetId>::new();
        loop {
            let runtime_revision = self.refresh_probe_plan();
            let now = Instant::now();
            if scheduled_revision != runtime_revision {
                scheduled_revision = runtime_revision;
                if let Ok(plan) = self.plan.lock() {
                    reconcile_probe_schedule(
                        &mut schedule,
                        plan.specs
                            .iter()
                            .map(|(target_id, spec)| (*target_id, spec.binding_fingerprint)),
                        now,
                    );
                }
                due.clear();
                due.extend(
                    schedule
                        .iter()
                        .map(|(target_id, scheduled)| Reverse((scheduled.next_due, *target_id))),
                );
            }

            while probes.len() < MAX_CONCURRENT_PROBES {
                let Some(Reverse((next, target_id))) = due.peek().copied() else {
                    break;
                };
                if next > now {
                    break;
                }
                due.pop();
                if in_flight.contains(&target_id) {
                    let next_due = now + PLAN_REFRESH_INTERVAL;
                    if let Some(scheduled) = schedule.get_mut(&target_id) {
                        scheduled.next_due = next_due;
                    }
                    due.push(Reverse((next_due, target_id)));
                    continue;
                }
                let Some(spec) = self.probe_spec(target_id) else {
                    schedule.remove(&target_id);
                    continue;
                };
                let next_due =
                    now + Duration::from_millis(spec.reliability.probe_policy.interval_ms);
                schedule.insert(
                    target_id,
                    ScheduledProbe {
                        binding_fingerprint: spec.binding_fingerprint,
                        next_due,
                    },
                );
                due.push(Reverse((next_due, target_id)));
                in_flight.insert(target_id);
                let worker = Arc::clone(&self);
                probes.spawn(async move {
                    worker.execute_probe(spec).await;
                    target_id
                });
            }

            let refresh_at = Instant::now() + PLAN_REFRESH_INTERVAL;
            let wake_at = if probes.len() >= MAX_CONCURRENT_PROBES {
                refresh_at
            } else {
                due.peek()
                    .map_or(refresh_at, |Reverse((next, _))| (*next).min(refresh_at))
            };
            tokio::select! {
                _ = tokio::time::sleep_until(wake_at) => {}
                Some(result) = probes.join_next(), if !probes.is_empty() => {
                    if let Ok(target_id) = result {
                        in_flight.remove(&target_id);
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
        probes.abort_all();
        while probes.join_next().await.is_some() {}
    }

    fn refresh_probe_plan(&self) -> i64 {
        let generation = self.runtime.capture();
        let revision = generation.snapshot.revision;
        let active = {
            let Ok(mut plan) = self.plan.lock() else {
                return revision;
            };
            if plan.runtime_revision == revision {
                return revision;
            }
            plan.runtime_revision = revision;
            plan.specs = collect_probe_specs(&generation);
            plan.specs.keys().copied().collect::<HashSet<_>>()
        };
        if let Ok(mut observations) = self.observations.lock() {
            observations.retain(|target_id, _| active.contains(target_id));
        }
        revision
    }

    fn probe_spec(&self, target_id: TargetId) -> Option<ProbeSpec> {
        self.plan.lock().ok()?.specs.get(&target_id).cloned()
    }

    fn probe_binding_is_current(&self, expected: &ProbeSpec) -> bool {
        self.refresh_probe_plan();
        self.plan.lock().is_ok_and(|plan| {
            plan.specs
                .get(&expected.candidate.target.id)
                .is_some_and(|candidate| {
                    candidate.binding_fingerprint == expected.binding_fingerprint
                })
        })
    }

    async fn execute_probe(&self, spec: ProbeSpec) {
        let policy = &spec.reliability.probe_policy;
        let lease_token = Uuid::now_v7().to_string();
        let lease = timeout(
            Duration::from_millis(policy.timeout_ms.min(250)),
            self.coordinator.try_acquire_target_probe_lease(
                spec.candidate.target.id.as_uuid(),
                &spec.binding_fingerprint,
                &lease_token,
                Duration::from_millis(policy.interval_ms),
            ),
        )
        .await;
        match lease {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) => {
                self.sync_shared_observation(&spec).await;
                return;
            }
            Ok(Err(_)) | Err(_) => return,
        }
        let deadline = Instant::now() + Duration::from_millis(policy.timeout_ms);
        let Ok(_global_permit) = self.protection.try_acquire_global() else {
            return;
        };
        let permit = match self
            .protection
            .try_acquire_target(&spec.candidate, &spec.reliability.circuit_policy)
        {
            Ok(permit) => permit,
            Err(TargetProtectionError::CircuitOpen) => {
                self.record_observation(&spec, 0, None, "circuit_open", &lease_token)
                    .await;
                return;
            }
            Err(TargetProtectionError::CapacityExhausted) => return,
        };

        let started = Instant::now();
        let outcome = timeout_at(
            deadline,
            execute_probe_request(&spec.client, policy, spec.candidate.target.id),
        )
        .await
        .unwrap_or(ProbeRequestOutcome::Timeout);
        if !self.probe_binding_is_current(&spec) {
            return;
        }
        let latency = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let (status, outcome_class, success) = match outcome {
            ProbeRequestOutcome::Success(status) => (Some(status.as_u16()), "success", true),
            ProbeRequestOutcome::HttpFailure(status) => {
                (Some(status.as_u16()), "http_failure", false)
            }
            ProbeRequestOutcome::NoEvidence | ProbeRequestOutcome::InvalidConfiguration => return,
            ProbeRequestOutcome::AuthenticationFailure => (None, "authentication_failure", false),
            ProbeRequestOutcome::TransportFailure => (None, "transport_failure", false),
            ProbeRequestOutcome::Timeout => (None, "timeout", false),
        };
        if success {
            permit.success();
        } else {
            permit.failure();
        }
        self.record_observation(&spec, latency, status, outcome_class, &lease_token)
            .await;
    }

    async fn sync_shared_observation(&self, spec: &ProbeSpec) {
        let Ok((summary, remaining_ttl)) = self
            .coordinator
            .get_target_health_summary(
                spec.candidate.target.id.as_uuid(),
                &spec.binding_fingerprint,
            )
            .await
        else {
            return;
        };
        if summary.binding_fingerprint != spec.binding_fingerprint
            || summary.deployment_id != spec.candidate.deployment.id.as_uuid()
            || summary.endpoint_id != spec.candidate.deployment.endpoint_id.as_uuid()
            || summary.credential_id != spec.candidate.deployment.credential_id.as_uuid()
        {
            return;
        }
        let now = Instant::now();
        let recovery_started_at = summary.recovery_started_at_unix_ms.map(|started| {
            now.checked_sub(Duration::from_millis(
                summary.observed_at_unix_ms.saturating_sub(started),
            ))
            .unwrap_or(now)
        });
        let observation = TargetProbeObservation {
            summary,
            route_id: spec.route_id.as_uuid(),
            latency_millis: 0,
            http_status: None,
            outcome: "shared",
            fresh_until: now
                + remaining_ttl.min(Duration::from_millis(
                    spec.reliability.health_policy.stale_after_ms,
                )),
            recovery_started_at,
        };
        self.store_observation(spec.candidate.target.id, observation);
    }

    async fn record_observation(
        &self,
        spec: &ProbeSpec,
        latency_millis: u64,
        http_status: Option<u16>,
        outcome: &'static str,
        lease_token: &str,
    ) {
        let local = self.protection.local_health(&spec.candidate);
        let now = unix_millis();
        let cooldown_until_unix_ms = local.cooldown_remaining.map(|remaining| {
            now.saturating_add(u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX))
        });
        let recovery_started_at_unix_ms = local.recovery_elapsed.map(|elapsed| {
            now.saturating_sub(u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        });
        let monotonic_now = Instant::now();
        let recovery_started_at = local
            .recovery_elapsed
            .and_then(|elapsed| monotonic_now.checked_sub(elapsed));
        let summary = TargetHealthSummary {
            target_id: spec.candidate.target.id.as_uuid(),
            deployment_id: spec.candidate.deployment.id.as_uuid(),
            endpoint_id: spec.candidate.deployment.endpoint_id.as_uuid(),
            credential_id: spec.candidate.deployment.credential_id.as_uuid(),
            runtime_revision: spec.runtime_revision,
            binding_fingerprint: spec.binding_fingerprint,
            health_epoch: local.health_epoch,
            category: local.category,
            cooldown_until_unix_ms,
            recovery_started_at_unix_ms,
            observed_at_unix_ms: now,
            source_node_id: self.node_instance_id.clone(),
        };
        let observation = TargetProbeObservation {
            summary: summary.clone(),
            route_id: spec.route_id.as_uuid(),
            latency_millis,
            http_status,
            outcome,
            fresh_until: monotonic_now
                + Duration::from_millis(spec.reliability.health_policy.stale_after_ms),
            recovery_started_at,
        };
        self.store_observation(spec.candidate.target.id, observation);
        if let Err(error) = self
            .coordinator
            .put_target_health_summary(
                &summary,
                lease_token,
                Duration::from_millis(spec.reliability.health_policy.shared_summary_ttl_ms),
            )
            .await
        {
            tracing::warn!(
                target_id = %summary.target_id,
                %error,
                "target health summary publication failed"
            );
        }
    }
}

fn reconcile_probe_schedule(
    schedule: &mut HashMap<TargetId, ScheduledProbe>,
    bindings: impl IntoIterator<Item = (TargetId, [u8; 32])>,
    now: Instant,
) {
    let bindings = bindings.into_iter().collect::<HashMap<_, _>>();
    schedule.retain(|target_id, _| bindings.contains_key(target_id));
    for (target_id, binding_fingerprint) in bindings {
        schedule
            .entry(target_id)
            .and_modify(|scheduled| {
                if scheduled.binding_fingerprint != binding_fingerprint {
                    *scheduled = ScheduledProbe {
                        binding_fingerprint,
                        next_due: now,
                    };
                }
            })
            .or_insert(ScheduledProbe {
                binding_fingerprint,
                next_due: now,
            });
    }
}

fn collect_probe_specs(generation: &RuntimeGeneration) -> HashMap<TargetId, ProbeSpec> {
    let mut specs = HashMap::new();
    for route in generation.snapshot.catalog.routes.values() {
        if !route.active {
            continue;
        }
        let Some(reliability) = generation
            .snapshot
            .catalog
            .reliability_policies
            .get(&route.reliability_policy_id)
            .filter(|policy| policy.active && policy.probe_policy.enabled)
        else {
            continue;
        };
        for target in &route.targets {
            let Some(deployment) = generation
                .snapshot
                .catalog
                .deployments
                .get(&target.deployment_id)
                .filter(|deployment| deployment.operational)
                .cloned()
            else {
                continue;
            };
            let Some(client) = generation
                .credential_clients
                .clients
                .get(&deployment.client_key())
                .cloned()
            else {
                continue;
            };
            let candidate = Candidate {
                target: target.clone(),
                deployment,
                client_build_fingerprint: *client.build_fingerprint(),
            };
            specs.insert(
                target.id,
                ProbeSpec {
                    runtime_revision: generation.snapshot.revision,
                    route_id: route.id,
                    binding_fingerprint: probe_binding_fingerprint(
                        route,
                        reliability,
                        &candidate,
                        &client,
                    ),
                    candidate,
                    reliability: reliability.clone(),
                    client,
                },
            );
        }
    }
    specs
}

async fn execute_probe_request(
    client: &CredentialClient,
    policy: &ProbePolicySnapshot,
    test_target_id: TargetId,
) -> ProbeRequestOutcome {
    let Some(url) = probe_url(&client.base_url, &policy.path) else {
        return ProbeRequestOutcome::InvalidConfiguration;
    };
    let mut builder = client.http.request(Method::HEAD, url);
    builder = match &client.injection {
        CredentialInjection::Bearer(value) => {
            let Ok(value) = super::dispatch::prefixed_header("Bearer ", value) else {
                return ProbeRequestOutcome::InvalidConfiguration;
            };
            builder.header(header::AUTHORIZATION, value)
        }
        CredentialInjection::Codex {
            authorization,
            account_id,
        } => builder
            .header(header::AUTHORIZATION, authorization.clone())
            .header("chatgpt-account-id", account_id.clone()),
        CredentialInjection::XApiKey(value) => builder.header("x-api-key", value.clone()),
        CredentialInjection::ApiKeyHeader(value) => {
            let name = if client.key.transport_kind == TransportKind::GoogleGeminiGenerateContent {
                "x-goog-api-key"
            } else {
                "api-key"
            };
            builder.header(name, value.clone())
        }
        CredentialInjection::Dynamic(_) => builder,
    };
    builder = add_test_probe_target_header(builder, test_target_id);
    let mut request = match builder.build() {
        Ok(request) => request,
        Err(_) => return ProbeRequestOutcome::InvalidConfiguration,
    };
    if let CredentialInjection::Dynamic(authenticator) = &client.injection
        && authenticator.apply(&mut request, &[]).await.is_err()
    {
        return ProbeRequestOutcome::AuthenticationFailure;
    }
    match client.http.execute(request).await {
        Ok(response) if response.status().is_success() => {
            ProbeRequestOutcome::Success(response.status())
        }
        Ok(response)
            if matches!(response.status().as_u16(), 401 | 403 | 429)
                || response.status().is_server_error() =>
        {
            ProbeRequestOutcome::HttpFailure(response.status())
        }
        Ok(_) => ProbeRequestOutcome::NoEvidence,
        Err(_) => ProbeRequestOutcome::TransportFailure,
    }
}

#[cfg(test)]
fn add_test_probe_target_header(
    builder: reqwest::RequestBuilder,
    target_id: TargetId,
) -> reqwest::RequestBuilder {
    builder.header("x-owlrora-test-probe-target", target_id.to_string())
}

#[cfg(not(test))]
fn add_test_probe_target_header(
    builder: reqwest::RequestBuilder,
    _target_id: TargetId,
) -> reqwest::RequestBuilder {
    builder
}

fn observation_replaces(
    existing: &TargetProbeObservation,
    candidate: &TargetProbeObservation,
    now: Instant,
) -> bool {
    existing.summary.binding_fingerprint != candidate.summary.binding_fingerprint
        || now >= existing.fresh_until
        || candidate.outcome != "shared"
        || existing.outcome == "shared"
}

fn local_health_decision(
    local: LocalTargetHealth,
    target_id: Uuid,
    affinity_hash: [u8; 32],
    recovery_duration: Duration,
) -> Option<bool> {
    match local.category {
        TargetHealthCategory::Open => Some(false),
        TargetHealthCategory::Recovering => local.recovery_elapsed.map(|elapsed| {
            deterministic_recovery_sample(
                target_id,
                local.health_epoch,
                affinity_hash,
                elapsed,
                recovery_duration,
            )
        }),
        TargetHealthCategory::Healthy
        | TargetHealthCategory::Degraded
        | TargetHealthCategory::Unavailable => None,
    }
}

fn observation_allows_candidate(
    observation: &TargetProbeObservation,
    binding_fingerprint: [u8; 32],
    affinity_hash: [u8; 32],
    recovery_duration: Duration,
    now: Instant,
) -> bool {
    if observation.summary.binding_fingerprint != binding_fingerprint
        || now >= observation.fresh_until
    {
        return true;
    }
    match observation.summary.category {
        TargetHealthCategory::Open | TargetHealthCategory::Unavailable => false,
        TargetHealthCategory::Recovering => {
            observation.recovery_started_at.is_some_and(|started| {
                deterministic_recovery_sample(
                    observation.summary.target_id,
                    observation.summary.health_epoch,
                    affinity_hash,
                    now.duration_since(started),
                    recovery_duration,
                )
            })
        }
        TargetHealthCategory::Healthy | TargetHealthCategory::Degraded => true,
    }
}

fn deterministic_recovery_sample(
    target_id: Uuid,
    health_epoch: Uuid,
    affinity_hash: [u8; 32],
    elapsed: Duration,
    recovery_duration: Duration,
) -> bool {
    if elapsed >= recovery_duration {
        return true;
    }
    if elapsed.is_zero() || recovery_duration.is_zero() {
        return false;
    }
    let mut digest = Sha256::new();
    digest.update(b"owlrora/recovery-ramp-v1\0");
    digest.update(target_id.as_bytes());
    digest.update(health_epoch.as_bytes());
    digest.update(affinity_hash);
    let digest: [u8; 32] = digest.finalize().into();
    let sample = u64::from_be_bytes(digest[..8].try_into().expect("fixed digest prefix"));
    let threshold = elapsed.as_nanos().saturating_mul(1_u128 << 64) / recovery_duration.as_nanos();
    u128::from(sample) < threshold
}

fn probe_binding_fingerprint(
    route: &RouteSnapshot,
    reliability: &ReliabilityPolicySnapshot,
    candidate: &Candidate,
    client: &CredentialClient,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"owlrora/target-probe-binding/v1\0");
    for id in [
        route.id.as_uuid(),
        candidate.target.id.as_uuid(),
        candidate.deployment.id.as_uuid(),
        candidate.deployment.endpoint_id.as_uuid(),
        candidate.deployment.credential_id.as_uuid(),
    ] {
        digest.update(id.as_bytes());
    }
    for version in [
        route.config_version,
        reliability.config_version,
        candidate.deployment.config_version,
        u64::try_from(candidate.deployment.endpoint_config_version).unwrap_or_default(),
        candidate.deployment.credential_state_identity_version,
        u64::try_from(candidate.deployment.credential_secret_version).unwrap_or_default(),
    ] {
        digest.update(version.to_be_bytes());
    }
    digest.update(client.build_fingerprint());
    digest.update(reliability.probe_policy.path.as_bytes());
    digest.finalize().into()
}

fn probe_url(base_url: &url::Url, path: &str) -> Option<url::Url> {
    if path.is_empty()
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains('?')
        || path.contains('#')
        || path.chars().any(char::is_control)
    {
        return None;
    }
    let candidate = base_url.join(path).ok()?;
    (candidate.scheme() == base_url.scheme()
        && candidate.host() == base_url.host()
        && candidate.port_or_known_default() == base_url.port_or_known_default()
        && candidate.username().is_empty()
        && candidate.password().is_none()
        && candidate.query().is_none()
        && candidate.fragment().is_none())
    .then_some(candidate)
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use crate::{
        domain::{CredentialId, EndpointAdapterKind, EndpointId},
        runtime::CredentialClientKey,
    };

    #[test]
    fn probe_url_is_origin_locked_and_query_free() {
        let base = url::Url::parse("https://provider.example/base/").unwrap();
        assert_eq!(
            probe_url(&base, "/health").unwrap().as_str(),
            "https://provider.example/health"
        );
        assert!(probe_url(&base, "//attacker.example/health").is_none());
        assert!(probe_url(&base, "/health?billable=true").is_none());
        assert!(probe_url(&base, "/health#fragment").is_none());
    }

    #[test]
    fn probe_outcomes_keep_success_and_provider_failure_distinct() {
        assert!(matches!(
            ProbeRequestOutcome::Success(StatusCode::NO_CONTENT),
            ProbeRequestOutcome::Success(StatusCode::NO_CONTENT)
        ));
        assert_ne!(
            ProbeRequestOutcome::Success(StatusCode::OK),
            ProbeRequestOutcome::HttpFailure(StatusCode::UNAUTHORIZED)
        );
        let _ = crate::adapters::coordinator::TargetHealthCategory::Unavailable;
    }

    #[test]
    fn runtime_revision_reconciliation_preserves_unchanged_probe_deadlines() {
        let now = Instant::now();
        let unchanged = TargetId::new();
        let changed = TargetId::new();
        let removed = TargetId::new();
        let added = TargetId::new();
        let unchanged_due = now + Duration::from_secs(60);
        let changed_due = now + Duration::from_secs(120);
        let mut schedule = HashMap::from([
            (
                unchanged,
                ScheduledProbe {
                    binding_fingerprint: [1; 32],
                    next_due: unchanged_due,
                },
            ),
            (
                changed,
                ScheduledProbe {
                    binding_fingerprint: [2; 32],
                    next_due: changed_due,
                },
            ),
            (
                removed,
                ScheduledProbe {
                    binding_fingerprint: [3; 32],
                    next_due: now + Duration::from_secs(180),
                },
            ),
        ]);
        reconcile_probe_schedule(
            &mut schedule,
            [(unchanged, [1; 32]), (changed, [4; 32]), (added, [5; 32])],
            now,
        );
        assert_eq!(schedule[&unchanged].next_due, unchanged_due);
        assert_eq!(schedule[&changed].next_due, now);
        assert_eq!(schedule[&added].next_due, now);
        assert!(!schedule.contains_key(&removed));
    }

    #[test]
    fn local_passive_recovery_is_an_authoritative_ramp_gate() {
        let target_id = Uuid::now_v7();
        let epoch = Uuid::now_v7();
        let affinity = [9; 32];
        let duration = Duration::from_secs(1);
        assert_eq!(
            local_health_decision(
                LocalTargetHealth {
                    category: TargetHealthCategory::Open,
                    cooldown_remaining: Some(Duration::from_secs(1)),
                    recovery_elapsed: None,
                    health_epoch: epoch,
                },
                target_id,
                affinity,
                duration,
            ),
            Some(false)
        );
        assert_eq!(
            local_health_decision(
                LocalTargetHealth {
                    category: TargetHealthCategory::Recovering,
                    cooldown_remaining: None,
                    recovery_elapsed: None,
                    health_epoch: epoch,
                },
                target_id,
                affinity,
                duration,
            ),
            None,
            "half-open must reach the bounded circuit sampler"
        );
        assert_eq!(
            local_health_decision(
                LocalTargetHealth {
                    category: TargetHealthCategory::Recovering,
                    cooldown_remaining: None,
                    recovery_elapsed: Some(Duration::ZERO),
                    health_epoch: epoch,
                },
                target_id,
                affinity,
                duration,
            ),
            Some(false)
        );
        assert_eq!(
            local_health_decision(
                LocalTargetHealth {
                    category: TargetHealthCategory::Recovering,
                    cooldown_remaining: None,
                    recovery_elapsed: Some(duration),
                    health_epoch: epoch,
                },
                target_id,
                affinity,
                duration,
            ),
            Some(true)
        );
    }

    #[test]
    fn shared_unhealthy_observations_are_binding_and_ttl_bounded() {
        let binding = [11; 32];
        let now = Instant::now();
        let mut observation = TargetProbeObservation {
            summary: TargetHealthSummary {
                target_id: Uuid::now_v7(),
                deployment_id: Uuid::now_v7(),
                endpoint_id: Uuid::now_v7(),
                credential_id: Uuid::now_v7(),
                runtime_revision: 1,
                binding_fingerprint: binding,
                health_epoch: Uuid::now_v7(),
                category: TargetHealthCategory::Open,
                cooldown_until_unix_ms: None,
                recovery_started_at_unix_ms: None,
                observed_at_unix_ms: 10_000,
                source_node_id: "node-a".to_owned(),
            },
            route_id: Uuid::now_v7(),
            latency_millis: 0,
            http_status: None,
            outcome: "shared",
            fresh_until: now + Duration::from_secs(1),
            recovery_started_at: None,
        };
        assert!(!observation_allows_candidate(
            &observation,
            binding,
            [2; 32],
            Duration::from_secs(1),
            now + Duration::from_millis(999),
        ));
        assert!(observation_allows_candidate(
            &observation,
            binding,
            [2; 32],
            Duration::from_secs(1),
            now + Duration::from_secs(1),
        ));
        assert!(observation_allows_candidate(
            &observation,
            [12; 32],
            [2; 32],
            Duration::from_secs(1),
            now + Duration::from_millis(1),
        ));
        observation.summary.category = TargetHealthCategory::Degraded;
        assert!(observation_allows_candidate(
            &observation,
            binding,
            [2; 32],
            Duration::from_secs(1),
            now + Duration::from_millis(1),
        ));

        let mut local = observation.clone();
        local.outcome = "success";
        local.summary.category = TargetHealthCategory::Healthy;
        local.fresh_until = now + Duration::from_secs(5);
        let mut older_shared = observation.clone();
        older_shared.summary.category = TargetHealthCategory::Open;
        assert!(!observation_replaces(
            &local,
            &older_shared,
            now + Duration::from_millis(1),
        ));
        assert!(observation_replaces(
            &older_shared,
            &local,
            now + Duration::from_millis(1),
        ));
        assert!(observation_replaces(
            &local,
            &older_shared,
            now + Duration::from_secs(5),
        ));
    }

    #[test]
    fn recovering_traffic_sampling_is_epoch_affinity_deterministic_and_gradual() {
        let binding = [21; 32];
        let affinity = [22; 32];
        let started = Instant::now();
        let observation = TargetProbeObservation {
            summary: TargetHealthSummary {
                target_id: Uuid::now_v7(),
                deployment_id: Uuid::now_v7(),
                endpoint_id: Uuid::now_v7(),
                credential_id: Uuid::now_v7(),
                runtime_revision: 1,
                binding_fingerprint: binding,
                health_epoch: Uuid::now_v7(),
                category: TargetHealthCategory::Recovering,
                cooldown_until_unix_ms: None,
                recovery_started_at_unix_ms: Some(10_000),
                observed_at_unix_ms: 10_000,
                source_node_id: "node-a".to_owned(),
            },
            route_id: Uuid::now_v7(),
            latency_millis: 0,
            http_status: None,
            outcome: "success",
            fresh_until: started + Duration::from_secs(2),
            recovery_started_at: Some(started),
        };
        let duration = Duration::from_secs(1);
        assert!(!observation_allows_candidate(
            &observation,
            binding,
            affinity,
            duration,
            started,
        ));
        let halfway = observation_allows_candidate(
            &observation,
            binding,
            affinity,
            duration,
            started + Duration::from_millis(500),
        );
        assert_eq!(
            halfway,
            observation_allows_candidate(
                &observation,
                binding,
                affinity,
                duration,
                started + Duration::from_millis(500),
            )
        );
        assert!(observation_allows_candidate(
            &observation,
            binding,
            affinity,
            duration,
            started + duration,
        ));

        let mut half_open = observation;
        half_open.recovery_started_at = None;
        assert!(!observation_allows_candidate(
            &half_open,
            binding,
            affinity,
            duration,
            started + Duration::from_millis(999),
        ));
    }

    #[tokio::test]
    async fn probe_is_authenticated_head_without_a_billable_body() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            loop {
                let read = socket.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            socket
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            String::from_utf8(request).unwrap()
        });
        let client = CredentialClient {
            key: CredentialClientKey {
                credential_id: CredentialId::new(),
                secret_version: 1,
                endpoint_id: EndpointId::new(),
                endpoint_config_version: 1,
                transport_kind: TransportKind::OpenaiResponsesHttp,
            },
            base_url: url::Url::parse(&format!("http://{address}/v1")).unwrap(),
            adapter: EndpointAdapterKind::OpenaiApi,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            endpoint_connect_timeout_ms: 10_000,
            max_request_body_bytes: 1024,
            max_response_body_bytes: 1024,
            injection: CredentialInjection::Bearer(HeaderValue::from_static("probe-secret")),
            dynamic_secret: None,
            build_fingerprint: [7; 32],
        };
        let policy = ProbePolicySnapshot {
            enabled: true,
            interval_ms: 1000,
            timeout_ms: 500,
            path: "/health".to_owned(),
        };
        assert_eq!(
            execute_probe_request(&client, &policy, TargetId::new()).await,
            ProbeRequestOutcome::Success(StatusCode::NO_CONTENT)
        );
        let request = upstream.await.unwrap().to_ascii_lowercase();
        assert!(request.starts_with("head /health http/1.1\r\n"));
        assert!(request.contains("authorization: bearer probe-secret\r\n"));
        assert!(!request.contains("content-length:"));
    }
}
