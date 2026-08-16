use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::{
    sync::{Mutex as AsyncMutex, watch},
    task::JoinHandle,
};
use uuid::Uuid;

use crate::{
    adapters::coordinator::{
        AllowanceGrant, BudgetGrantSide, ConcurrencySlotGrant, CoordinatorError,
        PairedBudgetGrantRequest, PolicyReference, RateTokenGrant, RedisCoordinator,
    },
    domain::{BudgetMode, PolicyKind, UnknownEstimateMode},
    protocols::NativeRequest,
    runtime::{
        BudgetPolicyVersionSnapshot, GatewayKeyVerifier, PricingOutcome, RatePolicyVersionSnapshot,
        RuntimeGeneration,
    },
};

use super::Candidate;

const BUDGET_RETURN_INTERVAL: Duration = Duration::from_secs(15);
const BUDGET_RETURN_AHEAD_MILLIS: u64 = 30_000;

#[derive(Debug)]
pub(crate) struct GatewayAdmissionState {
    node_instance_id: String,
    local: Mutex<LocalAdmissionState>,
    budget_refills: AsyncMutex<HashMap<BudgetPairKey, Arc<AsyncMutex<()>>>>,
    shutdown: watch::Sender<bool>,
    task: AsyncMutex<Option<JoinHandle<()>>>,
}

impl Default for GatewayAdmissionState {
    fn default() -> Self {
        Self::new("unconfigured".to_owned())
    }
}

#[derive(Debug, Default)]
struct LocalAdmissionState {
    rate_grants: HashMap<PolicyReference, Vec<LocalRateGrant>>,
    concurrency_grants: HashMap<PolicyReference, Vec<LocalConcurrencyGrant>>,
    budget_grants: HashMap<BudgetPairKey, Vec<LocalBudgetGrant>>,
    budget_debts: HashMap<BudgetPairKey, BudgetDebt>,
}

#[derive(Debug)]
struct LocalRateGrant {
    id: Uuid,
    expires_at_unix_ms: u64,
    remaining_requests: u32,
    remaining_input: u64,
}

#[derive(Debug)]
struct LocalConcurrencyGrant {
    id: Uuid,
    expires_at_unix_ms: u64,
    slots: u32,
    in_use: u32,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct BudgetPairKey {
    key: Option<PolicyReference>,
    origin: Option<PolicyReference>,
}

#[derive(Debug)]
struct LocalBudgetGrant {
    request: PairedBudgetGrantRequest,
    expires_at_unix_ms: u64,
    key_remaining_nanos: u128,
    origin_remaining_nanos: u128,
    in_use: u32,
    returning: bool,
}

#[derive(Debug)]
struct ReturningBudgetGrant {
    pair: BudgetPairKey,
    request: PairedBudgetGrantRequest,
    key_remaining_nanos: u128,
    origin_remaining_nanos: u128,
}

#[derive(Clone, Copy, Debug, Default)]
struct BudgetDebt {
    key_nanos: u128,
    origin_nanos: u128,
}

#[derive(Clone, Debug)]
struct EnforcingBudgetSide {
    policy: PolicyReference,
    estimate_nanos: u128,
    max_slice_nanos: u128,
}

#[derive(Debug)]
pub(crate) struct AttemptReservation {
    state: Option<Arc<GatewayAdmissionState>>,
    pair: Option<BudgetPairKey>,
    grant_id: Option<Uuid>,
    key_reserved_nanos: u128,
    origin_reserved_nanos: u128,
    estimated_cost_nanos: Option<u128>,
    released: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LogicalAdmissionError {
    PolicyUnavailable,
    RateDenied,
    ConcurrencyDenied,
    BudgetDenied,
    CoordinatorUnavailable,
}

#[derive(Debug)]
pub(crate) struct LogicalRequestPermit {
    concurrency: Option<ConcurrencyPermit>,
}

#[derive(Debug)]
enum ConcurrencyPermit {
    Approximate {
        state: Arc<GatewayAdmissionState>,
        policy: PolicyReference,
        grant_id: Uuid,
    },
    Strict {
        coordinator: Arc<RedisCoordinator>,
        policy: PolicyReference,
        lease_id: Uuid,
    },
}

impl AttemptReservation {
    pub(crate) const fn unconstrained() -> Self {
        Self {
            state: None,
            pair: None,
            grant_id: None,
            key_reserved_nanos: 0,
            origin_reserved_nanos: 0,
            estimated_cost_nanos: None,
            released: false,
        }
    }

    const fn unconstrained_with_estimate(estimated_cost_nanos: Option<u128>) -> Self {
        Self {
            state: None,
            pair: None,
            grant_id: None,
            key_reserved_nanos: 0,
            origin_reserved_nanos: 0,
            estimated_cost_nanos,
            released: false,
        }
    }

    pub(crate) const fn estimated_cost_nanos(&self) -> Option<u128> {
        self.estimated_cost_nanos
    }

    pub(crate) fn definitely_not_dispatched(&mut self) {
        if self.released {
            return;
        }
        let (Some(state), Some(pair), Some(grant_id)) = (&self.state, &self.pair, self.grant_id)
        else {
            self.released = true;
            return;
        };
        state.release_budget_reservation(
            pair,
            grant_id,
            self.key_reserved_nanos,
            self.origin_reserved_nanos,
        );
        self.released = true;
    }

    pub(crate) fn settle_actual_cost(&mut self, actual_cost_nanos: u128) {
        if self.released {
            return;
        }
        let (Some(state), Some(pair), Some(grant_id)) = (&self.state, &self.pair, self.grant_id)
        else {
            self.released = true;
            return;
        };
        state.settle_budget_reservation(
            pair,
            grant_id,
            self.key_reserved_nanos,
            self.origin_reserved_nanos,
            actual_cost_nanos,
        );
        self.released = true;
    }
}

impl Drop for AttemptReservation {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        if let (Some(state), Some(pair), Some(grant_id)) = (&self.state, &self.pair, self.grant_id)
        {
            state.abandon_budget_reservation(pair, grant_id);
        }
        self.released = true;
    }
}

impl LogicalRequestPermit {
    pub(crate) const fn unconstrained() -> Self {
        Self { concurrency: None }
    }
}

impl Drop for LogicalRequestPermit {
    fn drop(&mut self) {
        match self.concurrency.take() {
            Some(ConcurrencyPermit::Approximate {
                state,
                policy,
                grant_id,
            }) => state.release_approximate(&policy, grant_id),
            Some(ConcurrencyPermit::Strict {
                coordinator,
                policy,
                lease_id,
            }) => {
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    runtime.spawn(async move {
                        if let Err(error) = coordinator
                            .release_strict_concurrency(&policy, lease_id)
                            .await
                        {
                            tracing::warn!(%error, %lease_id, "strict concurrency lease release failed");
                        }
                    });
                }
            }
            None => {}
        }
    }
}

impl GatewayAdmissionState {
    pub(crate) fn new(node_instance_id: String) -> Self {
        let (shutdown, _) = watch::channel(false);
        Self {
            node_instance_id,
            local: Mutex::new(LocalAdmissionState::default()),
            budget_refills: AsyncMutex::new(HashMap::new()),
            shutdown,
            task: AsyncMutex::new(None),
        }
    }

    pub(crate) async fn start(self: &Arc<Self>, coordinator: Arc<RedisCoordinator>) {
        let mut task = self.task.lock().await;
        if task.is_some() {
            return;
        }
        let state = Arc::clone(self);
        let receiver = self.shutdown.subscribe();
        *task = Some(tokio::spawn(async move {
            state.run_budget_returns(coordinator, receiver).await;
        }));
    }

    pub(crate) async fn shutdown(&self, coordinator: Option<&Arc<RedisCoordinator>>) {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.lock().await.take() {
            let _ = task.await;
        } else if let Some(coordinator) = coordinator {
            self.return_budget_grants(coordinator, None, true, 0).await;
        }
    }

    async fn run_budget_returns(
        self: Arc<Self>,
        coordinator: Arc<RedisCoordinator>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let mut interval = tokio::time::interval(BUDGET_RETURN_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.return_budget_grants(
                        &coordinator,
                        None,
                        false,
                        BUDGET_RETURN_AHEAD_MILLIS,
                    ).await;
                    self.prune_budget_refill_locks().await;
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        self.return_budget_grants(&coordinator, None, true, 0).await;
                        return;
                    }
                }
            }
        }
    }

    pub(crate) async fn admit_gateway_key(
        self: &Arc<Self>,
        coordinator: Option<&Arc<RedisCoordinator>>,
        generation: &RuntimeGeneration,
        verifier: &GatewayKeyVerifier,
        input_units: u64,
    ) -> Result<LogicalRequestPermit, LogicalAdmissionError> {
        let Some(policy_id) = verifier.rate_policy_id else {
            return Ok(LogicalRequestPermit { concurrency: None });
        };
        let policy = generation
            .snapshot
            .catalog
            .rate_policies
            .get(&policy_id)
            .filter(|policy| policy.active)
            .and_then(|policy| policy.active_version.as_ref())
            .ok_or(LogicalAdmissionError::PolicyUnavailable)?;
        let reference = PolicyReference {
            organization_id: verifier.organization_id,
            kind: PolicyKind::GatewayKeyRequestLimits,
            policy_id: policy_id.as_uuid(),
            version_id: policy.id.as_uuid(),
            epoch: policy.epoch.clone(),
            generation: policy.generation,
            recovery_generation: 0,
        };
        let coordinator = coordinator.ok_or(LogicalAdmissionError::CoordinatorUnavailable)?;
        self.consume_rate(coordinator, &reference, policy, input_units)
            .await?;
        let concurrency = self
            .acquire_concurrency(coordinator, &reference, policy)
            .await?;
        Ok(LogicalRequestPermit { concurrency })
    }

    pub(crate) async fn reserve_attempt(
        self: &Arc<Self>,
        coordinator: Option<&Arc<RedisCoordinator>>,
        generation: &RuntimeGeneration,
        verifier: &GatewayKeyVerifier,
        candidate: &Candidate,
        native: &NativeRequest,
        maximum_output_units: u64,
    ) -> Result<AttemptReservation, LogicalAdmissionError> {
        let key_policy = generation
            .snapshot
            .catalog
            .key_budget_policies
            .get(&verifier.budget_policy_id)
            .filter(|policy| policy.active)
            .and_then(|policy| policy.active_version.as_ref())
            .ok_or(LogicalAdmissionError::PolicyUnavailable)?;
        let origin_policy = generation
            .snapshot
            .organizations
            .get(&verifier.organization_id)
            .and_then(|organization| {
                organization
                    .origin_budgets
                    .get(&candidate.deployment.origin)
            })
            .filter(|policy| policy.active)
            .and_then(|policy| policy.active_version.as_ref())
            .ok_or(LogicalAdmissionError::PolicyUnavailable)?;
        let estimated_cost_nanos = [
            estimate_budget_cost_for_recording(key_policy, candidate, native, maximum_output_units),
            estimate_budget_cost_for_recording(
                origin_policy,
                candidate,
                native,
                maximum_output_units,
            ),
        ]
        .into_iter()
        .flatten()
        .max();
        let key_side = enforcing_budget_side(
            verifier.organization_id,
            PolicyKind::GatewayKeyBudget,
            verifier.budget_policy_id.as_uuid(),
            key_policy,
            candidate,
            native,
            maximum_output_units,
        )?;
        let origin_snapshot = generation
            .snapshot
            .organizations
            .get(&verifier.organization_id)
            .and_then(|organization| {
                organization
                    .origin_budgets
                    .get(&candidate.deployment.origin)
            })
            .ok_or(LogicalAdmissionError::PolicyUnavailable)?;
        let origin_side = enforcing_budget_side(
            verifier.organization_id,
            PolicyKind::OrganizationOriginBudget,
            origin_snapshot.id.as_uuid(),
            origin_policy,
            candidate,
            native,
            maximum_output_units,
        )?;
        if key_side.is_none() && origin_side.is_none() {
            return Ok(AttemptReservation::unconstrained_with_estimate(
                estimated_cost_nanos,
            ));
        }
        let coordinator = coordinator.ok_or(LogicalAdmissionError::CoordinatorUnavailable)?;
        let pair = BudgetPairKey {
            key: key_side.as_ref().map(|side| side.policy.clone()),
            origin: origin_side.as_ref().map(|side| side.policy.clone()),
        };
        self.return_budget_grants(coordinator, Some(&pair), false, 0)
            .await;
        let key_estimate = key_side.as_ref().map_or(0, |side| side.estimate_nanos);
        let origin_estimate = origin_side.as_ref().map_or(0, |side| side.estimate_nanos);
        if let Some(reservation) =
            self.try_reserve_budget(&pair, key_estimate, origin_estimate, estimated_cost_nanos)?
        {
            return Ok(reservation);
        }
        let refill_lock = self.budget_refill_lock(&pair).await;
        let _refill_guard = refill_lock.lock().await;
        self.return_budget_grants(coordinator, Some(&pair), false, 0)
            .await;
        if let Some(reservation) =
            self.try_reserve_budget(&pair, key_estimate, origin_estimate, estimated_cost_nanos)?
        {
            return Ok(reservation);
        }
        let key_amount = key_side
            .as_ref()
            .map(|side| side.estimate_nanos.max(side.max_slice_nanos));
        let origin_amount = origin_side
            .as_ref()
            .map(|side| side.estimate_nanos.max(side.max_slice_nanos));
        let one_shot = key_side
            .as_ref()
            .is_some_and(|side| side.estimate_nanos > side.max_slice_nanos)
            || origin_side
                .as_ref()
                .is_some_and(|side| side.estimate_nanos > side.max_slice_nanos);
        let request = PairedBudgetGrantRequest {
            organization_id: verifier.organization_id,
            grant_id: Uuid::now_v7(),
            node_instance_id: self.node_instance_id.clone(),
            key: key_side
                .as_ref()
                .zip(key_amount)
                .map(|(side, amount)| BudgetGrantSide {
                    policy: side.policy.clone(),
                    amount_nanos: amount,
                }),
            origin: origin_side
                .as_ref()
                .zip(origin_amount)
                .map(|(side, amount)| BudgetGrantSide {
                    policy: side.policy.clone(),
                    amount_nanos: amount,
                }),
            requested_ttl: std::time::Duration::from_secs(3600),
            one_shot,
        };
        let grant = coordinator
            .grant_budget_allowance(&request)
            .await
            .map_err(map_budget_error)?;
        self.install_budget_grant(&pair, request, grant)?;
        self.try_reserve_budget(&pair, key_estimate, origin_estimate, estimated_cost_nanos)?
            .ok_or(LogicalAdmissionError::BudgetDenied)
    }

    async fn budget_refill_lock(&self, pair: &BudgetPairKey) -> Arc<AsyncMutex<()>> {
        let mut refills = self.budget_refills.lock().await;
        Arc::clone(
            refills
                .entry(pair.clone())
                .or_insert_with(|| Arc::new(AsyncMutex::new(()))),
        )
    }

    async fn prune_budget_refill_locks(&self) {
        self.budget_refills
            .lock()
            .await
            .retain(|_, lock| Arc::strong_count(lock) > 1);
    }

    async fn return_budget_grants(
        &self,
        coordinator: &Arc<RedisCoordinator>,
        only_pair: Option<&BudgetPairKey>,
        close_all: bool,
        return_ahead_millis: u64,
    ) {
        let Ok(now) = unix_millis() else {
            return;
        };
        let deadline = now.saturating_add(return_ahead_millis);
        let returning = {
            let Ok(mut local) = self.local.lock() else {
                return;
            };
            let mut returning = Vec::new();
            for (pair, grants) in &mut local.budget_grants {
                if only_pair.is_some_and(|selected| selected != pair) {
                    continue;
                }
                for grant in grants {
                    if !grant.returning
                        && grant.in_use == 0
                        && (close_all || grant.expires_at_unix_ms <= deadline)
                    {
                        grant.returning = true;
                        returning.push(ReturningBudgetGrant {
                            pair: pair.clone(),
                            request: grant.request.clone(),
                            key_remaining_nanos: grant.key_remaining_nanos,
                            origin_remaining_nanos: grant.origin_remaining_nanos,
                        });
                    }
                }
            }
            returning
        };
        for grant in returning {
            let result = coordinator
                .return_budget_allowance(
                    &grant.request,
                    grant.key_remaining_nanos,
                    grant.origin_remaining_nanos,
                )
                .await;
            let Ok(mut local) = self.local.lock() else {
                return;
            };
            if let Some(grants) = local.budget_grants.get_mut(&grant.pair) {
                if result.is_ok() {
                    grants.retain(|existing| existing.request.grant_id != grant.request.grant_id);
                } else if let Some(existing) = grants
                    .iter_mut()
                    .find(|existing| existing.request.grant_id == grant.request.grant_id)
                {
                    existing.returning = false;
                }
            }
            if let Err(error) = result {
                tracing::warn!(grant_id=%grant.request.grant_id, %error, "unused budget allowance return failed");
            }
        }
        if let Ok(mut local) = self.local.lock() {
            local.budget_grants.retain(|_, grants| !grants.is_empty());
        }
    }

    fn try_reserve_budget(
        self: &Arc<Self>,
        pair: &BudgetPairKey,
        key_estimate_nanos: u128,
        origin_estimate_nanos: u128,
        estimated_cost_nanos: Option<u128>,
    ) -> Result<Option<AttemptReservation>, LogicalAdmissionError> {
        let now = unix_millis()?;
        let mut local = self
            .local
            .lock()
            .map_err(|_| LogicalAdmissionError::CoordinatorUnavailable)?;
        if local
            .budget_debts
            .get(pair)
            .is_some_and(|debt| debt.key_nanos > 0 || debt.origin_nanos > 0)
        {
            return Ok(None);
        }
        let grants = local.budget_grants.entry(pair.clone()).or_default();
        for grant in grants {
            if !grant.returning
                && grant.expires_at_unix_ms > now
                && grant.key_remaining_nanos >= key_estimate_nanos
                && grant.origin_remaining_nanos >= origin_estimate_nanos
            {
                grant.key_remaining_nanos -= key_estimate_nanos;
                grant.origin_remaining_nanos -= origin_estimate_nanos;
                grant.in_use = grant.in_use.saturating_add(1);
                return Ok(Some(AttemptReservation {
                    state: Some(Arc::clone(self)),
                    pair: Some(pair.clone()),
                    grant_id: Some(grant.request.grant_id),
                    key_reserved_nanos: key_estimate_nanos,
                    origin_reserved_nanos: origin_estimate_nanos,
                    estimated_cost_nanos,
                    released: false,
                }));
            }
        }
        Ok(None)
    }

    fn install_budget_grant(
        &self,
        pair: &BudgetPairKey,
        request: PairedBudgetGrantRequest,
        grant: AllowanceGrant,
    ) -> Result<(), LogicalAdmissionError> {
        let mut local = self
            .local
            .lock()
            .map_err(|_| LogicalAdmissionError::CoordinatorUnavailable)?;
        let mut key_remaining_nanos = grant.key_amount_nanos.unwrap_or(0);
        let mut origin_remaining_nanos = grant.origin_amount_nanos.unwrap_or(0);
        if let Some(debt) = local.budget_debts.get_mut(pair) {
            let key_payment = key_remaining_nanos.min(debt.key_nanos);
            key_remaining_nanos -= key_payment;
            debt.key_nanos -= key_payment;
            let origin_payment = origin_remaining_nanos.min(debt.origin_nanos);
            origin_remaining_nanos -= origin_payment;
            debt.origin_nanos -= origin_payment;
        }
        local
            .budget_debts
            .retain(|_, debt| debt.key_nanos > 0 || debt.origin_nanos > 0);
        let grants = local.budget_grants.entry(pair.clone()).or_default();
        if !grants
            .iter()
            .any(|existing| existing.request.grant_id == grant.id)
        {
            grants.push(LocalBudgetGrant {
                request,
                expires_at_unix_ms: grant.expires_at_unix_ms,
                key_remaining_nanos,
                origin_remaining_nanos,
                in_use: 0,
                returning: false,
            });
        }
        Ok(())
    }

    fn abandon_budget_reservation(&self, pair: &BudgetPairKey, grant_id: Uuid) {
        let Ok(mut local) = self.local.lock() else {
            tracing::error!(%grant_id, "budget allowance state lock was poisoned");
            return;
        };
        if let Some(grant) = local.budget_grants.get_mut(pair).and_then(|grants| {
            grants
                .iter_mut()
                .find(|grant| grant.request.grant_id == grant_id)
        }) {
            grant.in_use = grant.in_use.saturating_sub(1);
        }
    }

    fn release_budget_reservation(
        &self,
        pair: &BudgetPairKey,
        grant_id: Uuid,
        key_nanos: u128,
        origin_nanos: u128,
    ) {
        let Ok(mut local) = self.local.lock() else {
            tracing::error!(%grant_id, "budget allowance state lock was poisoned");
            return;
        };
        if let Some(grant) = local.budget_grants.get_mut(pair).and_then(|grants| {
            grants
                .iter_mut()
                .find(|grant| grant.request.grant_id == grant_id)
        }) {
            grant.key_remaining_nanos = grant.key_remaining_nanos.saturating_add(key_nanos);
            grant.origin_remaining_nanos =
                grant.origin_remaining_nanos.saturating_add(origin_nanos);
            grant.in_use = grant.in_use.saturating_sub(1);
        }
    }

    fn settle_budget_reservation(
        &self,
        pair: &BudgetPairKey,
        grant_id: Uuid,
        key_reserved_nanos: u128,
        origin_reserved_nanos: u128,
        actual_cost_nanos: u128,
    ) {
        let Ok(mut local) = self.local.lock() else {
            tracing::error!(%grant_id, "budget allowance state lock was poisoned");
            return;
        };
        let mut key_debt = 0_u128;
        let mut origin_debt = 0_u128;
        if let Some(grant) = local.budget_grants.get_mut(pair).and_then(|grants| {
            grants
                .iter_mut()
                .find(|grant| grant.request.grant_id == grant_id)
        }) {
            settle_budget_side(
                &mut grant.key_remaining_nanos,
                key_reserved_nanos,
                if key_reserved_nanos == 0 {
                    0
                } else {
                    actual_cost_nanos
                },
                &mut key_debt,
            );
            settle_budget_side(
                &mut grant.origin_remaining_nanos,
                origin_reserved_nanos,
                if origin_reserved_nanos == 0 {
                    0
                } else {
                    actual_cost_nanos
                },
                &mut origin_debt,
            );
            grant.in_use = grant.in_use.saturating_sub(1);
        } else {
            key_debt = pair
                .key
                .as_ref()
                .map_or(0, |_| actual_cost_nanos.saturating_sub(key_reserved_nanos));
            origin_debt = pair.origin.as_ref().map_or(0, |_| {
                actual_cost_nanos.saturating_sub(origin_reserved_nanos)
            });
        }
        if key_debt > 0 || origin_debt > 0 {
            let debt = local.budget_debts.entry(pair.clone()).or_default();
            debt.key_nanos = debt.key_nanos.saturating_add(key_debt);
            debt.origin_nanos = debt.origin_nanos.saturating_add(origin_debt);
        }
    }

    async fn consume_rate(
        &self,
        coordinator: &Arc<RedisCoordinator>,
        policy: &PolicyReference,
        config: &RatePolicyVersionSnapshot,
        input_units: u64,
    ) -> Result<(), LogicalAdmissionError> {
        let input_limited = config.input_units_per_minute.is_some();
        if config.grant_mode == "local_grants" {
            if self.try_consume_local_rate(policy, input_units, input_limited)? {
                return Ok(());
            }
            let request_tokens = config.grant_policy.max_request_tokens;
            let requested_input = config.input_units_per_minute.map_or(0, |capacity| {
                input_units
                    .saturating_mul(u64::from(request_tokens))
                    .min(capacity)
            });
            let grant = coordinator
                .grant_rate_tokens(
                    policy,
                    Uuid::now_v7(),
                    request_tokens,
                    requested_input,
                    false,
                )
                .await
                .map_err(map_rate_error)?;
            self.install_rate_grant(policy, grant)?;
            if self.try_consume_local_rate(policy, input_units, input_limited)? {
                Ok(())
            } else {
                Err(LogicalAdmissionError::RateDenied)
            }
        } else if config.grant_mode == "strict" {
            coordinator
                .grant_rate_tokens(policy, Uuid::now_v7(), 1, input_units, true)
                .await
                .map(|_| ())
                .map_err(map_rate_error)
        } else {
            Err(LogicalAdmissionError::PolicyUnavailable)
        }
    }

    async fn acquire_concurrency(
        self: &Arc<Self>,
        coordinator: &Arc<RedisCoordinator>,
        policy: &PolicyReference,
        config: &RatePolicyVersionSnapshot,
    ) -> Result<Option<ConcurrencyPermit>, LogicalAdmissionError> {
        match config.concurrency_mode.as_deref() {
            None => Ok(None),
            Some("approximate") => {
                if let Some(grant_id) = self.try_acquire_approximate(policy)? {
                    return Ok(Some(ConcurrencyPermit::Approximate {
                        state: Arc::clone(self),
                        policy: policy.clone(),
                        grant_id,
                    }));
                }
                let grant = coordinator
                    .grant_approximate_concurrency_slots(policy, Uuid::now_v7(), 1)
                    .await
                    .map_err(map_concurrency_error)?;
                self.install_concurrency_grant(policy, grant)?;
                let grant_id = self
                    .try_acquire_approximate(policy)?
                    .ok_or(LogicalAdmissionError::ConcurrencyDenied)?;
                Ok(Some(ConcurrencyPermit::Approximate {
                    state: Arc::clone(self),
                    policy: policy.clone(),
                    grant_id,
                }))
            }
            Some("strict") => {
                let lease_seconds = config
                    .lease_seconds
                    .ok_or(LogicalAdmissionError::PolicyUnavailable)?;
                let lease_id = Uuid::now_v7();
                coordinator
                    .acquire_strict_concurrency(policy, lease_id, lease_seconds)
                    .await
                    .map_err(map_concurrency_error)?;
                Ok(Some(ConcurrencyPermit::Strict {
                    coordinator: Arc::clone(coordinator),
                    policy: policy.clone(),
                    lease_id,
                }))
            }
            Some(_) => Err(LogicalAdmissionError::PolicyUnavailable),
        }
    }

    fn try_consume_local_rate(
        &self,
        policy: &PolicyReference,
        input_units: u64,
        input_limited: bool,
    ) -> Result<bool, LogicalAdmissionError> {
        let now = unix_millis()?;
        let mut local = self
            .local
            .lock()
            .map_err(|_| LogicalAdmissionError::CoordinatorUnavailable)?;
        let grants = local.rate_grants.entry(policy.clone()).or_default();
        grants.retain(|grant| grant.expires_at_unix_ms > now && grant.remaining_requests > 0);
        for grant in grants {
            if grant.remaining_requests > 0
                && (!input_limited || grant.remaining_input >= input_units)
            {
                grant.remaining_requests -= 1;
                if input_limited {
                    grant.remaining_input -= input_units;
                }
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn install_rate_grant(
        &self,
        policy: &PolicyReference,
        grant: RateTokenGrant,
    ) -> Result<(), LogicalAdmissionError> {
        let mut local = self
            .local
            .lock()
            .map_err(|_| LogicalAdmissionError::CoordinatorUnavailable)?;
        let grants = local.rate_grants.entry(policy.clone()).or_default();
        if !grants.iter().any(|existing| existing.id == grant.id) {
            grants.push(LocalRateGrant {
                id: grant.id,
                expires_at_unix_ms: grant.expires_at_unix_ms,
                remaining_requests: grant.request_tokens,
                remaining_input: grant.input_tokens,
            });
        }
        Ok(())
    }

    fn try_acquire_approximate(
        &self,
        policy: &PolicyReference,
    ) -> Result<Option<Uuid>, LogicalAdmissionError> {
        let now = unix_millis()?;
        let mut local = self
            .local
            .lock()
            .map_err(|_| LogicalAdmissionError::CoordinatorUnavailable)?;
        let grants = local.concurrency_grants.entry(policy.clone()).or_default();
        grants.retain(|grant| grant.expires_at_unix_ms > now || grant.in_use > 0);
        for grant in grants {
            if grant.expires_at_unix_ms > now && grant.in_use < grant.slots {
                grant.in_use += 1;
                return Ok(Some(grant.id));
            }
        }
        Ok(None)
    }

    fn install_concurrency_grant(
        &self,
        policy: &PolicyReference,
        grant: ConcurrencySlotGrant,
    ) -> Result<(), LogicalAdmissionError> {
        let mut local = self
            .local
            .lock()
            .map_err(|_| LogicalAdmissionError::CoordinatorUnavailable)?;
        let grants = local.concurrency_grants.entry(policy.clone()).or_default();
        if !grants.iter().any(|existing| existing.id == grant.id) {
            grants.push(LocalConcurrencyGrant {
                id: grant.id,
                expires_at_unix_ms: grant.expires_at_unix_ms,
                slots: grant.slots,
                in_use: 0,
            });
        }
        Ok(())
    }

    fn release_approximate(&self, policy: &PolicyReference, grant_id: Uuid) {
        let Ok(mut local) = self.local.lock() else {
            tracing::error!(%grant_id, "approximate concurrency state lock was poisoned");
            return;
        };
        if let Some(grant) = local
            .concurrency_grants
            .get_mut(policy)
            .and_then(|grants| grants.iter_mut().find(|grant| grant.id == grant_id))
        {
            grant.in_use = grant.in_use.saturating_sub(1);
        }
    }
}

fn settle_budget_side(
    remaining_nanos: &mut u128,
    reserved_nanos: u128,
    actual_nanos: u128,
    debt_nanos: &mut u128,
) {
    if actual_nanos <= reserved_nanos {
        *remaining_nanos = remaining_nanos.saturating_add(reserved_nanos - actual_nanos);
        return;
    }
    let excess = actual_nanos - reserved_nanos;
    let covered = (*remaining_nanos).min(excess);
    *remaining_nanos -= covered;
    *debt_nanos = excess - covered;
}

fn enforcing_budget_side(
    organization_id: crate::domain::OrganizationId,
    kind: PolicyKind,
    policy_id: Uuid,
    policy: &BudgetPolicyVersionSnapshot,
    candidate: &Candidate,
    native: &NativeRequest,
    maximum_output_units: u64,
) -> Result<Option<EnforcingBudgetSide>, LogicalAdmissionError> {
    if policy.mode == BudgetMode::RecordOnly {
        return Ok(None);
    }
    let estimate = estimate_budget_cost(policy, candidate, native, maximum_output_units)?;
    if estimate == 0 {
        return Ok(None);
    }
    Ok(Some(EnforcingBudgetSide {
        policy: PolicyReference {
            organization_id,
            kind,
            policy_id,
            version_id: policy.id.as_uuid(),
            epoch: policy.epoch.clone(),
            generation: policy.generation,
            recovery_generation: policy.recovery_generation,
        },
        estimate_nanos: estimate,
        max_slice_nanos: policy.allowance_policy.max_slice_nanos,
    }))
}

fn estimate_budget_cost_for_recording(
    policy: &BudgetPolicyVersionSnapshot,
    candidate: &Candidate,
    native: &NativeRequest,
    maximum_output_units: u64,
) -> Option<u128> {
    calculate_budget_cost(policy, candidate, native, maximum_output_units).or_else(|| {
        (policy.estimate_policy.unknown_mode == UnknownEstimateMode::FixedUnknownReservation)
            .then_some(policy.estimate_policy.fixed_unknown_reservation_nanos)
            .flatten()
    })
}

fn estimate_budget_cost(
    policy: &BudgetPolicyVersionSnapshot,
    candidate: &Candidate,
    native: &NativeRequest,
    maximum_output_units: u64,
) -> Result<u128, LogicalAdmissionError> {
    if let Some(cost) = calculate_budget_cost(policy, candidate, native, maximum_output_units) {
        return Ok(cost);
    }
    match policy.estimate_policy.unknown_mode {
        UnknownEstimateMode::RequireEstimate => Err(LogicalAdmissionError::BudgetDenied),
        UnknownEstimateMode::FixedUnknownReservation => policy
            .estimate_policy
            .fixed_unknown_reservation_nanos
            .ok_or(LogicalAdmissionError::PolicyUnavailable),
    }
}

fn calculate_budget_cost(
    policy: &BudgetPolicyVersionSnapshot,
    candidate: &Candidate,
    native: &NativeRequest,
    maximum_output_units: u64,
) -> Option<u128> {
    candidate.deployment.pricing.as_ref().and_then(|pricing| {
        let input_units = u64::try_from(native.original_body.len())
            .ok()?
            .checked_mul(u64::from(policy.estimate_policy.input_units_per_byte))?;
        let mut usage = HashMap::new();
        for dimension in pricing.rates.cost_nanos_per_unit.keys() {
            let quantity = match dimension.as_str() {
                "input_tokens" | "input_units" => input_units,
                "output_tokens" | "output_units" => maximum_output_units,
                "request" | "requests" => 1,
                _ => return None,
            };
            usage.insert(dimension.clone(), quantity);
        }
        match pricing.price(&usage) {
            PricingOutcome::Known { cost_nanos } => Some(cost_nanos),
            PricingOutcome::Unknown { .. } | PricingOutcome::Overflow => None,
        }
    })
}

fn unix_millis() -> Result<u64, LogicalAdmissionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LogicalAdmissionError::CoordinatorUnavailable)
        .and_then(|duration| {
            u64::try_from(duration.as_millis())
                .map_err(|_| LogicalAdmissionError::CoordinatorUnavailable)
        })
}

fn map_budget_error(error: CoordinatorError) -> LogicalAdmissionError {
    match error {
        CoordinatorError::Denied => LogicalAdmissionError::BudgetDenied,
        CoordinatorError::Conflict => LogicalAdmissionError::PolicyUnavailable,
        _ => LogicalAdmissionError::CoordinatorUnavailable,
    }
}

fn map_rate_error(error: CoordinatorError) -> LogicalAdmissionError {
    match error {
        CoordinatorError::Denied => LogicalAdmissionError::RateDenied,
        CoordinatorError::Conflict => LogicalAdmissionError::PolicyUnavailable,
        _ => LogicalAdmissionError::CoordinatorUnavailable,
    }
}

fn map_concurrency_error(error: CoordinatorError) -> LogicalAdmissionError {
    match error {
        CoordinatorError::Denied => LogicalAdmissionError::ConcurrencyDenied,
        CoordinatorError::Conflict => LogicalAdmissionError::PolicyUnavailable,
        _ => LogicalAdmissionError::CoordinatorUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adapters::coordinator::{PolicyCandidate, PolicyCoordinatorConfig},
        domain::OrganizationId,
    };

    async fn test_coordinator() -> Option<Arc<RedisCoordinator>> {
        let url = std::env::var("OWLRORA_TEST_REDIS_URL").ok()?;
        let url = url::Url::parse(&url).unwrap();
        Some(Arc::new(
            RedisCoordinator::connect(&url, 4, Duration::from_secs(2), Duration::from_secs(2))
                .await
                .unwrap(),
        ))
    }

    async fn active_budget_policy(
        coordinator: &RedisCoordinator,
        organization_id: OrganizationId,
        limit: u128,
    ) -> PolicyReference {
        let version_id = Uuid::now_v7();
        let candidate = PolicyCandidate {
            organization_id,
            kind: PolicyKind::GatewayKeyBudget,
            policy_id: Uuid::now_v7(),
            desired_epoch: Uuid::now_v7().to_string(),
            desired_version_id: version_id,
            desired_generation: 1,
            desired_recovery_generation: 0,
            fence: Uuid::now_v7(),
            config: PolicyCoordinatorConfig::Budget {
                version_id,
                mode: "enforce".to_owned(),
                limit_cost_nanos: limit.to_string(),
                max_slice_nanos: limit.to_string(),
                grant_seconds: 30,
            },
        };
        coordinator.stage_policy(&candidate).await.unwrap();
        coordinator.arm_policy(&candidate).await.unwrap();
        coordinator.activate_policy(&candidate).await.unwrap();
        PolicyReference {
            organization_id,
            kind: candidate.kind,
            policy_id: candidate.policy_id,
            version_id,
            epoch: candidate.desired_epoch,
            generation: 1,
            recovery_generation: 0,
        }
    }

    fn grant_request(
        organization_id: OrganizationId,
        policy: PolicyReference,
        amount_nanos: u128,
    ) -> PairedBudgetGrantRequest {
        PairedBudgetGrantRequest {
            organization_id,
            grant_id: Uuid::now_v7(),
            node_instance_id: "admission-test".to_owned(),
            key: Some(BudgetGrantSide {
                policy,
                amount_nanos,
            }),
            origin: None,
            requested_ttl: Duration::from_secs(30),
            one_shot: true,
        }
    }

    #[tokio::test]
    async fn exact_pair_refills_share_one_singleflight_lock() {
        let state = GatewayAdmissionState::default();
        let pair = BudgetPairKey {
            key: None,
            origin: None,
        };
        let first = state.budget_refill_lock(&pair).await;
        let second = state.budget_refill_lock(&pair).await;
        assert!(Arc::ptr_eq(&first, &second));
        drop(first);
        drop(second);
        state.prune_budget_refill_locks().await;
        assert!(state.budget_refills.lock().await.is_empty());
    }

    #[tokio::test]
    async fn budget_returns_wait_for_in_flight_reservations_and_preserve_ambiguous_spend() {
        let Some(coordinator) = test_coordinator().await else {
            return;
        };
        let organization_id = OrganizationId::new();
        let policy = active_budget_policy(&coordinator, organization_id, 100).await;
        let pair = BudgetPairKey {
            key: Some(policy.clone()),
            origin: None,
        };
        let state = Arc::new(GatewayAdmissionState::default());
        let request = grant_request(organization_id, policy.clone(), 100);
        let grant = coordinator.grant_budget_allowance(&request).await.unwrap();
        state.install_budget_grant(&pair, request, grant).unwrap();
        let reservation = state
            .try_reserve_budget(&pair, 25, 0, Some(25))
            .unwrap()
            .unwrap();

        state
            .return_budget_grants(&coordinator, None, true, 0)
            .await;
        let denied = grant_request(organization_id, policy.clone(), 1);
        assert!(matches!(
            coordinator.grant_budget_allowance(&denied).await,
            Err(CoordinatorError::Denied)
        ));

        drop(reservation);
        state
            .return_budget_grants(&coordinator, None, true, 0)
            .await;
        let remaining = grant_request(organization_id, policy.clone(), 75);
        coordinator
            .grant_budget_allowance(&remaining)
            .await
            .unwrap();
        let over_remaining = grant_request(organization_id, policy, 1);
        assert!(matches!(
            coordinator.grant_budget_allowance(&over_remaining).await,
            Err(CoordinatorError::Denied)
        ));
    }
}
