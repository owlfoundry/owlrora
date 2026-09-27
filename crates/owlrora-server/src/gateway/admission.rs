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
    local: Mutex<LocalAdmissionState>,
    budget_refills: AsyncMutex<HashMap<BudgetPairKey, Arc<AsyncMutex<()>>>>,
    budget_returns: AsyncMutex<()>,
    lease_releases: Mutex<tokio::task::JoinSet<()>>,
    shutdown: watch::Sender<bool>,
    task: AsyncMutex<Option<JoinHandle<()>>>,
}

impl Default for GatewayAdmissionState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
struct LocalAdmissionState {
    rate_grants: HashMap<PolicyReference, Vec<LocalRateGrant>>,
    concurrency_grants: HashMap<PolicyReference, Vec<LocalConcurrencyGrant>>,
    budget_grants: HashMap<BudgetPairKey, Vec<LocalBudgetGrant>>,
    budget_debts: HashMap<BudgetLedgerKey, u128>,
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

// Policy versions and paired grants share one debt balance for the epoch.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct BudgetLedgerKey {
    organization_id: crate::domain::OrganizationId,
    kind: PolicyKind,
    policy_id: Uuid,
    epoch: String,
}

impl From<&PolicyReference> for BudgetLedgerKey {
    fn from(policy: &PolicyReference) -> Self {
        Self {
            organization_id: policy.organization_id,
            kind: policy.kind,
            policy_id: policy.policy_id,
            epoch: policy.epoch.clone(),
        }
    }
}

fn pay_budget_debt(
    debts: &mut HashMap<BudgetLedgerKey, u128>,
    policy: Option<&PolicyReference>,
    remaining_nanos: &mut u128,
) {
    let Some(policy) = policy else { return };
    let key = BudgetLedgerKey::from(policy);
    if let Some(debt) = debts.get_mut(&key) {
        let payment = (*remaining_nanos).min(*debt);
        *remaining_nanos -= payment;
        *debt -= payment;
        if *debt == 0 {
            debts.remove(&key);
        }
    }
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
    dispatched: bool,
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
        state: Arc<GatewayAdmissionState>,
        coordinator: Arc<RedisCoordinator>,
        policy: PolicyReference,
        lease_id: Uuid,
        deadline: tokio::time::Instant,
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
            dispatched: false,
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
            dispatched: false,
            released: false,
        }
    }

    pub(crate) const fn estimated_cost_nanos(&self) -> Option<u128> {
        self.estimated_cost_nanos
    }

    pub(crate) fn mark_dispatched(&mut self) {
        self.dispatched = true;
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
        if !self.dispatched {
            self.definitely_not_dispatched();
        }
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
    pub(crate) fn deadline(&self) -> Option<tokio::time::Instant> {
        match &self.concurrency {
            Some(ConcurrencyPermit::Strict { deadline, .. }) => Some(*deadline),
            _ => None,
        }
    }

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
                state,
                coordinator,
                policy,
                lease_id,
                ..
            }) if tokio::runtime::Handle::try_current().is_ok() => {
                let mut releases = state.lease_releases.lock().expect("lease release registry");
                while releases.try_join_next().is_some() {}
                releases.spawn(async move {
                        if let Err(error) = coordinator
                            .release_strict_concurrency(&policy, lease_id)
                            .await
                        {
                            tracing::warn!(%error, %lease_id, "strict concurrency lease release failed");
                        }
                    });
            }
            Some(ConcurrencyPermit::Strict { .. }) | None => {}
        }
    }
}

impl GatewayAdmissionState {
    pub(crate) fn new() -> Self {
        let (shutdown, _) = watch::channel(false);
        Self {
            local: Mutex::new(LocalAdmissionState::default()),
            budget_refills: AsyncMutex::new(HashMap::new()),
            budget_returns: AsyncMutex::new(()),
            lease_releases: Mutex::new(tokio::task::JoinSet::new()),
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

    pub(crate) async fn shutdown_bounded(
        &self,
        coordinator: Option<&Arc<RedisCoordinator>>,
        grace: Duration,
    ) {
        self.shutdown.send_replace(true);
        let deadline = tokio::time::Instant::now() + grace;
        let mut releases =
            std::mem::take(&mut *self.lease_releases.lock().expect("lease release registry"));
        if tokio::time::timeout_at(deadline, async {
            while releases.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            tracing::warn!(
                "strict lease release deadline exceeded; remaining leases expire by TTL"
            );
            releases.abort_all();
            while releases.join_next().await.is_some() {}
        }
        let grace = deadline.saturating_duration_since(tokio::time::Instant::now());
        let complete = if let Some(task) = self.task.lock().await.take() {
            crate::lifecycle::join_bounded(task, grace).await
        } else if let Some(coordinator) = coordinator {
            tokio::time::timeout(grace, self.return_budget_grants(coordinator, None, true, 0))
                .await
                .is_ok()
        } else {
            true
        };
        if !complete {
            tracing::warn!(
                "allowance shutdown deadline exceeded; unused grants may expire without return"
            );
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
        if !generation.snapshot.policy_admission_ready(
            PolicyKind::GatewayKeyRequestLimits,
            policy_id.as_uuid(),
            chrono::Utc::now(),
        ) {
            return Err(LogicalAdmissionError::PolicyUnavailable);
        }
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
        let now = chrono::Utc::now();
        if !generation.snapshot.policy_admission_ready(
            PolicyKind::GatewayKeyBudget,
            verifier.budget_policy_id.as_uuid(),
            now,
        ) {
            return Err(LogicalAdmissionError::PolicyUnavailable);
        }
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
        if !generation.snapshot.policy_admission_ready(
            PolicyKind::OrganizationOriginBudget,
            origin_snapshot.id.as_uuid(),
            now,
        ) {
            return Err(LogicalAdmissionError::PolicyUnavailable);
        }
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
        // Coalesce return work without blocking unrelated admission. The lock
        // is cancellation-safe; frozen returns can be retried by the next owner.
        let Ok(_return_owner) = self.budget_returns.try_lock() else {
            return;
        };
        let Ok(now) = unix_millis() else {
            return;
        };
        let deadline = now.saturating_add(return_ahead_millis);
        let returning = {
            let Ok(mut local) = self.local.lock() else {
                return;
            };
            let mut returning = Vec::new();
            let LocalAdmissionState {
                budget_grants,
                budget_debts,
                ..
            } = &mut *local;
            for (pair, grants) in budget_grants {
                if only_pair.is_some_and(|selected| selected != pair) {
                    continue;
                }
                for grant in grants {
                    if grant.in_use == 0
                        && (grant.returning || close_all || grant.expires_at_unix_ms <= deadline)
                    {
                        if !grant.returning {
                            pay_budget_debt(
                                budget_debts,
                                pair.key.as_ref(),
                                &mut grant.key_remaining_nanos,
                            );
                            pay_budget_debt(
                                budget_debts,
                                pair.origin.as_ref(),
                                &mut grant.origin_remaining_nanos,
                            );
                            // Freeze the exact return permanently: Redis may
                            // apply it even when the acknowledgement is lost.
                            grant.returning = true;
                        }
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
        let LocalAdmissionState {
            budget_grants,
            budget_debts,
            ..
        } = &mut *local;
        let grants = budget_grants.entry(pair.clone()).or_default();
        for grant in grants.iter_mut().filter(|grant| !grant.returning) {
            pay_budget_debt(
                budget_debts,
                pair.key.as_ref(),
                &mut grant.key_remaining_nanos,
            );
            pay_budget_debt(
                budget_debts,
                pair.origin.as_ref(),
                &mut grant.origin_remaining_nanos,
            );
        }
        if [&pair.key, &pair.origin]
            .into_iter()
            .flatten()
            .any(|policy| budget_debts.contains_key(&BudgetLedgerKey::from(policy)))
        {
            return Ok(None);
        }
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
                    dispatched: false,
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
        let LocalAdmissionState {
            budget_grants,
            budget_debts,
            ..
        } = &mut *local;
        let grants = budget_grants.entry(pair.clone()).or_default();
        if grants
            .iter()
            .any(|existing| existing.request.grant_id == grant.id)
        {
            return Ok(());
        }
        let mut key_remaining_nanos = grant.key_amount_nanos.unwrap_or(0);
        let mut origin_remaining_nanos = grant.origin_amount_nanos.unwrap_or(0);
        pay_budget_debt(budget_debts, pair.key.as_ref(), &mut key_remaining_nanos);
        pay_budget_debt(
            budget_debts,
            pair.origin.as_ref(),
            &mut origin_remaining_nanos,
        );
        grants.push(LocalBudgetGrant {
            request,
            expires_at_unix_ms: grant.expires_at_unix_ms,
            key_remaining_nanos,
            origin_remaining_nanos,
            in_use: 0,
            returning: false,
        });
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
                if pair.key.is_none() {
                    0
                } else {
                    actual_cost_nanos
                },
                &mut key_debt,
            );
            settle_budget_side(
                &mut grant.origin_remaining_nanos,
                origin_reserved_nanos,
                if pair.origin.is_none() {
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
        for (policy, amount) in [
            (pair.key.as_ref(), key_debt),
            (pair.origin.as_ref(), origin_debt),
        ] {
            if let Some(policy) = policy.filter(|_| amount > 0) {
                let debt = local
                    .budget_debts
                    .entry(BudgetLedgerKey::from(policy))
                    .or_default();
                *debt = debt.saturating_add(amount);
            }
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
                let deadline = coordinator
                    .acquire_strict_concurrency(policy, lease_id, lease_seconds)
                    .await
                    .map_err(map_concurrency_error)?;
                Ok(Some(ConcurrencyPermit::Strict {
                    state: Arc::clone(self),
                    coordinator: Arc::clone(coordinator),
                    policy: policy.clone(),
                    lease_id,
                    deadline,
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
pub(super) mod tests {
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
        kind: PolicyKind,
        limit: u128,
    ) -> PolicyReference {
        let version_id = Uuid::now_v7();
        let candidate = PolicyCandidate {
            organization_id,
            kind,
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
            key: Some(BudgetGrantSide {
                policy,
                amount_nanos,
            }),
            origin: None,
            requested_ttl: Duration::from_secs(30),
            one_shot: true,
        }
    }

    async fn install_test_budget_grant(
        state: &GatewayAdmissionState,
        coordinator: &RedisCoordinator,
        pair: &BudgetPairKey,
        amount_nanos: u128,
    ) -> (PairedBudgetGrantRequest, AllowanceGrant) {
        let request = PairedBudgetGrantRequest {
            organization_id: pair
                .key
                .as_ref()
                .or(pair.origin.as_ref())
                .unwrap()
                .organization_id,
            grant_id: Uuid::now_v7(),
            key: pair.key.clone().map(|policy| BudgetGrantSide {
                policy,
                amount_nanos,
            }),
            origin: pair.origin.clone().map(|policy| BudgetGrantSide {
                policy,
                amount_nanos,
            }),
            requested_ttl: Duration::from_secs(30),
            one_shot: true,
        };
        let grant = coordinator.grant_budget_allowance(&request).await.unwrap();
        state
            .install_budget_grant(pair, request.clone(), grant.clone())
            .unwrap();
        (request, grant)
    }

    pub(in crate::gateway) async fn assert_response_settlement_charges_paired_grants(
        admission: &crate::gateway::AdmissionContext,
        candidate: &Candidate,
    ) {
        use crate::{
            adapters::provider::wire::{ProviderUsage, UsageCompleteness},
            gateway::dispatch::{AttemptTelemetry, ResponseSettlement},
        };
        let coordinator = test_coordinator().await.expect("Redis fixture is required");
        for explicit in [false, true] {
            for partial in [false, true] {
                let organization_id = OrganizationId::new();
                let pair = BudgetPairKey {
                    key: Some(
                        active_budget_policy(
                            &coordinator,
                            organization_id,
                            PolicyKind::GatewayKeyBudget,
                            1000,
                        )
                        .await,
                    ),
                    origin: Some(
                        active_budget_policy(
                            &coordinator,
                            organization_id,
                            PolicyKind::OrganizationOriginBudget,
                            1000,
                        )
                        .await,
                    ),
                };
                let state = Arc::new(GatewayAdmissionState::default());
                install_test_budget_grant(&state, &coordinator, &pair, 100).await;
                let mut reservation = state
                    .try_reserve_budget(&pair, 25, 25, Some(25))
                    .unwrap()
                    .unwrap();
                reservation.mark_dispatched();
                let mut telemetry = AttemptTelemetry::new(admission, candidate, &reservation);
                telemetry.mark_dispatched();
                let mut settlement = ResponseSettlement::new(reservation, telemetry);
                settlement.observe(ProviderUsage {
                    completeness: UsageCompleteness::Complete,
                    dimensions: [
                        ("input_tokens".to_owned(), 3),
                        ("output_tokens".to_owned(), 5),
                    ]
                    .into(),
                });
                if partial {
                    settlement.observe(ProviderUsage {
                        completeness: UsageCompleteness::Partial,
                        dimensions: [("input_tokens".to_owned(), 4)].into(),
                    });
                }
                if explicit {
                    settlement.finish();
                }
                assert!(
                    crate::gateway::lifetime::before(
                        tokio::time::Instant::now() + Duration::from_millis(1),
                        async move {
                            let _settlement = settlement;
                            std::future::pending::<()>().await;
                        }
                    )
                    .await
                    .is_err()
                );
                {
                    let local = state.local.lock().unwrap();
                    let grant = &local.budget_grants[&pair][0];
                    let remaining = if partial { 75 } else { 87 };
                    assert_eq!(grant.key_remaining_nanos, remaining);
                    assert_eq!(grant.origin_remaining_nanos, remaining);
                }
                state
                    .return_budget_grants(&coordinator, None, true, 0)
                    .await;
            }
        }
    }

    #[tokio::test]
    async fn policy_debt_follows_both_sides_across_pairs_and_grant_replays() {
        let Some(coordinator) = test_coordinator().await else {
            return;
        };
        let organization_id = OrganizationId::new();
        let key_a = active_budget_policy(
            &coordinator,
            organization_id,
            PolicyKind::GatewayKeyBudget,
            1000,
        )
        .await;
        let key_b = active_budget_policy(
            &coordinator,
            organization_id,
            PolicyKind::GatewayKeyBudget,
            1000,
        )
        .await;
        let origin_a = active_budget_policy(
            &coordinator,
            organization_id,
            PolicyKind::OrganizationOriginBudget,
            1000,
        )
        .await;
        let origin_b = active_budget_policy(
            &coordinator,
            organization_id,
            PolicyKind::OrganizationOriginBudget,
            1000,
        )
        .await;
        let pair = BudgetPairKey {
            key: Some(key_a.clone()),
            origin: Some(origin_a.clone()),
        };
        let other_origin = BudgetPairKey {
            key: Some(key_a.clone()),
            origin: Some(origin_b),
        };
        let other_key = BudgetPairKey {
            key: Some(key_b),
            origin: Some(origin_a.clone()),
        };
        let state = Arc::new(GatewayAdmissionState::default());
        let (request, grant) = install_test_budget_grant(&state, &coordinator, &pair, 100).await;
        install_test_budget_grant(&state, &coordinator, &other_origin, 40).await;
        install_test_budget_grant(&state, &coordinator, &other_key, 40).await;
        // An enforcing zero estimate must still settle actual consumption.
        state
            .try_reserve_budget(&pair, 0, 0, Some(0))
            .unwrap()
            .unwrap()
            .settle_actual_cost(150);
        assert_eq!(
            state.local.lock().unwrap().budget_debts[&BudgetLedgerKey::from(&key_a)],
            50
        );
        // Replayed allocation cannot pay the new debt with already-spent funds.
        state.install_budget_grant(&pair, request, grant).unwrap();
        assert_eq!(
            state.local.lock().unwrap().budget_debts[&BudgetLedgerKey::from(&key_a)],
            50
        );
        assert!(
            state
                .try_reserve_budget(&other_origin, 1, 1, Some(1))
                .unwrap()
                .is_none()
        );
        assert!(
            state
                .try_reserve_budget(&other_key, 1, 1, Some(1))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            state.local.lock().unwrap().budget_debts[&BudgetLedgerKey::from(&key_a)],
            10
        );
        assert_eq!(
            state.local.lock().unwrap().budget_debts[&BudgetLedgerKey::from(&origin_a)],
            10
        );
        install_test_budget_grant(&state, &coordinator, &other_origin, 20).await;
        install_test_budget_grant(&state, &coordinator, &other_key, 20).await;
        assert!(state.local.lock().unwrap().budget_debts.is_empty());
        for pair in [&other_origin, &other_key] {
            let mut reservation = state
                .try_reserve_budget(pair, 10, 10, Some(10))
                .unwrap()
                .unwrap();
            reservation.definitely_not_dispatched();
        }
        // Refunds pay sibling policy debt before returning unused allowance.
        state
            .try_reserve_budget(&pair, 0, 0, Some(0))
            .unwrap()
            .unwrap()
            .settle_actual_cost(5);
        state
            .return_budget_grants(&coordinator, None, true, 0)
            .await;
        assert!(state.local.lock().unwrap().budget_debts.is_empty());
        assert!(state.local.lock().unwrap().budget_grants.is_empty());
    }

    #[tokio::test]
    async fn uncertain_budget_return_never_reopens_funds_for_new_debt() {
        let Some(coordinator) = test_coordinator().await else {
            return;
        };
        let organization_id = OrganizationId::new();
        let policy = active_budget_policy(
            &coordinator,
            organization_id,
            PolicyKind::GatewayKeyBudget,
            500,
        )
        .await;
        let pair = BudgetPairKey {
            key: Some(policy.clone()),
            origin: None,
        };
        let state = Arc::new(GatewayAdmissionState::default());
        let (return_request, _) = install_test_budget_grant(&state, &coordinator, &pair, 100).await;
        install_test_budget_grant(&state, &coordinator, &pair, 100).await;
        // Model a successful coordinator return whose acknowledgement is lost:
        // the local frozen return remains, with no confirmed removal.
        state
            .local
            .lock()
            .unwrap()
            .budget_grants
            .get_mut(&pair)
            .unwrap()[0]
            .returning = true;
        coordinator
            .return_budget_allowance(&return_request, 100, 0)
            .await
            .unwrap();
        state
            .try_reserve_budget(&pair, 100, 0, Some(100))
            .unwrap()
            .unwrap()
            .settle_actual_cost(150);
        assert!(
            state
                .try_reserve_budget(&pair, 1, 0, Some(1))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            state.local.lock().unwrap().budget_debts[&BudgetLedgerKey::from(&policy)],
            50
        );
        state
            .return_budget_grants(&coordinator, None, true, 0)
            .await;
        assert!(state.local.lock().unwrap().budget_grants.is_empty());
        assert_eq!(
            state.local.lock().unwrap().budget_debts[&BudgetLedgerKey::from(&policy)],
            50
        );
        install_test_budget_grant(&state, &coordinator, &pair, 100).await;
        assert!(state.local.lock().unwrap().budget_debts.is_empty());
        assert!(
            state
                .try_reserve_budget(&pair, 51, 0, Some(51))
                .unwrap()
                .is_none()
        );
        state
            .try_reserve_budget(&pair, 50, 0, Some(50))
            .unwrap()
            .unwrap()
            .definitely_not_dispatched();
        state
            .return_budget_grants(&coordinator, None, true, 0)
            .await;
    }

    #[test]
    fn debt_identity_ignores_same_epoch_versions_but_not_policy_or_epoch() {
        let policy = PolicyReference {
            organization_id: OrganizationId::new(),
            kind: PolicyKind::GatewayKeyBudget,
            policy_id: Uuid::now_v7(),
            version_id: Uuid::now_v7(),
            epoch: "current".to_owned(),
            generation: 1,
            recovery_generation: 0,
        };
        let key = BudgetLedgerKey::from(&policy);
        let mut updated = policy.clone();
        updated.version_id = Uuid::now_v7();
        updated.generation += 1;
        updated.recovery_generation += 1;
        assert_eq!(key, BudgetLedgerKey::from(&updated));
        updated.epoch = "next".to_owned();
        assert_ne!(key, BudgetLedgerKey::from(&updated));
        updated = policy.clone();
        updated.policy_id = Uuid::now_v7();
        assert_ne!(key, BudgetLedgerKey::from(&updated));
        updated = policy.clone();
        updated.organization_id = OrganizationId::new();
        assert_ne!(key, BudgetLedgerKey::from(&updated));
        updated = policy;
        updated.kind = PolicyKind::OrganizationOriginBudget;
        assert_ne!(key, BudgetLedgerKey::from(&updated));
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
    async fn pre_dispatch_deadline_cancellation_refunds_both_budget_reservations() {
        let Some(coordinator) = test_coordinator().await else {
            return;
        };
        let organization_id = OrganizationId::new();
        let key = active_budget_policy(
            &coordinator,
            organization_id,
            PolicyKind::GatewayKeyBudget,
            100,
        )
        .await;
        let origin = active_budget_policy(
            &coordinator,
            organization_id,
            PolicyKind::OrganizationOriginBudget,
            100,
        )
        .await;
        let pair = BudgetPairKey {
            key: Some(key),
            origin: Some(origin),
        };
        let state = Arc::new(GatewayAdmissionState::default());
        install_test_budget_grant(&state, &coordinator, &pair, 100).await;
        let reservation = state
            .try_reserve_budget(&pair, 25, 40, Some(40))
            .unwrap()
            .unwrap();
        let result = super::super::lifetime::before(
            tokio::time::Instant::now() + Duration::from_millis(10),
            async move {
                // A pending pre-send operation (for example dynamic credential
                // authentication) is cancelled by the outer request deadline.
                let _reservation = reservation;
                std::future::pending::<()>().await;
            },
        )
        .await;
        assert!(result.is_err());
        let local = state.local.lock().unwrap();
        let grant = &local.budget_grants[&pair][0];
        assert_eq!(grant.key_remaining_nanos, 100);
        assert_eq!(grant.origin_remaining_nanos, 100);
        assert_eq!(grant.in_use, 0);
    }

    #[tokio::test]
    async fn budget_returns_wait_for_in_flight_reservations_and_preserve_ambiguous_spend() {
        let Some(coordinator) = test_coordinator().await else {
            return;
        };
        let organization_id = OrganizationId::new();
        let policy = active_budget_policy(
            &coordinator,
            organization_id,
            PolicyKind::GatewayKeyBudget,
            100,
        )
        .await;
        let pair = BudgetPairKey {
            key: Some(policy.clone()),
            origin: None,
        };
        let state = Arc::new(GatewayAdmissionState::default());
        let request = grant_request(organization_id, policy.clone(), 100);
        let grant = coordinator.grant_budget_allowance(&request).await.unwrap();
        state.install_budget_grant(&pair, request, grant).unwrap();
        let mut reservation = state
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

        reservation.mark_dispatched();
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
