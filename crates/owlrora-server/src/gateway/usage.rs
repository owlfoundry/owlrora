use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};

use chrono::{DateTime, Timelike as _, Utc};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;
use tokio::{
    sync::{Mutex as AsyncMutex, watch},
    task::JoinHandle,
};
use uuid::Uuid;

use crate::{
    adapters::{
        postgres::PgStore,
        provider::wire::{ProviderUsage, UsageCompleteness},
    },
    domain::AccountingOrigin,
    runtime::{DeploymentSnapshot, PricingOutcome},
};

use super::{AdmissionContext, Candidate, GatewayPrincipal};

const MAX_NUMERIC_38: u128 = 99_999_999_999_999_999_999_999_999_999_999_999_999;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AttemptTerminalClass {
    Actual,
    DefinitelyNotDispatched,
    UnknownOrAmbiguous,
}

impl AttemptTerminalClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Actual => "actual",
            Self::DefinitelyNotDispatched => "definitely_not_dispatched",
            Self::UnknownOrAmbiguous => "unknown_or_ambiguous",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct UsageConfig {
    pub flush_interval: Duration,
    pub max_aggregate_keys: usize,
    pub max_pending_batches: usize,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct UsageStatus {
    pub active_logical_keys: usize,
    pub active_attempt_keys: usize,
    pub pending_batches: usize,
    pub lost_logical_facts: u64,
    pub lost_attempt_facts: u64,
    pub last_flush_error: Option<String>,
}

#[derive(Debug)]
pub(crate) struct UsageAggregator {
    store: PgStore,
    source_epoch: Uuid,
    config: UsageConfig,
    state: Mutex<UsageState>,
    shutdown: watch::Sender<bool>,
    task: AsyncMutex<Option<JoinHandle<()>>>,
}

#[derive(Debug, Default)]
struct UsageState {
    next_batch_sequence: u64,
    logical: HashMap<LogicalUsageKey, LogicalUsageDelta>,
    attempts: HashMap<AttemptUsageKey, AttemptUsageDelta>,
    pending: VecDeque<UsageBatch>,
    lost_logical_facts: u64,
    lost_attempt_facts: u64,
    last_flush_error: Option<String>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
struct PrincipalDimensions {
    principal_kind: &'static str,
    gateway_api_key_id: Option<Uuid>,
    user_id: Option<Uuid>,
    membership_id: Option<Uuid>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
struct LogicalUsageKey {
    bucket_start: DateTime<Utc>,
    organization_id: Uuid,
    principal: PrincipalDimensions,
    route_id: Uuid,
    route_grant_identity_id: Option<Uuid>,
    ingress_protocol_family: &'static str,
    outcome_class: &'static str,
}

#[derive(Clone, Debug, Default, Serialize)]
struct LogicalUsageDelta {
    request_count: u64,
    input_units: u128,
    output_units: u128,
    cached_input_units: u128,
    cost_nanos: Option<u128>,
    unknown_cost_count: u64,
    duration_millis: u128,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
struct BudgetDimensions {
    key_policy_id: Option<Uuid>,
    key_version_id: Option<Uuid>,
    key_generation: Option<u64>,
    key_epoch: Option<String>,
    origin_policy_id: Option<Uuid>,
    origin_version_id: Option<Uuid>,
    origin_generation: Option<u64>,
    origin_epoch: Option<String>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
struct AttemptUsageKey {
    bucket_start: DateTime<Utc>,
    organization_id: Uuid,
    principal: PrincipalDimensions,
    route_id: Uuid,
    route_grant_identity_id: Option<Uuid>,
    target_id: Uuid,
    deployment_id: Uuid,
    endpoint_id: Uuid,
    endpoint_config_version: i64,
    credential_id: Uuid,
    credential_secret_version: i64,
    credential_state_identity_version: u64,
    origin: &'static str,
    pricing_policy_version_id: Option<Uuid>,
    budgets: BudgetDimensions,
    terminal_class: &'static str,
}

#[derive(Clone, Debug, Default, Serialize)]
struct AttemptUsageDelta {
    attempt_count: u64,
    input_units: u128,
    output_units: u128,
    cached_input_units: u128,
    estimated_cost_nanos: Option<u128>,
    unknown_estimate_count: u64,
    actual_cost_nanos: Option<u128>,
    unknown_cost_count: u64,
    duration_millis: u128,
}

#[derive(Clone, Debug)]
struct UsageBatch {
    sequence: u64,
    digest: [u8; 32],
    facts: UsageFacts,
}

#[derive(Clone, Debug, Serialize)]
enum UsageFacts {
    Logical(Vec<(LogicalUsageKey, LogicalUsageDelta)>),
    Attempts(Vec<(AttemptUsageKey, AttemptUsageDelta)>),
}

impl UsageFacts {
    const fn family(&self) -> &'static str {
        match self {
            Self::Logical(_) => "logical_hourly",
            Self::Attempts(_) => "attempt_hourly",
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Logical(facts) => facts.len(),
            Self::Attempts(facts) => facts.len(),
        }
    }
}

impl UsageAggregator {
    pub(crate) fn new(store: PgStore, config: UsageConfig) -> Arc<Self> {
        let (shutdown, _) = watch::channel(false);
        Arc::new(Self {
            store,
            source_epoch: Uuid::now_v7(),
            config,
            state: Mutex::new(UsageState::default()),
            shutdown,
            task: AsyncMutex::new(None),
        })
    }

    pub(crate) async fn start(self: &Arc<Self>) {
        let mut task = self.task.lock().await;
        if task.is_some() {
            return;
        }
        let aggregator = Arc::clone(self);
        let receiver = self.shutdown.subscribe();
        *task = Some(tokio::spawn(async move {
            aggregator.run(receiver).await;
        }));
    }

    pub(crate) async fn shutdown(&self) {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.lock().await.take() {
            let _ = task.await;
        } else {
            self.flush_all().await;
        }
    }

    pub(crate) fn status(&self) -> UsageStatus {
        let Ok(state) = self.state.lock() else {
            return UsageStatus {
                last_flush_error: Some("usage state lock poisoned".to_owned()),
                ..UsageStatus::default()
            };
        };
        UsageStatus {
            active_logical_keys: state.logical.len(),
            active_attempt_keys: state.attempts.len(),
            pending_batches: state.pending.len(),
            lost_logical_facts: state.lost_logical_facts,
            lost_attempt_facts: state.lost_attempt_facts,
            last_flush_error: state.last_flush_error.clone(),
        }
    }

    pub(crate) async fn flush_now(&self) -> (UsageStatus, UsageStatus) {
        let before = self.status();
        self.flush_all().await;
        (before, self.status())
    }

    pub(crate) fn record_logical(
        &self,
        admission: &AdmissionContext,
        outcome_class: &'static str,
        usage: Option<&ProviderUsage>,
        deployment: Option<&DeploymentSnapshot>,
        duration: Duration,
    ) {
        let (input, output, cached) = usage_dimensions(usage);
        let (cost_nanos, unknown_cost_count) = priced_usage(usage, deployment);
        let key = LogicalUsageKey {
            bucket_start: current_hour(),
            organization_id: admission.organization.id.as_uuid(),
            principal: principal_dimensions(&admission.principal),
            route_id: admission.route.id.as_uuid(),
            route_grant_identity_id: route_grant_identity(admission),
            ingress_protocol_family: admission.route.ingress_protocol_family.as_str(),
            outcome_class,
        };
        let delta = LogicalUsageDelta {
            request_count: 1,
            input_units: input,
            output_units: output,
            cached_input_units: cached,
            cost_nanos,
            unknown_cost_count,
            duration_millis: duration.as_millis(),
        };
        let Ok(mut state) = self.state.lock() else {
            tracing::error!("usage state lock poisoned while recording logical fact");
            return;
        };
        if !state.logical.contains_key(&key)
            && state.logical.len() >= self.config.max_aggregate_keys
            && !seal_logical(&mut state, self.config.max_pending_batches)
        {
            state.lost_logical_facts = state.lost_logical_facts.saturating_add(1);
            return;
        }
        if !merge_logical(state.logical.entry(key).or_default(), &delta) {
            state.lost_logical_facts = state.lost_logical_facts.saturating_add(1);
        }
    }

    pub(crate) fn record_attempt(
        &self,
        admission: &AdmissionContext,
        candidate: &Candidate,
        terminal_class: AttemptTerminalClass,
        estimated_cost_nanos: Option<u128>,
        usage: Option<&ProviderUsage>,
        duration: Duration,
    ) {
        let (input, output, cached) = usage_dimensions(usage);
        let (actual_cost_nanos, unknown_cost_count) =
            priced_usage(usage, Some(&candidate.deployment));
        let terminal_class = terminal_class.as_str();
        let terminal_class = if actual_cost_nanos
            .zip(estimated_cost_nanos)
            .is_some_and(|(actual, estimate)| actual > estimate)
            && terminal_class == "actual"
        {
            "actual_above_estimate"
        } else {
            terminal_class
        };
        let key = AttemptUsageKey {
            bucket_start: current_hour(),
            organization_id: admission.organization.id.as_uuid(),
            principal: principal_dimensions(&admission.principal),
            route_id: admission.route.id.as_uuid(),
            route_grant_identity_id: route_grant_identity(admission),
            target_id: candidate.target.id.as_uuid(),
            deployment_id: candidate.deployment.id.as_uuid(),
            endpoint_id: candidate.deployment.endpoint_id.as_uuid(),
            endpoint_config_version: candidate.deployment.endpoint_config_version,
            credential_id: candidate.deployment.credential_id.as_uuid(),
            credential_secret_version: candidate.deployment.credential_secret_version,
            credential_state_identity_version: candidate
                .deployment
                .credential_state_identity_version,
            origin: origin_str(candidate.deployment.origin),
            pricing_policy_version_id: candidate
                .deployment
                .pricing_policy_version_id
                .map(|id| id.as_uuid()),
            budgets: budget_dimensions(admission, candidate),
            terminal_class,
        };
        let delta = AttemptUsageDelta {
            attempt_count: 1,
            input_units: input,
            output_units: output,
            cached_input_units: cached,
            estimated_cost_nanos: estimated_cost_nanos.filter(|value| *value <= MAX_NUMERIC_38),
            unknown_estimate_count: u64::from(
                estimated_cost_nanos.is_none_or(|value| value > MAX_NUMERIC_38),
            ),
            actual_cost_nanos,
            unknown_cost_count,
            duration_millis: duration.as_millis(),
        };
        let Ok(mut state) = self.state.lock() else {
            tracing::error!("usage state lock poisoned while recording attempt fact");
            return;
        };
        if !state.attempts.contains_key(&key)
            && state.attempts.len() >= self.config.max_aggregate_keys
            && !seal_attempts(&mut state, self.config.max_pending_batches)
        {
            state.lost_attempt_facts = state.lost_attempt_facts.saturating_add(1);
            return;
        }
        if !merge_attempt(state.attempts.entry(key).or_default(), &delta) {
            state.lost_attempt_facts = state.lost_attempt_facts.saturating_add(1);
        }
    }

    async fn run(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(self.config.flush_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => self.flush_once().await,
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        self.flush_all().await;
                        return;
                    }
                }
            }
        }
    }

    async fn flush_all(&self) {
        loop {
            let before = self.status();
            self.flush_once().await;
            let after = self.status();
            if after.pending_batches == 0
                && after.active_logical_keys == 0
                && after.active_attempt_keys == 0
            {
                return;
            }
            if after.pending_batches >= before.pending_batches
                && after.active_logical_keys >= before.active_logical_keys
                && after.active_attempt_keys >= before.active_attempt_keys
            {
                tracing::warn!(
                    pending_batches = after.pending_batches,
                    lost_logical_facts = after.lost_logical_facts,
                    lost_attempt_facts = after.lost_attempt_facts,
                    "usage shutdown flush remains incomplete"
                );
                return;
            }
        }
    }

    async fn flush_once(&self) {
        let batch = {
            let Ok(mut state) = self.state.lock() else {
                tracing::error!("usage state lock poisoned while sealing a flush batch");
                return;
            };
            if state.pending.len() < self.config.max_pending_batches {
                let _ = seal_logical(&mut state, self.config.max_pending_batches);
            }
            if state.pending.len() < self.config.max_pending_batches {
                let _ = seal_attempts(&mut state, self.config.max_pending_batches);
            }
            state.pending.front().cloned()
        };
        let Some(batch) = batch else {
            return;
        };
        match flush_batch(&self.store, self.source_epoch, &batch).await {
            Ok(()) => {
                let Ok(mut state) = self.state.lock() else {
                    return;
                };
                if state
                    .pending
                    .front()
                    .is_some_and(|front| front.sequence == batch.sequence)
                {
                    state.pending.pop_front();
                }
                state.last_flush_error = None;
            }
            Err(error) => {
                let message = error.to_string();
                if let Ok(mut state) = self.state.lock() {
                    state.last_flush_error = Some(message.clone());
                }
                tracing::warn!(%error, sequence=batch.sequence, family=batch.facts.family(), "usage aggregate flush failed");
            }
        }
    }
}

fn seal_logical(state: &mut UsageState, maximum_pending: usize) -> bool {
    if state.logical.is_empty() {
        return true;
    }
    if state.pending.len() >= maximum_pending {
        return false;
    }
    let facts = UsageFacts::Logical(state.logical.drain().collect());
    push_batch(state, facts);
    true
}

fn seal_attempts(state: &mut UsageState, maximum_pending: usize) -> bool {
    if state.attempts.is_empty() {
        return true;
    }
    if state.pending.len() >= maximum_pending {
        return false;
    }
    let facts = UsageFacts::Attempts(state.attempts.drain().collect());
    push_batch(state, facts);
    true
}

fn push_batch(state: &mut UsageState, facts: UsageFacts) {
    let sequence = state.next_batch_sequence;
    state.next_batch_sequence = state.next_batch_sequence.saturating_add(1);
    let serialized = serde_json::to_vec(&facts).expect("usage facts are serializable");
    let digest = Sha256::digest(serialized).into();
    state.pending.push_back(UsageBatch {
        sequence,
        digest,
        facts,
    });
}

fn merge_logical(target: &mut LogicalUsageDelta, delta: &LogicalUsageDelta) -> bool {
    add_u64(&mut target.request_count, delta.request_count)
        && add_numeric(&mut target.input_units, delta.input_units)
        && add_numeric(&mut target.output_units, delta.output_units)
        && add_numeric(&mut target.cached_input_units, delta.cached_input_units)
        && add_optional_numeric(&mut target.cost_nanos, delta.cost_nanos)
        && add_u64(&mut target.unknown_cost_count, delta.unknown_cost_count)
        && add_numeric(&mut target.duration_millis, delta.duration_millis)
}

fn merge_attempt(target: &mut AttemptUsageDelta, delta: &AttemptUsageDelta) -> bool {
    add_u64(&mut target.attempt_count, delta.attempt_count)
        && add_numeric(&mut target.input_units, delta.input_units)
        && add_numeric(&mut target.output_units, delta.output_units)
        && add_numeric(&mut target.cached_input_units, delta.cached_input_units)
        && add_optional_numeric(&mut target.estimated_cost_nanos, delta.estimated_cost_nanos)
        && add_u64(
            &mut target.unknown_estimate_count,
            delta.unknown_estimate_count,
        )
        && add_optional_numeric(&mut target.actual_cost_nanos, delta.actual_cost_nanos)
        && add_u64(&mut target.unknown_cost_count, delta.unknown_cost_count)
        && add_numeric(&mut target.duration_millis, delta.duration_millis)
}

fn add_u64(target: &mut u64, value: u64) -> bool {
    if let Some(result) = target.checked_add(value) {
        *target = result;
        true
    } else {
        false
    }
}

fn add_numeric(target: &mut u128, value: u128) -> bool {
    if let Some(result) = target
        .checked_add(value)
        .filter(|value| *value <= MAX_NUMERIC_38)
    {
        *target = result;
        true
    } else {
        false
    }
}

fn add_optional_numeric(target: &mut Option<u128>, value: Option<u128>) -> bool {
    let Some(value) = value else {
        return true;
    };
    match target {
        Some(target) => add_numeric(target, value),
        None if value <= MAX_NUMERIC_38 => {
            *target = Some(value);
            true
        }
        None => false,
    }
}

fn current_hour() -> DateTime<Utc> {
    let now = Utc::now();
    now.with_minute(0)
        .and_then(|value| value.with_second(0))
        .and_then(|value| value.with_nanosecond(0))
        .expect("UTC timestamps support an hourly bucket")
}

fn principal_dimensions(principal: &GatewayPrincipal) -> PrincipalDimensions {
    match principal {
        GatewayPrincipal::GatewayKey { key_id, .. } => PrincipalDimensions {
            principal_kind: "gateway_api_key",
            gateway_api_key_id: Some(key_id.as_uuid()),
            user_id: None,
            membership_id: None,
        },
        GatewayPrincipal::LocalUser {
            user_id,
            membership,
            ..
        } => PrincipalDimensions {
            principal_kind: "external_jwt",
            gateway_api_key_id: None,
            user_id: Some(user_id.as_uuid()),
            membership_id: Some(membership.membership_id),
        },
    }
}

fn budget_dimensions(admission: &AdmissionContext, candidate: &Candidate) -> BudgetDimensions {
    let GatewayPrincipal::GatewayKey { verifier, .. } = &admission.principal else {
        return BudgetDimensions {
            key_policy_id: None,
            key_version_id: None,
            key_generation: None,
            key_epoch: None,
            origin_policy_id: None,
            origin_version_id: None,
            origin_generation: None,
            origin_epoch: None,
        };
    };
    let key_policy = admission
        .generation
        .snapshot
        .catalog
        .key_budget_policies
        .get(&verifier.budget_policy_id);
    let key_version = key_policy.and_then(|policy| policy.active_version.as_ref());
    let origin_policy = admission
        .organization
        .origin_budgets
        .get(&candidate.deployment.origin);
    let origin_version = origin_policy.and_then(|policy| policy.active_version.as_ref());
    BudgetDimensions {
        key_policy_id: Some(verifier.budget_policy_id.as_uuid()),
        key_version_id: key_version.map(|version| version.id.as_uuid()),
        key_generation: key_version.map(|version| version.generation),
        key_epoch: key_version.map(|version| version.epoch.clone()),
        origin_policy_id: origin_policy.map(|policy| policy.id.as_uuid()),
        origin_version_id: origin_version.map(|version| version.id.as_uuid()),
        origin_generation: origin_version.map(|version| version.generation),
        origin_epoch: origin_version.map(|version| version.epoch.clone()),
    }
}

fn route_grant_identity(admission: &AdmissionContext) -> Option<Uuid> {
    admission
        .organization
        .system_route_grants
        .get(&admission.route.id)
        .map(|grant| grant.identity_id)
}

fn usage_dimensions(usage: Option<&ProviderUsage>) -> (u128, u128, u128) {
    let Some(usage) = usage else {
        return (0, 0, 0);
    };
    let get = |primary: &str, alternate: &str| {
        u128::from(
            usage
                .dimensions
                .get(primary)
                .or_else(|| usage.dimensions.get(alternate))
                .copied()
                .unwrap_or(0),
        )
    };
    (
        get("input_tokens", "input_units"),
        get("output_tokens", "output_units"),
        get("cached_input_tokens", "cached_input_units"),
    )
}

fn priced_usage(
    usage: Option<&ProviderUsage>,
    deployment: Option<&DeploymentSnapshot>,
) -> (Option<u128>, u64) {
    let Some(usage) = usage.filter(|usage| usage.completeness != UsageCompleteness::Absent) else {
        return (None, 1);
    };
    let outcome = deployment.and_then(|deployment| usage.price(deployment));
    match outcome {
        Some(PricingOutcome::Known { cost_nanos }) if cost_nanos <= MAX_NUMERIC_38 => {
            (Some(cost_nanos), 0)
        }
        Some(PricingOutcome::Known { .. })
        | Some(PricingOutcome::Unknown { .. })
        | Some(PricingOutcome::Overflow)
        | None => (None, 1),
    }
}

const fn origin_str(origin: AccountingOrigin) -> &'static str {
    match origin {
        AccountingOrigin::SystemProvided => "system_provided",
        AccountingOrigin::OrganizationByok => "organization_byok",
    }
}

async fn flush_batch(
    store: &PgStore,
    source_epoch: Uuid,
    batch: &UsageBatch,
) -> Result<(), sqlx::Error> {
    let mut transaction = store.pool().begin().await?;
    let inserted = sqlx::query_scalar::<_, i32>(
        "INSERT INTO aggregate_flush_receipts(
             id,source_epoch,batch_sequence,fact_family,batch_digest,fact_count
         ) VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (source_epoch,batch_sequence,fact_family) DO NOTHING
         RETURNING 1",
    )
    .bind(Uuid::now_v7())
    .bind(source_epoch)
    .bind(i64::try_from(batch.sequence).unwrap_or(i64::MAX))
    .bind(batch.facts.family())
    .bind(batch.digest.to_vec())
    .bind(i32::try_from(batch.facts.len()).unwrap_or(i32::MAX))
    .fetch_optional(&mut *transaction)
    .await?;
    if inserted.is_none() {
        let existing = sqlx::query(
            "SELECT batch_digest,fact_count FROM aggregate_flush_receipts
             WHERE source_epoch=$1 AND batch_sequence=$2 AND fact_family=$3",
        )
        .bind(source_epoch)
        .bind(i64::try_from(batch.sequence).unwrap_or(i64::MAX))
        .bind(batch.facts.family())
        .fetch_one(&mut *transaction)
        .await?;
        let digest: Vec<u8> = existing.try_get("batch_digest")?;
        let count: i32 = existing.try_get("fact_count")?;
        if !bool::from(subtle::ConstantTimeEq::ct_eq(
            digest.as_slice(),
            batch.digest.as_slice(),
        )) || count != i32::try_from(batch.facts.len()).unwrap_or(i32::MAX)
        {
            return Err(sqlx::Error::Protocol(
                "aggregate receipt identity was reused with different facts".to_owned(),
            ));
        }
        transaction.rollback().await?;
        return Ok(());
    }
    match &batch.facts {
        UsageFacts::Logical(facts) => {
            for (key, delta) in facts {
                upsert_logical(&mut transaction, key, delta).await?;
            }
        }
        UsageFacts::Attempts(facts) => {
            for (key, delta) in facts {
                upsert_attempt(&mut transaction, key, delta).await?;
            }
        }
    }
    transaction.commit().await
}

async fn upsert_logical(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    key: &LogicalUsageKey,
    delta: &LogicalUsageDelta,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO logical_usage_hourly(
             bucket_start,organization_id,principal_kind,gateway_api_key_id,user_id,membership_id,
             route_id,route_grant_identity_id,ingress_protocol_family,outcome_class,request_count,
             input_units,output_units,cached_input_units,cost_nanos,unknown_cost_count,duration_millis
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::numeric,$13::numeric,$14::numeric,
                   $15::numeric,$16,$17::numeric)
         ON CONFLICT ON CONSTRAINT logical_usage_hourly_identity_unique DO UPDATE SET
             request_count=(logical_usage_hourly.request_count::numeric+EXCLUDED.request_count)::bigint,
             input_units=logical_usage_hourly.input_units+EXCLUDED.input_units,
             output_units=logical_usage_hourly.output_units+EXCLUDED.output_units,
             cached_input_units=logical_usage_hourly.cached_input_units+EXCLUDED.cached_input_units,
             cost_nanos=CASE
                 WHEN logical_usage_hourly.cost_nanos IS NULL AND EXCLUDED.cost_nanos IS NULL THEN NULL
                 ELSE COALESCE(logical_usage_hourly.cost_nanos,0)+COALESCE(EXCLUDED.cost_nanos,0)
             END,
             unknown_cost_count=(logical_usage_hourly.unknown_cost_count::numeric+EXCLUDED.unknown_cost_count)::bigint,
             duration_millis=logical_usage_hourly.duration_millis+EXCLUDED.duration_millis",
    )
    .bind(key.bucket_start)
    .bind(key.organization_id)
    .bind(key.principal.principal_kind)
    .bind(key.principal.gateway_api_key_id)
    .bind(key.principal.user_id)
    .bind(key.principal.membership_id)
    .bind(key.route_id)
    .bind(key.route_grant_identity_id)
    .bind(key.ingress_protocol_family)
    .bind(key.outcome_class)
    .bind(i64::try_from(delta.request_count).unwrap_or(i64::MAX))
    .bind(delta.input_units.to_string())
    .bind(delta.output_units.to_string())
    .bind(delta.cached_input_units.to_string())
    .bind(delta.cost_nanos.map(|value| value.to_string()))
    .bind(i64::try_from(delta.unknown_cost_count).unwrap_or(i64::MAX))
    .bind(delta.duration_millis.to_string())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn upsert_attempt(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    key: &AttemptUsageKey,
    delta: &AttemptUsageDelta,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO attempt_usage_hourly(
             bucket_start,organization_id,principal_kind,gateway_api_key_id,user_id,membership_id,
             route_id,route_grant_identity_id,target_id,deployment_id,endpoint_id,
             endpoint_config_version,credential_id,credential_secret_version,
             credential_state_identity_version,origin,pricing_policy_version_id,key_budget_policy_id,
             key_budget_version_id,key_budget_generation,key_budget_epoch,origin_budget_policy_id,
             origin_budget_version_id,origin_budget_generation,origin_budget_epoch,terminal_class,
             attempt_count,input_units,output_units,cached_input_units,estimated_cost_nanos,
             unknown_estimate_count,actual_cost_nanos,unknown_cost_count,duration_millis
         ) VALUES (
             $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
             $21,$22,$23,$24,$25,$26,$27,$28::numeric,$29::numeric,$30::numeric,$31::numeric,
             $32,$33::numeric,$34,$35::numeric
         )
         ON CONFLICT ON CONSTRAINT attempt_usage_hourly_identity_unique DO UPDATE SET
             attempt_count=(attempt_usage_hourly.attempt_count::numeric+EXCLUDED.attempt_count)::bigint,
             input_units=attempt_usage_hourly.input_units+EXCLUDED.input_units,
             output_units=attempt_usage_hourly.output_units+EXCLUDED.output_units,
             cached_input_units=attempt_usage_hourly.cached_input_units+EXCLUDED.cached_input_units,
             estimated_cost_nanos=CASE
                 WHEN attempt_usage_hourly.estimated_cost_nanos IS NULL
                      AND EXCLUDED.estimated_cost_nanos IS NULL THEN NULL
                 ELSE COALESCE(attempt_usage_hourly.estimated_cost_nanos,0)
                      +COALESCE(EXCLUDED.estimated_cost_nanos,0)
             END,
             unknown_estimate_count=(attempt_usage_hourly.unknown_estimate_count::numeric
                 +EXCLUDED.unknown_estimate_count)::bigint,
             actual_cost_nanos=CASE
                 WHEN attempt_usage_hourly.actual_cost_nanos IS NULL AND EXCLUDED.actual_cost_nanos IS NULL THEN NULL
                 ELSE COALESCE(attempt_usage_hourly.actual_cost_nanos,0)+COALESCE(EXCLUDED.actual_cost_nanos,0)
             END,
             unknown_cost_count=(attempt_usage_hourly.unknown_cost_count::numeric+EXCLUDED.unknown_cost_count)::bigint,
             duration_millis=attempt_usage_hourly.duration_millis+EXCLUDED.duration_millis",
    )
    .bind(key.bucket_start)
    .bind(key.organization_id)
    .bind(key.principal.principal_kind)
    .bind(key.principal.gateway_api_key_id)
    .bind(key.principal.user_id)
    .bind(key.principal.membership_id)
    .bind(key.route_id)
    .bind(key.route_grant_identity_id)
    .bind(key.target_id)
    .bind(key.deployment_id)
    .bind(key.endpoint_id)
    .bind(key.endpoint_config_version)
    .bind(key.credential_id)
    .bind(key.credential_secret_version)
    .bind(i64::try_from(key.credential_state_identity_version).unwrap_or(i64::MAX))
    .bind(key.origin)
    .bind(key.pricing_policy_version_id)
    .bind(key.budgets.key_policy_id)
    .bind(key.budgets.key_version_id)
    .bind(key.budgets.key_generation.map(|value| i64::try_from(value).unwrap_or(i64::MAX)))
    .bind(key.budgets.key_epoch.as_deref())
    .bind(key.budgets.origin_policy_id)
    .bind(key.budgets.origin_version_id)
    .bind(key.budgets.origin_generation.map(|value| i64::try_from(value).unwrap_or(i64::MAX)))
    .bind(key.budgets.origin_epoch.as_deref())
    .bind(key.terminal_class)
    .bind(i64::try_from(delta.attempt_count).unwrap_or(i64::MAX))
    .bind(delta.input_units.to_string())
    .bind(delta.output_units.to_string())
    .bind(delta.cached_input_units.to_string())
    .bind(delta.estimated_cost_nanos.map(|value| value.to_string()))
    .bind(i64::try_from(delta.unknown_estimate_count).unwrap_or(i64::MAX))
    .bind(delta.actual_cost_nanos.map(|value| value.to_string()))
    .bind(i64::try_from(delta.unknown_cost_count).unwrap_or(i64::MAX))
    .bind(delta.duration_millis.to_string())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::postgres::test_support::{
        connect_from_environment, valid_reliability_components,
    };

    #[allow(clippy::struct_field_names)]
    struct UsageFixture {
        organization_id: Uuid,
        user_id: Uuid,
        membership_id: Uuid,
        route_id: Uuid,
        route_grant_identity_id: Uuid,
        target_id: Uuid,
        deployment_id: Uuid,
        endpoint_id: Uuid,
        credential_id: Uuid,
    }

    async fn insert_usage_fixture(store: &PgStore) -> UsageFixture {
        let fixture = UsageFixture {
            organization_id: Uuid::now_v7(),
            user_id: Uuid::now_v7(),
            membership_id: Uuid::now_v7(),
            route_id: Uuid::now_v7(),
            route_grant_identity_id: Uuid::now_v7(),
            target_id: Uuid::now_v7(),
            deployment_id: Uuid::now_v7(),
            endpoint_id: Uuid::now_v7(),
            credential_id: Uuid::now_v7(),
        };
        let network_id = Uuid::now_v7();
        let credential_version_id = Uuid::now_v7();
        let reliability_id = Uuid::now_v7();
        let mut transaction = store.begin().await.unwrap();
        sqlx::query("SET CONSTRAINTS ALL DEFERRED")
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO organizations(id,kind,status,name,created_by_principal,etag_token)
             VALUES ($1,'ordinary','active',$2,'{}',$3)",
        )
        .bind(fixture.organization_id)
        .bind(format!("usage-fixture-{}", fixture.organization_id))
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO organization_api_key_policies(organization_id,policy,etag_token)
             VALUES ($1,$2,$3)",
        )
        .bind(fixture.organization_id)
        .bind(crate::application::default_organization_api_key_policy())
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO users(id,kind,status,display_name,created_by_principal,etag_token)
             VALUES ($1,'human','active','Usage fixture user','{}',$2)",
        )
        .bind(fixture.user_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO memberships(id,organization_id,user_id,role,status,
                created_by_principal,etag_token)
             VALUES ($1,$2,$3,'owner','active','{}',$4)",
        )
        .bind(fixture.membership_id)
        .bind(fixture.organization_id)
        .bind(fixture.user_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO egress_network_policies(id,name,dns_policy,address_policy,tls_policy,
                redirect_policy,connection_policy,body_policy,status,created_by_principal,etag_token)
             VALUES ($1,$2,'{}','{}','{}','{}','{}','{}','active','{}',$3)",
        )
        .bind(network_id)
        .bind(format!("usage-network-{network_id}"))
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO upstream_endpoints(id,name,adapter_kind,base_url,network_policy_id,
                status,created_by_principal,etag_token)
             VALUES ($1,$2,'openai_api','https://usage.example/v1/',$3,'active','{}',$4)",
        )
        .bind(fixture.endpoint_id)
        .bind(format!("usage-endpoint-{}", fixture.endpoint_id))
        .bind(network_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO upstream_credentials(id,resource_scope_kind,name,credential_kind,
                secret_source_kind,source_configuration,injection_kind,sharing_policy,
                administrative_status,authentication_status,current_secret_version,
                created_by_principal,etag_token)
             VALUES ($1,'deployment',$2,'static_api_key','environment_reference',
                '{\"environment_variable\":\"OWLRORA_TEST_UPSTREAM_KEY\"}','bearer',
                'exclusive','active','ready',1,'{}',$3)",
        )
        .bind(fixture.credential_id)
        .bind(format!("usage-credential-{}", fixture.credential_id))
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO upstream_credential_secret_versions(id,credential_id,version,
                credential_state_identity_version,source_configuration,safe_fingerprint,state)
             VALUES ($1,$2,1,1,
                '{\"environment_variable\":\"OWLRORA_TEST_UPSTREAM_KEY\"}',$3,'current')",
        )
        .bind(credential_version_id)
        .bind(fixture.credential_id)
        .bind(vec![11_u8; 32])
        .execute(&mut *transaction)
        .await
        .unwrap();
        let reliability = valid_reliability_components();
        sqlx::query(
            "INSERT INTO reliability_policies(id,name,attempt_policy,deadline_policy,retry_policy,
                failover_policy,commitment_policy,health_policy,circuit_policy,probe_policy,
                status,created_by_principal,etag_token)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'active','{}',$11)",
        )
        .bind(reliability_id)
        .bind(format!("usage-reliability-{reliability_id}"))
        .bind(&reliability[0])
        .bind(&reliability[1])
        .bind(&reliability[2])
        .bind(&reliability[3])
        .bind(&reliability[4])
        .bind(&reliability[5])
        .bind(&reliability[6])
        .bind(&reliability[7])
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO model_deployments(id,resource_scope_kind,name,endpoint_id,credential_id,
                transport_kind,upstream_model_id,capability_set,context_limits,
                state_isolation_profile,unpriced,status,created_by_principal,etag_token)
             VALUES ($1,'deployment',$2,$3,$4,'openai_responses_http','usage-model',
                '[]','{}','{}',true,'active','{}',$5)",
        )
        .bind(fixture.deployment_id)
        .bind(format!("usage-deployment-{}", fixture.deployment_id))
        .bind(fixture.endpoint_id)
        .bind(fixture.credential_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO model_routes(id,resource_scope_kind,model_key,ingress_protocol_family,
                required_base_capabilities,selection_policy,reliability_policy_id,request_policy,
                status,created_by_principal,etag_token)
             VALUES ($1,'deployment',$2,'openai_responses','[]','{}',$3,'{}','active','{}',$4)",
        )
        .bind(fixture.route_id)
        .bind(format!("usage-model-{}", fixture.route_id))
        .bind(reliability_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO route_targets(id,route_id,deployment_id,affinity_identity,priority,
                weight,enabled,etag_token) VALUES ($1,$2,$3,$4,0,256,true,$5)",
        )
        .bind(fixture.target_id)
        .bind(fixture.route_id)
        .bind(fixture.deployment_id)
        .bind(Uuid::new_v4().as_bytes().to_vec())
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO organization_route_grant_identities(
                id,organization_id,route_id,created_by_principal
             ) VALUES ($1,$2,$3,'{}')",
        )
        .bind(fixture.route_grant_identity_id)
        .bind(fixture.organization_id)
        .bind(fixture.route_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO organization_route_grants(organization_id,route_id,ceilings,status,
                created_by_principal,etag_token) VALUES ($1,$2,'{}','active','{}',$3)",
        )
        .bind(fixture.organization_id)
        .bind(fixture.route_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
            .execute(&mut *transaction)
            .await
            .unwrap();
        transaction.commit().await.unwrap();
        fixture
    }

    fn external_principal(fixture: &UsageFixture) -> PrincipalDimensions {
        PrincipalDimensions {
            principal_kind: "external_jwt",
            gateway_api_key_id: None,
            user_id: Some(fixture.user_id),
            membership_id: Some(fixture.membership_id),
        }
    }

    #[test]
    fn bounded_numeric_merge_reports_loss_without_wrapping() {
        let mut value = MAX_NUMERIC_38;
        assert!(!add_numeric(&mut value, 1));
        assert_eq!(value, MAX_NUMERIC_38);
    }

    #[test]
    fn batches_have_monotonic_identity_and_stable_digest() {
        let mut state = UsageState::default();
        let key = LogicalUsageKey {
            bucket_start: current_hour(),
            organization_id: Uuid::nil(),
            principal: PrincipalDimensions {
                principal_kind: "gateway_api_key",
                gateway_api_key_id: Some(Uuid::nil()),
                user_id: None,
                membership_id: None,
            },
            route_id: Uuid::nil(),
            route_grant_identity_id: None,
            ingress_protocol_family: "openai_responses",
            outcome_class: "success",
        };
        state.logical.insert(
            key,
            LogicalUsageDelta {
                request_count: 1,
                ..LogicalUsageDelta::default()
            },
        );
        assert!(seal_logical(&mut state, 2));
        assert_eq!(state.pending[0].sequence, 0);
        assert_eq!(state.pending[0].facts.len(), 1);
        assert_ne!(state.pending[0].digest, [0; 32]);
    }

    fn test_batch(sequence: u64, facts: UsageFacts) -> UsageBatch {
        let digest = Sha256::digest(serde_json::to_vec(&facts).unwrap()).into();
        UsageBatch {
            sequence,
            digest,
            facts,
        }
    }

    #[tokio::test]
    async fn postgres_flush_is_atomic_idempotent_and_rejects_identity_reuse() {
        let Some(store) = connect_from_environment().await else {
            return;
        };
        let fixture = insert_usage_fixture(&store).await;
        let bucket_start = current_hour();
        let principal = external_principal(&fixture);
        let logical_key = LogicalUsageKey {
            bucket_start,
            organization_id: fixture.organization_id,
            principal: principal.clone(),
            route_id: fixture.route_id,
            route_grant_identity_id: Some(fixture.route_grant_identity_id),
            ingress_protocol_family: "openai_responses",
            outcome_class: "success",
        };
        let logical_delta = LogicalUsageDelta {
            request_count: 2,
            input_units: 11,
            output_units: 7,
            cached_input_units: 3,
            cost_nanos: None,
            unknown_cost_count: 2,
            duration_millis: 19,
        };
        let logical_batch = test_batch(
            17,
            UsageFacts::Logical(vec![(logical_key.clone(), logical_delta)]),
        );
        let attempt_key = AttemptUsageKey {
            bucket_start,
            organization_id: fixture.organization_id,
            principal,
            route_id: fixture.route_id,
            route_grant_identity_id: Some(fixture.route_grant_identity_id),
            target_id: fixture.target_id,
            deployment_id: fixture.deployment_id,
            endpoint_id: fixture.endpoint_id,
            endpoint_config_version: 1,
            credential_id: fixture.credential_id,
            credential_secret_version: 1,
            credential_state_identity_version: 1,
            origin: "system_provided",
            pricing_policy_version_id: None,
            budgets: BudgetDimensions {
                key_policy_id: None,
                key_version_id: None,
                key_generation: None,
                key_epoch: None,
                origin_policy_id: None,
                origin_version_id: None,
                origin_generation: None,
                origin_epoch: None,
            },
            terminal_class: "unknown_or_ambiguous",
        };
        let attempt_batch = test_batch(
            18,
            UsageFacts::Attempts(vec![(
                attempt_key.clone(),
                AttemptUsageDelta {
                    attempt_count: 1,
                    input_units: 11,
                    output_units: 0,
                    cached_input_units: 3,
                    estimated_cost_nanos: Some(23),
                    unknown_estimate_count: 0,
                    actual_cost_nanos: None,
                    unknown_cost_count: 1,
                    duration_millis: 13,
                },
            )]),
        );
        let unknown_attempt_batch = test_batch(
            19,
            UsageFacts::Attempts(vec![(
                attempt_key,
                AttemptUsageDelta {
                    attempt_count: 1,
                    input_units: 0,
                    output_units: 0,
                    cached_input_units: 0,
                    estimated_cost_nanos: None,
                    unknown_estimate_count: 1,
                    actual_cost_nanos: None,
                    unknown_cost_count: 1,
                    duration_millis: 5,
                },
            )]),
        );
        let source_epoch = Uuid::now_v7();

        sqlx::query(
            "DELETE FROM organization_route_grants
             WHERE organization_id=$1 AND route_id=$2",
        )
        .bind(fixture.organization_id)
        .bind(fixture.route_id)
        .execute(store.pool())
        .await
        .unwrap();

        flush_batch(&store, source_epoch, &logical_batch)
            .await
            .unwrap();
        flush_batch(&store, source_epoch, &logical_batch)
            .await
            .unwrap();
        flush_batch(&store, source_epoch, &attempt_batch)
            .await
            .unwrap();
        flush_batch(&store, source_epoch, &attempt_batch)
            .await
            .unwrap();
        flush_batch(&store, source_epoch, &unknown_attempt_batch)
            .await
            .unwrap();
        flush_batch(&store, source_epoch, &unknown_attempt_batch)
            .await
            .unwrap();

        let logical = sqlx::query(
            "SELECT request_count,input_units::text,output_units::text,
                    cached_input_units::text,cost_nanos::text,unknown_cost_count,
                    duration_millis::text
             FROM logical_usage_hourly
             WHERE organization_id=$1 AND route_id=$2 AND bucket_start=$3",
        )
        .bind(fixture.organization_id)
        .bind(fixture.route_id)
        .bind(bucket_start)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(logical.try_get::<i64, _>("request_count").unwrap(), 2);
        assert_eq!(logical.try_get::<String, _>("input_units").unwrap(), "11");
        assert_eq!(logical.try_get::<String, _>("output_units").unwrap(), "7");
        assert_eq!(
            logical.try_get::<String, _>("cached_input_units").unwrap(),
            "3"
        );
        assert!(
            logical
                .try_get::<Option<String>, _>("cost_nanos")
                .unwrap()
                .is_none()
        );
        assert_eq!(logical.try_get::<i64, _>("unknown_cost_count").unwrap(), 2);
        assert_eq!(
            logical.try_get::<String, _>("duration_millis").unwrap(),
            "19"
        );

        let attempt = sqlx::query(
            "SELECT attempt_count,estimated_cost_nanos::text,unknown_estimate_count,
                    actual_cost_nanos::text,unknown_cost_count,duration_millis::text
             FROM attempt_usage_hourly
             WHERE organization_id=$1 AND target_id=$2 AND bucket_start=$3",
        )
        .bind(fixture.organization_id)
        .bind(fixture.target_id)
        .bind(bucket_start)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(attempt.try_get::<i64, _>("attempt_count").unwrap(), 2);
        assert_eq!(
            attempt
                .try_get::<String, _>("estimated_cost_nanos")
                .unwrap(),
            "23"
        );
        assert_eq!(
            attempt.try_get::<i64, _>("unknown_estimate_count").unwrap(),
            1
        );
        assert!(
            attempt
                .try_get::<Option<String>, _>("actual_cost_nanos")
                .unwrap()
                .is_none()
        );
        assert_eq!(attempt.try_get::<i64, _>("unknown_cost_count").unwrap(), 2);
        assert_eq!(
            attempt.try_get::<String, _>("duration_millis").unwrap(),
            "18"
        );
        let receipts = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM aggregate_flush_receipts WHERE source_epoch=$1",
        )
        .bind(source_epoch)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(receipts, 3);

        let conflicting = test_batch(
            logical_batch.sequence,
            UsageFacts::Logical(vec![(
                logical_key,
                LogicalUsageDelta {
                    request_count: 3,
                    ..LogicalUsageDelta::default()
                },
            )]),
        );
        let error = flush_batch(&store, source_epoch, &conflicting)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("reused with different facts"));
        let request_count = sqlx::query_scalar::<_, i64>(
            "SELECT request_count FROM logical_usage_hourly
             WHERE organization_id=$1 AND route_id=$2 AND bucket_start=$3",
        )
        .bind(fixture.organization_id)
        .bind(fixture.route_id)
        .bind(bucket_start)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(request_count, 2);
    }
}
