use std::{
    collections::{BTreeSet, HashMap},
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, jwk::JwkSet};
use owlrora_key_provider::SecretPlaintext;
use reqwest::header::HeaderValue;
use tower::{Layer, Service};

use crate::adapters::provider::auth::ProviderAuthenticator;
use crate::domain::{
    AccountingOrigin, BrowserLoginProfile, BudgetAllowancePolicy, BudgetEstimatePolicy,
    BudgetFailurePolicy, BudgetMode, BudgetPolicyId, BudgetPolicyVersionId, BudgetRecoveryPolicy,
    Capability, CapabilityClaimPolicy, CatalogScopeKind, ClaimMapping, CredentialId,
    CredentialKind, CredentialSecretVersionId, DeploymentId, EndpointAdapterKind, EndpointId,
    GatewayKeyId, IngressProtocolFamily, IssuerId, JwksSource, JwtRouteCeiling, KeyCachePolicy,
    KeyId, LlmFeatureCapability, LlmScopeCeiling, LlmScopeSet, ManagementOrganizationCeiling,
    ManagementScopeSet, NetworkPolicyId, OrganizationId, OrganizationRole, OrganizationSelector,
    PolicyActivationId, PolicyId, PolicyKind, PricingPolicyId, PricingPolicyVersionId,
    PricingRates, PricingRoundingMode, PricingRoundingPolicy, RateGrantPolicy, RatePolicyId,
    RatePolicyVersionId, ReliabilityPolicyId, ResourceScope, RouteId, RouteRequestPolicy,
    RouteSelectionPolicy, SystemRouteGrantCeilings, TargetId, TargetNarrowingConstraints,
    TargetTimeoutOverrides, TransportKind, UserId,
};

#[derive(Clone, Debug)]
pub struct RuntimeGeneration {
    pub snapshot: Arc<RuntimeSnapshot>,
    pub credential_clients: Arc<CredentialClientRegistry>,
}

#[derive(Clone, Debug)]
pub struct RuntimeSnapshot {
    pub revision: i64,
    pub security_revision: i64,
    pub built_at: DateTime<Utc>,
    pub compatibility_registry_version: u32,
    pub gateway_policy_ceilings: GatewayPolicyCeilingsSnapshot,
    pub identity: IdentitySnapshot,
    pub gateway_keys: HashMap<String, GatewayKeyVerifier>,
    pub organizations: HashMap<OrganizationId, OrganizationSnapshot>,
    pub policy_activations: HashMap<PolicyActivationKey, PolicyActivationSnapshot>,
    pub catalog: CatalogSnapshot,
}

#[derive(Clone, Debug, Default)]
pub struct GatewayPolicyCeilingsSnapshot {
    pub key_budget_max_limit_cost_nanos: u128,
    pub byok_origin_budget_max_limit_cost_nanos: u128,
    pub max_recovery_incident_cap_nanos: u128,
    pub max_recovery_epoch_cap_nanos: u128,
    pub max_requests_per_minute: u32,
    pub max_input_units_per_minute: u64,
    pub max_concurrency: u32,
    pub max_stream_seconds: u32,
    pub allowed_budget_modes: BTreeSet<BudgetMode>,
    pub allowed_rate_grant_modes: BTreeSet<String>,
    pub allowed_concurrency_modes: BTreeSet<String>,
}

#[derive(Clone, Debug, Default)]
pub struct IdentitySnapshot {
    pub active_users: HashMap<UserId, bool>,
    pub active_organizations: HashMap<OrganizationId, bool>,
    pub memberships: HashMap<(OrganizationId, UserId), MembershipSnapshot>,
    pub management_keys: HashMap<String, ManagementKeyVerifier>,
    pub management_keys_by_id: HashMap<KeyId, ManagementKeyVerifier>,
    pub system_administrator_users: HashMap<UserId, bool>,
    pub system_administrator_keys: HashMap<KeyId, bool>,
    pub external_issuers_by_issuer: HashMap<String, ExternalIssuerSnapshot>,
    pub external_issuers_by_id: HashMap<IssuerId, ExternalIssuerSnapshot>,
    pub external_bindings: HashMap<(IssuerId, String), UserId>,
}

#[derive(Clone, Debug)]
pub struct MembershipSnapshot {
    pub membership_id: uuid::Uuid,
    pub role: OrganizationRole,
    pub llm_scopes: LlmScopeCeiling,
    pub llm_capabilities: BTreeSet<LlmFeatureCapability>,
    pub llm_routes: JwtRouteCeiling,
}

#[derive(Clone, Debug)]
pub struct GatewayKeyVerifier {
    pub key_id: GatewayKeyId,
    pub organization_id: OrganizationId,
    pub scopes: Option<LlmScopeSet>,
    pub capabilities: BTreeSet<LlmFeatureCapability>,
    pub route_ids: BTreeSet<RouteId>,
    pub budget_policy_id: BudgetPolicyId,
    pub rate_policy_id: Option<RatePolicyId>,
    pub current_digest: [u8; 32],
    pub overlap_digest: Option<[u8; 32]>,
    pub overlap_until: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub active: bool,
}

#[derive(Clone, Debug)]
pub struct SystemRouteGrantSnapshot {
    pub identity_id: uuid::Uuid,
    pub ceilings: SystemRouteGrantCeilings,
}

#[derive(Clone, Debug)]
pub struct OrganizationSnapshot {
    pub id: OrganizationId,
    pub active: bool,
    pub pending_tightening_deadline: Option<DateTime<Utc>>,
    pub api_key_policy: serde_json::Value,
    pub system_route_grants: HashMap<RouteId, SystemRouteGrantSnapshot>,
    pub endpoint_grants: BTreeSet<EndpointId>,
    pub deployment_grants: BTreeSet<DeploymentId>,
    pub reliability_policy_grants: BTreeSet<ReliabilityPolicyId>,
    pub origin_budgets: HashMap<AccountingOrigin, BudgetPolicySnapshot>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PolicyActivationKey {
    pub kind: PolicyKind,
    pub policy_id: uuid::Uuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyActivationState {
    Desired,
    CoordinatorStaged,
    CoordinatorArmed,
    Active,
}

#[derive(Clone, Debug)]
pub struct PolicyActivationSnapshot {
    pub id: PolicyActivationId,
    pub organization_id: OrganizationId,
    pub key: PolicyActivationKey,
    pub desired_epoch: String,
    pub desired_version_id: uuid::Uuid,
    pub desired_generation: u64,
    pub active_epoch: Option<String>,
    pub active_version_id: Option<uuid::Uuid>,
    pub active_generation: Option<u64>,
    pub prior_epoch: Option<String>,
    pub prior_version_id: Option<uuid::Uuid>,
    pub prior_generation: Option<u64>,
    pub candidate_fence: uuid::Uuid,
    pub state: PolicyActivationState,
    pub tightening_deadline: Option<DateTime<Utc>>,
    pub prior_cutoff_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct BudgetPolicySnapshot {
    pub id: BudgetPolicyId,
    pub active: bool,
    pub active_version: Option<BudgetPolicyVersionSnapshot>,
}

#[derive(Clone, Debug)]
pub struct BudgetPolicyVersionSnapshot {
    pub id: BudgetPolicyVersionId,
    pub generation: u64,
    pub recovery_generation: u64,
    pub epoch: String,
    pub mode: BudgetMode,
    pub limit_cost_nanos: u128,
    pub recovery_incident_cap_nanos: u128,
    pub recovery_epoch_cap_nanos: u128,
    pub estimate_policy: BudgetEstimatePolicy,
    pub allowance_policy: BudgetAllowancePolicy,
    pub failure_policy: BudgetFailurePolicy,
    pub recovery_policy: BudgetRecoveryPolicy,
}

#[derive(Clone, Debug)]
pub struct RatePolicySnapshot {
    pub id: RatePolicyId,
    pub active: bool,
    pub active_version: Option<RatePolicyVersionSnapshot>,
}

#[derive(Clone, Debug)]
pub struct RatePolicyVersionSnapshot {
    pub id: RatePolicyVersionId,
    pub generation: u64,
    pub epoch: String,
    pub requests_per_minute: u32,
    pub input_units_per_minute: Option<u64>,
    pub grant_mode: String,
    pub grant_policy: RateGrantPolicy,
    pub concurrency_mode: Option<String>,
    pub concurrency_limit: Option<u32>,
    pub lease_seconds: Option<u32>,
    pub max_stream_seconds: u32,
}

#[derive(Clone, Debug, Default)]
pub struct CatalogSnapshot {
    pub routes_by_namespace:
        HashMap<(Option<OrganizationId>, IngressProtocolFamily, String), RouteId>,
    pub routes: HashMap<RouteId, RouteSnapshot>,
    pub deployments: HashMap<DeploymentId, DeploymentSnapshot>,
    pub endpoints: HashMap<EndpointId, EndpointSnapshot>,
    pub reliability_policies: HashMap<ReliabilityPolicyId, ReliabilityPolicySnapshot>,
    pub pricing_policy_versions: HashMap<PricingPolicyVersionId, PricingPolicyVersionSnapshot>,
    pub key_budget_policies: HashMap<BudgetPolicyId, BudgetPolicySnapshot>,
    pub rate_policies: HashMap<RatePolicyId, RatePolicySnapshot>,
}

impl CatalogSnapshot {
    #[must_use]
    pub fn resolve_route(
        &self,
        organization: &OrganizationSnapshot,
        ingress: IngressProtocolFamily,
        model_key: &str,
    ) -> Option<&RouteSnapshot> {
        let organization_route =
            self.routes_by_namespace
                .get(&(Some(organization.id), ingress, model_key.to_owned()));
        if let Some(route_id) = organization_route
            && let Some(route) = self.routes.get(route_id).filter(|route| route.active)
        {
            return Some(route);
        }
        let route_id = self
            .routes_by_namespace
            .get(&(None, ingress, model_key.to_owned()))?;
        organization
            .system_route_grants
            .contains_key(route_id)
            .then(|| self.routes.get(route_id))
            .flatten()
            .filter(|route| route.active)
    }
}

#[derive(Clone, Debug)]
pub struct RouteSnapshot {
    pub id: RouteId,
    pub scope: CatalogScopeKind,
    pub organization_id: Option<OrganizationId>,
    pub owner_user_id: Option<UserId>,
    pub owner_membership_id: Option<uuid::Uuid>,
    pub model_key: String,
    pub ingress_protocol_family: IngressProtocolFamily,
    pub required_base_capabilities: BTreeSet<LlmFeatureCapability>,
    pub selection_policy: RouteSelectionPolicy,
    pub reliability_policy_id: ReliabilityPolicyId,
    pub request_policy: RouteRequestPolicy,
    pub config_version: u64,
    pub active: bool,
    pub targets: Vec<TargetSnapshot>,
}

#[derive(Clone, Debug)]
pub struct TargetSnapshot {
    pub id: TargetId,
    pub deployment_id: DeploymentId,
    pub affinity_identity: [u8; 16],
    pub priority: u8,
    pub weight: u16,
    pub narrowing_constraints: TargetNarrowingConstraints,
    pub timeout_overrides: TargetTimeoutOverrides,
}

#[derive(Clone, Debug)]
pub struct PricingPolicyVersionSnapshot {
    pub id: PricingPolicyVersionId,
    pub pricing_policy_id: PricingPolicyId,
    pub generation: u64,
    pub rates: PricingRates,
    pub rounding_policy: PricingRoundingPolicy,
    pub organization_usable: bool,
    pub policy_active: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PricingOutcome {
    Known {
        cost_nanos: u128,
    },
    Unknown {
        missing_dimensions: BTreeSet<String>,
    },
    Overflow,
}

impl PricingPolicyVersionSnapshot {
    #[must_use]
    pub fn price(&self, usage: &HashMap<String, u64>) -> PricingOutcome {
        let mut total = 0_u128;
        let mut missing = BTreeSet::new();
        for (dimension, rate) in &self.rates.cost_nanos_per_unit {
            let Some(quantity) = usage.get(dimension) else {
                missing.insert(dimension.clone());
                continue;
            };
            if *quantity == 0 {
                continue;
            }
            let Some(raw) = u128::from(*quantity).checked_mul(u128::from(*rate)) else {
                return PricingOutcome::Overflow;
            };
            let quantum = u128::from(self.rounding_policy.quantum_units);
            let rounded = match self.rounding_policy.mode {
                PricingRoundingMode::Up => raw
                    .checked_add(quantum - 1)
                    .map(|value| value / quantum)
                    .and_then(|value| value.checked_mul(quantum)),
                PricingRoundingMode::Nearest => raw
                    .checked_add(quantum / 2)
                    .map(|value| value / quantum)
                    .and_then(|value| value.checked_mul(quantum)),
            };
            let Some(rounded) = rounded else {
                return PricingOutcome::Overflow;
            };
            let Some(next) = total.checked_add(rounded) else {
                return PricingOutcome::Overflow;
            };
            total = next;
        }
        for (dimension, quantity) in usage {
            if *quantity > 0 && !self.rates.cost_nanos_per_unit.contains_key(dimension) {
                missing.insert(dimension.clone());
            }
        }
        if missing.is_empty() {
            PricingOutcome::Known { cost_nanos: total }
        } else {
            PricingOutcome::Unknown {
                missing_dimensions: missing,
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct DeploymentSnapshot {
    pub id: DeploymentId,
    pub scope: CatalogScopeKind,
    pub organization_id: Option<OrganizationId>,
    pub endpoint_id: EndpointId,
    pub endpoint_adapter: EndpointAdapterKind,
    pub endpoint_config_version: i64,
    pub credential_id: CredentialId,
    pub credential_state_identity_version: u64,
    pub credential_secret_version_id: CredentialSecretVersionId,
    pub credential_secret_version: i64,
    pub credential_kind: CredentialKind,
    pub transport_kind: TransportKind,
    pub upstream_model_id: String,
    pub capabilities: BTreeSet<LlmFeatureCapability>,
    pub context_limits: serde_json::Value,
    pub state_isolation_profile: serde_json::Value,
    pub pricing_policy_version_id: Option<PricingPolicyVersionId>,
    pub pricing: Option<Arc<PricingPolicyVersionSnapshot>>,
    pub config_version: u64,
    pub origin: AccountingOrigin,
    pub operational: bool,
}

#[cfg(test)]
mod pricing_tests {
    use super::*;
    use crate::domain::{
        PricingPolicyId, PricingRates, PricingRoundingMode, PricingRoundingPolicy,
    };

    fn pricing() -> PricingPolicyVersionSnapshot {
        PricingPolicyVersionSnapshot {
            id: PricingPolicyVersionId::new(),
            pricing_policy_id: PricingPolicyId::new(),
            generation: 1,
            rates: PricingRates {
                currency: "USD".to_owned(),
                cost_nanos_per_unit: [("input_tokens".to_owned(), 3)].into(),
            },
            rounding_policy: PricingRoundingPolicy {
                mode: PricingRoundingMode::Up,
                quantum_units: 10,
            },
            organization_usable: false,
            policy_active: true,
        }
    }

    #[test]
    fn pricing_is_checked_and_unknown_is_not_zero() {
        assert_eq!(
            pricing().price(&[("input_tokens".to_owned(), 2)].into()),
            PricingOutcome::Known { cost_nanos: 10 }
        );
        assert_eq!(
            pricing().price(&[("output_tokens".to_owned(), 1)].into()),
            PricingOutcome::Unknown {
                missing_dimensions: ["input_tokens".to_owned(), "output_tokens".to_owned()].into()
            }
        );
        assert_eq!(
            pricing().price(&[("input_tokens".to_owned(), u64::MAX)].into()),
            PricingOutcome::Known {
                cost_nanos: 55_340_232_221_128_654_850
            }
        );
    }
}

impl DeploymentSnapshot {
    #[must_use]
    pub fn price(&self, usage: &HashMap<String, u64>) -> Option<PricingOutcome> {
        self.pricing.as_ref().map(|pricing| pricing.price(usage))
    }

    #[must_use]
    pub fn client_key(&self) -> CredentialClientKey {
        CredentialClientKey {
            credential_id: self.credential_id,
            secret_version: self.credential_secret_version,
            endpoint_id: self.endpoint_id,
            endpoint_config_version: self.endpoint_config_version,
            transport_kind: self.transport_kind,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EndpointSnapshot {
    pub id: EndpointId,
    pub adapter: EndpointAdapterKind,
    pub base_url: url::Url,
    pub region: Option<String>,
    pub api_version: Option<String>,
    pub network_policy_id: NetworkPolicyId,
    pub safe_headers: HashMap<String, String>,
    pub config_version: u64,
    pub active: bool,
}

#[derive(Clone, Debug)]
pub struct ReliabilityPolicySnapshot {
    pub id: ReliabilityPolicyId,
    pub attempt_policy: AttemptPolicySnapshot,
    pub deadline_policy: DeadlinePolicySnapshot,
    pub retry_policy: RetryPolicySnapshot,
    pub failover_policy: FailoverPolicySnapshot,
    pub commitment_policy: CommitmentPolicySnapshot,
    pub health_policy: HealthPolicySnapshot,
    pub circuit_policy: CircuitPolicySnapshot,
    pub probe_policy: ProbePolicySnapshot,
    pub config_version: u64,
    pub active: bool,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct AttemptPolicySnapshot {
    pub max_total_attempts: u8,
    pub max_same_target_retries: u8,
    pub max_distinct_failover_targets: u8,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct DeadlinePolicySnapshot {
    pub overall_timeout_ms: u64,
    pub connect_timeout_ms: u64,
    pub response_header_timeout_ms: u64,
    pub body_timeout_ms: u64,
    pub stream_idle_timeout_ms: u64,
    pub pre_commit_classification_timeout_ms: u64,
}

#[derive(Clone, Copy, Debug, serde::Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum RetryCondition {
    ConnectFailure,
    ConnectTimeout,
    ResponseHeaderTimeout,
    ProviderOverloaded,
    ProviderRateLimited,
    #[serde(rename = "provider_5xx")]
    Provider5xx,
}

#[derive(Clone, Debug)]
pub struct RetryPolicySnapshot {
    pub conditions: BTreeSet<RetryCondition>,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub jitter_ratio_millis: u16,
    pub honor_retry_after: bool,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RetryPolicyInput {
    conditions: Vec<RetryCondition>,
    initial_backoff_ms: u64,
    max_backoff_ms: u64,
    jitter_ratio_millis: u16,
    honor_retry_after: bool,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailoverPolicySnapshot {
    pub enabled: bool,
    pub require_replay_safe_request: bool,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitmentPolicySnapshot {
    pub stream_precommit_buffer_bytes: u64,
    pub stream_precommit_buffer_events: u64,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthPolicySnapshot {
    pub shared_summary_ttl_ms: u64,
    pub stale_after_ms: u64,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitPolicySnapshot {
    pub failure_threshold: u64,
    pub success_threshold: u64,
    pub open_duration_ms: u64,
    pub max_open_duration_ms: u64,
    pub half_open_max_requests: u64,
    pub recovery_duration_ms: u64,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbePolicySnapshot {
    pub enabled: bool,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub path: String,
}

impl ReliabilityPolicySnapshot {
    pub(super) fn from_json(
        id: ReliabilityPolicyId,
        attempt_policy: serde_json::Value,
        deadline_policy: serde_json::Value,
        retry_policy: serde_json::Value,
        failover_policy: serde_json::Value,
        commitment_policy: serde_json::Value,
        health_policy: serde_json::Value,
        circuit_policy: serde_json::Value,
        probe_policy: serde_json::Value,
        config_version: u64,
        active: bool,
    ) -> Result<Self, &'static str> {
        let attempt_policy: AttemptPolicySnapshot =
            parse_reliability_component(attempt_policy, "invalid attempt policy")?;
        if !(1..=16).contains(&attempt_policy.max_total_attempts)
            || attempt_policy.max_same_target_retries > 8
            || attempt_policy.max_same_target_retries >= attempt_policy.max_total_attempts
            || attempt_policy.max_distinct_failover_targets > 15
            || attempt_policy.max_distinct_failover_targets >= attempt_policy.max_total_attempts
        {
            return Err("invalid attempt policy");
        }

        let deadline_policy: DeadlinePolicySnapshot =
            parse_reliability_component(deadline_policy, "invalid deadline policy")?;
        if !(100..=3_600_000).contains(&deadline_policy.overall_timeout_ms)
            || !(10..=120_000).contains(&deadline_policy.connect_timeout_ms)
            || !(10..=3_600_000).contains(&deadline_policy.response_header_timeout_ms)
            || !(10..=3_600_000).contains(&deadline_policy.body_timeout_ms)
            || !(100..=3_600_000).contains(&deadline_policy.stream_idle_timeout_ms)
            || !(10..=120_000).contains(&deadline_policy.pre_commit_classification_timeout_ms)
            || [
                deadline_policy.connect_timeout_ms,
                deadline_policy.response_header_timeout_ms,
                deadline_policy.body_timeout_ms,
                deadline_policy.stream_idle_timeout_ms,
                deadline_policy.pre_commit_classification_timeout_ms,
            ]
            .into_iter()
            .any(|timeout| timeout > deadline_policy.overall_timeout_ms)
        {
            return Err("invalid deadline policy");
        }

        let retry_input: RetryPolicyInput =
            parse_reliability_component(retry_policy, "invalid retry policy")?;
        let retry_conditions = retry_input
            .conditions
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if retry_conditions.len() != retry_input.conditions.len()
            || retry_input.conditions.len() > 6
            || retry_input.initial_backoff_ms > 60_000
            || retry_input.max_backoff_ms > 300_000
            || retry_input.initial_backoff_ms > retry_input.max_backoff_ms
            || retry_input.jitter_ratio_millis > 1000
        {
            return Err("invalid retry policy");
        }
        let retry_policy = RetryPolicySnapshot {
            conditions: retry_conditions,
            initial_backoff_ms: retry_input.initial_backoff_ms,
            max_backoff_ms: retry_input.max_backoff_ms,
            jitter_ratio_millis: retry_input.jitter_ratio_millis,
            honor_retry_after: retry_input.honor_retry_after,
        };

        let failover_policy =
            parse_reliability_component(failover_policy, "invalid failover policy")?;
        let commitment_policy: CommitmentPolicySnapshot =
            parse_reliability_component(commitment_policy, "invalid commitment policy")?;
        if !(1..=16 * 1024 * 1024).contains(&commitment_policy.stream_precommit_buffer_bytes)
            || !(1..=4096).contains(&commitment_policy.stream_precommit_buffer_events)
        {
            return Err("invalid commitment policy");
        }
        let health_policy: HealthPolicySnapshot =
            parse_reliability_component(health_policy, "invalid health policy")?;
        if !(100..=300_000).contains(&health_policy.shared_summary_ttl_ms)
            || !(100..=300_000).contains(&health_policy.stale_after_ms)
        {
            return Err("invalid health policy");
        }
        let circuit_policy: CircuitPolicySnapshot =
            parse_reliability_component(circuit_policy, "invalid circuit policy")?;
        if !(1..=1000).contains(&circuit_policy.failure_threshold)
            || !(1..=1000).contains(&circuit_policy.success_threshold)
            || !(100..=3_600_000).contains(&circuit_policy.open_duration_ms)
            || !(100..=3_600_000).contains(&circuit_policy.max_open_duration_ms)
            || circuit_policy.max_open_duration_ms < circuit_policy.open_duration_ms
            || !(1..=128).contains(&circuit_policy.half_open_max_requests)
            || !(100..=3_600_000).contains(&circuit_policy.recovery_duration_ms)
        {
            return Err("invalid circuit policy");
        }
        let probe_policy: ProbePolicySnapshot =
            parse_reliability_component(probe_policy, "invalid probe policy")?;
        if !(1000..=3_600_000).contains(&probe_policy.interval_ms)
            || !(10..=120_000).contains(&probe_policy.timeout_ms)
            || probe_policy.timeout_ms >= probe_policy.interval_ms
            || probe_policy.path.is_empty()
            || probe_policy.path.len() > 1024
            || !probe_policy.path.starts_with('/')
            || probe_policy.path.starts_with("//")
            || probe_policy.path.contains('?')
            || probe_policy.path.contains('#')
            || probe_policy.path.chars().any(char::is_control)
        {
            return Err("invalid probe policy");
        }

        Ok(Self {
            id,
            attempt_policy,
            deadline_policy,
            retry_policy,
            failover_policy,
            commitment_policy,
            health_policy,
            circuit_policy,
            probe_policy,
            config_version,
            active,
        })
    }
}

fn parse_reliability_component<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
    invariant: &'static str,
) -> Result<T, &'static str> {
    serde_json::from_value(value).map_err(|_| invariant)
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CredentialClientKey {
    pub credential_id: CredentialId,
    pub secret_version: i64,
    pub endpoint_id: EndpointId,
    pub endpoint_config_version: i64,
    pub transport_kind: TransportKind,
}

pub enum CredentialInjection {
    Bearer(HeaderValue),
    Codex {
        authorization: HeaderValue,
        account_id: HeaderValue,
    },
    XApiKey(HeaderValue),
    ApiKeyHeader(HeaderValue),
    Dynamic(Arc<ProviderAuthenticator>),
}

impl fmt::Debug for CredentialInjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Bearer(_) => "bearer",
            Self::Codex { .. } => "codex",
            Self::XApiKey(_) => "x_api_key",
            Self::ApiKeyHeader(_) => "api_key_header",
            Self::Dynamic(_) => "dynamic",
        };
        formatter
            .debug_struct("CredentialInjection")
            .field("kind", &kind)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

pub struct CredentialClient {
    pub key: CredentialClientKey,
    pub base_url: url::Url,
    pub adapter: EndpointAdapterKind,
    pub http: reqwest::Client,
    pub(crate) endpoint_connect_timeout_ms: u64,
    pub max_request_body_bytes: u64,
    pub max_response_body_bytes: u64,
    pub injection: CredentialInjection,
    pub(crate) dynamic_secret: Option<SecretPlaintext>,
    pub(crate) build_fingerprint: [u8; 32],
}

impl fmt::Debug for CredentialClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialClient")
            .field("key", &self.key)
            .field("base_url", &self.base_url)
            .field("adapter", &self.adapter)
            .field("injection", &self.injection)
            .field(
                "dynamic_secret",
                &self.dynamic_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("build_fingerprint", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl CredentialClient {
    #[must_use]
    pub const fn request_body_allowed(&self, length: u64) -> bool {
        length <= self.max_request_body_bytes
    }

    #[must_use]
    pub const fn response_body_allowed(&self, length: u64) -> bool {
        length <= self.max_response_body_bytes
    }

    pub(crate) async fn execute_attempt(
        &self,
        request: reqwest::Request,
        connect_timeout_ms: u64,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let timeout =
            Duration::from_millis(connect_timeout_ms.min(self.endpoint_connect_timeout_ms));
        ATTEMPT_CONNECT_TIMEOUT
            .scope(timeout, self.http.execute(request))
            .await
    }

    #[must_use]
    pub(crate) const fn build_fingerprint(&self) -> &[u8; 32] {
        &self.build_fingerprint
    }
}

tokio::task_local! {
    static ATTEMPT_CONNECT_TIMEOUT: Duration;
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AttemptConnectTimeoutLayer;

impl<S> Layer<S> for AttemptConnectTimeoutLayer {
    type Service = AttemptConnectTimeoutService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AttemptConnectTimeoutService { inner }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct AttemptConnectTimeoutService<S> {
    inner: S,
}

impl<S, Request> Service<Request> for AttemptConnectTimeoutService<S>
where
    S: Service<Request> + Send + 'static,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
    S::Response: Send + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context).map_err(Into::into)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let timeout = ATTEMPT_CONNECT_TIMEOUT.try_with(|timeout| *timeout).ok();
        let response = self.inner.call(request);
        Box::pin(async move {
            let Some(timeout) = timeout else {
                return response.await.map_err(Into::into);
            };
            match tokio::time::timeout(timeout, response).await {
                Ok(result) => result.map_err(Into::into),
                Err(elapsed) => Err(Box::new(io::Error::new(io::ErrorKind::TimedOut, elapsed))),
            }
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct CredentialClientRegistry {
    pub clients: HashMap<CredentialClientKey, Arc<CredentialClient>>,
    pub unavailable: HashMap<CredentialClientKey, &'static str>,
}

#[derive(Clone, Debug)]
pub struct ExternalIssuerSnapshot {
    pub id: IssuerId,
    pub name: String,
    pub issuer: String,
    pub active: bool,
    pub allowed_algorithms: Vec<Algorithm>,
    pub accepted_audiences: BTreeSet<String>,
    pub subject_claim: String,
    pub claim_mapping: ClaimMapping,
    pub jwt_capability_ceiling: BTreeSet<String>,
    pub management_scopes: ManagementScopeSet,
    pub management_capabilities: BTreeSet<Capability>,
    pub management_organization_ceiling: ManagementOrganizationCeiling,
    pub llm_access: bool,
    pub llm_scopes: LlmScopeCeiling,
    pub llm_capabilities: BTreeSet<LlmFeatureCapability>,
    pub llm_routes: JwtRouteCeiling,
    pub organization_selector: OrganizationSelector,
    pub capability_claim_policy: CapabilityClaimPolicy,
    pub browser_login: Option<BrowserLoginProfile>,
    pub provisioning_policy_id: Option<PolicyId>,
    pub clock_skew_seconds: u32,
    pub key_cache_policy: KeyCachePolicy,
    pub jwks_source: JwksSource,
    pub policy_version: i64,
    pub verifier_material: Option<IssuerVerifierMaterial>,
}

#[derive(Clone, Debug)]
pub struct IssuerVerifierMaterial {
    pub id: uuid::Uuid,
    pub version: i64,
    pub jwks: JwkSet,
    pub fetched_at: DateTime<Utc>,
    pub accepted_until: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct ManagementKeyVerifier {
    pub key_id: KeyId,
    pub resource_scope: ResourceScope,
    pub issuance_policy_class: String,
    pub scopes: ManagementScopeSet,
    pub capability_ceiling: serde_json::Value,
    pub current_digest: [u8; 32],
    pub accepted_version_id: String,
    pub overlap_digest: Option<[u8; 32]>,
    pub overlap_version_id: Option<String>,
    pub overlap_until: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub active: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn attempt_connect_timeout_is_request_scoped_without_variant_capacity() {
        let mut service =
            AttemptConnectTimeoutLayer.layer(tower::service_fn(|delay: Duration| async move {
                tokio::time::sleep(delay).await;
                Ok::<(), BoxError>(())
            }));

        for timeout_ms in 1..=17 {
            let result = ATTEMPT_CONNECT_TIMEOUT
                .scope(Duration::from_millis(timeout_ms), async {
                    service.call(Duration::from_millis(25)).await
                })
                .await;
            let error = result.expect_err("the request-local connector timeout must fire");
            assert_eq!(
                error.downcast_ref::<io::Error>().map(io::Error::kind),
                Some(io::ErrorKind::TimedOut)
            );
        }

        service
            .call(Duration::from_millis(1))
            .await
            .expect("an unscoped connector call must remain available");
    }
}
