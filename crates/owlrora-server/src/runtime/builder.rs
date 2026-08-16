use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{Arc, LazyLock},
    time::Duration,
};

use ipnet::IpNet;
use owlrora_key_provider::{
    ContextVersion, FieldPurpose, InstallationId, MaterialId, OpaqueEnvelope,
    OrganizationId as SecretOrganizationId, OwnerId, OwnerKind, ProtectionContext,
    ProtectionContextParts, ProviderFormatVersion, ProviderId, SecretPlaintext, SecretScope,
};
use reqwest::{
    dns::{Addrs, Name, Resolve, Resolving},
    header::{HeaderMap, HeaderName, HeaderValue},
};
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use crate::{
    adapters::postgres::StoreError,
    domain::{
        AccountingOrigin, BudgetMode, BudgetPolicyId, BudgetPolicyVersionId, CatalogScopeKind,
        CredentialId, CredentialKind, CredentialSecretVersionId, CredentialSourceKind,
        DeploymentId, EgressNetworkConfiguration, EndpointAdapterKind, EndpointId, GatewayKeyId,
        IngressProtocolFamily, LlmFeatureCapability, LlmScopeSet, NetworkPolicyId, OrganizationId,
        PolicyActivationId, PolicyKind, PricingPolicyId, PricingPolicyVersionId, PricingRates,
        PricingRoundingPolicy, RatePolicyId, RatePolicyVersionId, ReliabilityPolicyId, RouteId,
        SystemRouteGrantCeilings, TargetId, TransportKind, UserId, compatibility,
    },
    secrets::SecretService,
};

use super::generation::AttemptConnectTimeoutLayer;
use super::{
    BudgetPolicySnapshot, BudgetPolicyVersionSnapshot, CatalogSnapshot, CredentialClient,
    CredentialClientKey, CredentialClientRegistry, CredentialInjection, DeploymentSnapshot,
    EndpointSnapshot, GatewayKeyVerifier, GatewayPolicyCeilingsSnapshot, OrganizationSnapshot,
    PolicyActivationKey, PolicyActivationSnapshot, PolicyActivationState,
    PricingPolicyVersionSnapshot, RatePolicySnapshot, RatePolicyVersionSnapshot,
    ReliabilityPolicySnapshot, RouteSnapshot, RuntimeGeneration, TargetSnapshot,
};

const COMPATIBILITY_REGISTRY_VERSION: u32 = 1;
const MAX_SOURCE_PATH_LEN: usize = 4096;
const MAX_ENVIRONMENT_NAME_LEN: usize = 128;

pub(super) const fn compatibility_registry_version() -> u32 {
    COMPATIBILITY_REGISTRY_VERSION
}

pub(super) struct CapturedGatewayRuntime {
    pub gateway_policy_ceilings: GatewayPolicyCeilingsSnapshot,
    pub gateway_keys: HashMap<String, GatewayKeyVerifier>,
    pub organizations: HashMap<OrganizationId, OrganizationSnapshot>,
    pub policy_activations: HashMap<PolicyActivationKey, PolicyActivationSnapshot>,
    pub catalog: CatalogSnapshot,
    client_builds: HashMap<CredentialClientKey, ClientBuild>,
}

#[derive(Clone)]
struct ClientBuild {
    key: CredentialClientKey,
    credential_kind: CredentialKind,
    adapter: EndpointAdapterKind,
    base_url: url::Url,
    region: Option<String>,
    safe_headers: HashMap<String, String>,
    source_kind: CredentialSourceKind,
    injection_kind: InjectionKind,
    safe_fingerprint: [u8; 32],
    source: CapturedSecretSource,
    network_configuration: EgressNetworkConfiguration,
    custom_ca: Option<ProtectedSecretRecord>,
}

#[derive(Clone)]
enum CapturedSecretSource {
    Protected(ProtectedSecretRecord),
    External(serde_json::Value),
}

#[derive(Clone)]
struct ProtectedSecretRecord {
    material_id: Uuid,
    scope: SecretScopeRecord,
    owner_kind: String,
    owner_id: Uuid,
    owner_generation: u64,
    secret_version: u64,
    field_purpose: String,
    provider_id: String,
    provider_format_version: u32,
    context_version: u32,
    envelope: Vec<u8>,
}

#[derive(Clone)]
enum SecretScopeRecord {
    System,
    Organization(OrganizationId),
}

#[derive(Clone, Copy)]
enum InjectionKind {
    Bearer,
    XApiKey,
    ApiKeyHeader,
    AwsSigV4,
    GoogleOauth,
    AzureBearer,
}

struct CredentialRecord {
    scope: CatalogScopeKind,
    organization_id: Option<OrganizationId>,
    kind: CredentialKind,
    source_kind: CredentialSourceKind,
    injection_kind: InjectionKind,
    state_identity_version: u64,
    administrative_active: bool,
    authentication_ready: bool,
    selected: Option<SelectedCredentialVersion>,
}

struct SelectedCredentialVersion {
    id: CredentialSecretVersionId,
    version: i64,
    safe_fingerprint: [u8; 32],
    source: CapturedSecretSource,
}

struct EndpointRecord {
    snapshot: EndpointSnapshot,
    network_active: bool,
    network_configuration: EgressNetworkConfiguration,
    custom_ca: Option<ProtectedSecretRecord>,
}

pub(super) async fn capture_gateway_runtime(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<CapturedGatewayRuntime, StoreError> {
    let gateway_policy_ceilings = load_gateway_policy_ceilings(transaction).await?;
    let mut organizations = load_organizations(transaction).await?;
    let (origin_budgets, key_budgets) = load_budget_policies(transaction).await?;
    for (organization_id, policies) in origin_budgets {
        let organization = organizations
            .get_mut(&organization_id)
            .ok_or(StoreError::Invariant(
                "origin budget references unknown organization",
            ))?;
        organization.origin_budgets = policies;
    }
    if organizations
        .values()
        .any(|organization| organization.origin_budgets.len() != 2)
    {
        return Err(StoreError::Invariant(
            "organization must have exactly two origin budget policies",
        ));
    }

    let rate_policies = load_rate_policies(transaction).await?;
    let policy_activations = load_policy_activations(transaction, &mut organizations).await?;
    let pricing_policy_versions = load_pricing_policy_versions(transaction).await?;
    let reliability_policies = load_reliability_policies(transaction).await?;
    let endpoints = load_endpoints(transaction).await?;
    let credentials = load_credentials(transaction).await?;
    let (mut deployments, client_builds) = load_deployments(
        transaction,
        &endpoints,
        &credentials,
        &pricing_policy_versions,
    )
    .await?;
    apply_deployment_grants(&organizations, &mut deployments);
    let routes = load_routes(
        transaction,
        &organizations,
        &reliability_policies,
        &deployments,
    )
    .await?;
    let gateway_keys = load_gateway_keys(
        transaction,
        &organizations,
        &key_budgets,
        &rate_policies,
        &routes,
    )
    .await?;

    let endpoint_snapshots = endpoints
        .into_iter()
        .map(|(id, endpoint)| (id, endpoint.snapshot))
        .collect();
    Ok(CapturedGatewayRuntime {
        gateway_policy_ceilings,
        gateway_keys,
        organizations,
        policy_activations,
        catalog: CatalogSnapshot {
            routes_by_namespace: routes
                .values()
                .map(|route| {
                    (
                        (
                            route.organization_id,
                            route.ingress_protocol_family,
                            route.model_key.clone(),
                        ),
                        route.id,
                    )
                })
                .collect(),
            routes,
            deployments,
            endpoints: endpoint_snapshots,
            reliability_policies,
            pricing_policy_versions,
            key_budget_policies: key_budgets,
            rate_policies,
        },
        client_builds,
    })
}

pub(super) async fn build_credential_clients(
    captured: &mut CapturedGatewayRuntime,
    installation_id: Uuid,
    secrets: &SecretService,
    prior: Option<&RuntimeGeneration>,
    egress_dns_overrides: &HashMap<String, SocketAddr>,
) -> CredentialClientRegistry {
    let mut registry = CredentialClientRegistry::default();
    for (key, build) in &captured.client_builds {
        let fingerprint = client_build_fingerprint(build);
        let shared = prior
            .and_then(|generation| generation.credential_clients.clients.get(key))
            .filter(|client| client.build_fingerprint() == &fingerprint)
            .cloned();
        let client = match shared {
            Some(client) => Ok(client),
            None => build_client(
                build,
                installation_id,
                secrets,
                fingerprint,
                egress_dns_overrides,
            )
            .await
            .map(Arc::new),
        };
        match client {
            Ok(client) => {
                registry.clients.insert(key.clone(), client);
            }
            Err(reason) => {
                registry.unavailable.insert(key.clone(), reason);
            }
        }
    }
    for deployment in captured.catalog.deployments.values_mut() {
        if deployment.operational && !registry.clients.contains_key(&deployment.client_key()) {
            deployment.operational = false;
        }
    }
    registry
}

async fn load_organizations(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<HashMap<OrganizationId, OrganizationSnapshot>, StoreError> {
    let rows = sqlx::query(
        "SELECT organization.id, organization.status, policy.policy
         FROM organizations organization
         LEFT JOIN organization_api_key_policies policy
           ON policy.organization_id = organization.id",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut organizations = HashMap::with_capacity(rows.len());
    for row in rows {
        let id = OrganizationId::from_uuid(row.try_get("id")?);
        let policy = row
            .try_get::<Option<serde_json::Value>, _>("policy")?
            .ok_or(StoreError::Invariant(
                "organization API key policy is missing",
            ))?;
        require_object(&policy, "invalid organization API key policy")?;
        organizations.insert(
            id,
            OrganizationSnapshot {
                id,
                active: row.try_get::<String, _>("status")? == "active",
                pending_tightening_deadline: None,
                api_key_policy: policy,
                system_route_grants: HashMap::new(),
                endpoint_grants: BTreeSet::new(),
                deployment_grants: BTreeSet::new(),
                reliability_policy_grants: BTreeSet::new(),
                origin_budgets: HashMap::new(),
            },
        );
    }

    for row in sqlx::query(
        "SELECT grant_row.organization_id,grant_row.route_id,grant_row.ceilings,
                identity.id AS identity_id
         FROM organization_route_grants grant_row
         JOIN organization_route_grant_identities identity
           ON identity.organization_id=grant_row.organization_id
          AND identity.route_id=grant_row.route_id
         WHERE grant_row.status='active'",
    )
    .fetch_all(&mut **transaction)
    .await?
    {
        let organization = organization_mut(&mut organizations, &row)?;
        let ceilings: SystemRouteGrantCeilings =
            typed_column(&row, "ceilings", "invalid route grant ceilings")?;
        if !ceilings.is_valid() {
            return Err(StoreError::Invariant("invalid route grant ceilings"));
        }
        organization.system_route_grants.insert(
            RouteId::from_uuid(row.try_get("route_id")?),
            super::SystemRouteGrantSnapshot {
                identity_id: row.try_get("identity_id")?,
                ceilings,
            },
        );
    }
    for row in sqlx::query(
        "SELECT organization_id, endpoint_id
         FROM organization_endpoint_grants WHERE status='active'",
    )
    .fetch_all(&mut **transaction)
    .await?
    {
        organization_mut(&mut organizations, &row)?
            .endpoint_grants
            .insert(EndpointId::from_uuid(row.try_get("endpoint_id")?));
    }
    for row in sqlx::query(
        "SELECT organization_id, deployment_id
         FROM organization_deployment_grants WHERE status='active'",
    )
    .fetch_all(&mut **transaction)
    .await?
    {
        organization_mut(&mut organizations, &row)?
            .deployment_grants
            .insert(DeploymentId::from_uuid(row.try_get("deployment_id")?));
    }
    for row in sqlx::query(
        "SELECT organization_id, reliability_policy_id
         FROM organization_reliability_policy_grants WHERE status='active'",
    )
    .fetch_all(&mut **transaction)
    .await?
    {
        organization_mut(&mut organizations, &row)?
            .reliability_policy_grants
            .insert(ReliabilityPolicyId::from_uuid(
                row.try_get("reliability_policy_id")?,
            ));
    }
    Ok(organizations)
}

fn organization_mut<'a>(
    organizations: &'a mut HashMap<OrganizationId, OrganizationSnapshot>,
    row: &PgRow,
) -> Result<&'a mut OrganizationSnapshot, StoreError> {
    let id = OrganizationId::from_uuid(row.try_get("organization_id")?);
    organizations.get_mut(&id).ok_or(StoreError::Invariant(
        "grant references unknown organization",
    ))
}

type OriginBudgets = HashMap<OrganizationId, HashMap<AccountingOrigin, BudgetPolicySnapshot>>;

async fn load_budget_policies(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(OriginBudgets, HashMap<BudgetPolicyId, BudgetPolicySnapshot>), StoreError> {
    let origin_rows = sqlx::query(
        "SELECT policy.id, policy.organization_id, policy.origin, policy.status,
                version.id AS version_id, version.generation,
                COALESCE((
                    SELECT MAX(recovery.recovery_generation)
                    FROM coordinator_recoveries recovery
                    WHERE recovery.policy_kind='organization_origin_budget'
                      AND recovery.policy_id=policy.id
                      AND recovery.policy_version_id=version.id
                      AND recovery.epoch=version.epoch
                ),0) AS recovery_generation,
                version.epoch, version.mode,
                version.limit_cost_nanos::text AS limit_cost_nanos,
                version.recovery_incident_cap_nanos::text AS recovery_incident_cap_nanos,
                version.recovery_epoch_cap_nanos::text AS recovery_epoch_cap_nanos,
                version.estimate_policy, version.allowance_policy, version.failure_policy,
                version.recovery_policy
         FROM organization_origin_budget_policies policy
         LEFT JOIN budget_policy_versions version ON version.id=policy.active_version_id
          AND version.organization_origin_budget_policy_id=policy.id",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut origins: OriginBudgets = HashMap::new();
    for row in origin_rows {
        let organization_id = OrganizationId::from_uuid(row.try_get("organization_id")?);
        let origin = match row.try_get::<String, _>("origin")?.as_str() {
            "system_provided" => AccountingOrigin::SystemProvided,
            "organization_byok" => AccountingOrigin::OrganizationByok,
            _ => return Err(StoreError::Invariant("unknown accounting origin")),
        };
        let snapshot = parse_budget_policy(&row)?;
        if origins
            .entry(organization_id)
            .or_default()
            .insert(origin, snapshot)
            .is_some()
        {
            return Err(StoreError::Invariant(
                "duplicate organization origin budget",
            ));
        }
    }

    let key_rows = sqlx::query(
        "SELECT policy.id, policy.organization_id, policy.status,
                version.id AS version_id, version.generation,
                COALESCE((
                    SELECT MAX(recovery.recovery_generation)
                    FROM coordinator_recoveries recovery
                    WHERE recovery.policy_kind='gateway_key_budget'
                      AND recovery.policy_id=policy.id
                      AND recovery.policy_version_id=version.id
                      AND recovery.epoch=version.epoch
                ),0) AS recovery_generation,
                version.epoch, version.mode,
                version.limit_cost_nanos::text AS limit_cost_nanos,
                version.recovery_incident_cap_nanos::text AS recovery_incident_cap_nanos,
                version.recovery_epoch_cap_nanos::text AS recovery_epoch_cap_nanos,
                version.estimate_policy, version.allowance_policy, version.failure_policy,
                version.recovery_policy
         FROM gateway_key_budget_policies policy
         LEFT JOIN budget_policy_versions version ON version.id=policy.active_version_id
          AND version.gateway_key_budget_policy_id=policy.id",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut keys = HashMap::with_capacity(key_rows.len());
    for row in key_rows {
        let policy = parse_budget_policy(&row)?;
        if keys.insert(policy.id, policy).is_some() {
            return Err(StoreError::Invariant("duplicate gateway key budget policy"));
        }
    }
    Ok((origins, keys))
}

async fn load_policy_activations(
    transaction: &mut Transaction<'_, Postgres>,
    organizations: &mut HashMap<OrganizationId, OrganizationSnapshot>,
) -> Result<HashMap<PolicyActivationKey, PolicyActivationSnapshot>, StoreError> {
    let rows = sqlx::query(
        "SELECT id,organization_id,policy_kind,policy_id,desired_epoch,desired_version_id,
                desired_generation,active_epoch,active_version_id,active_generation,
                prior_epoch,prior_version_id,prior_generation,candidate_fence,state,
                tightening_deadline,prior_cutoff_at
         FROM policy_activations
         WHERE state NOT IN ('finalized','superseded','failed')",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut activations = HashMap::with_capacity(rows.len());
    for row in rows {
        let organization_id = OrganizationId::from_uuid(row.try_get("organization_id")?);
        let organization = organizations
            .get_mut(&organization_id)
            .ok_or(StoreError::Invariant(
                "policy activation references unknown organization",
            ))?;
        let kind: PolicyKind = parse_enum(
            row.try_get("policy_kind")?,
            "invalid policy activation kind",
        )?;
        let key = PolicyActivationKey {
            kind,
            policy_id: row.try_get("policy_id")?,
        };
        let state = match row.try_get::<String, _>("state")?.as_str() {
            "desired" => PolicyActivationState::Desired,
            "coordinator_staged" => PolicyActivationState::CoordinatorStaged,
            "coordinator_armed" => PolicyActivationState::CoordinatorArmed,
            "active" => PolicyActivationState::Active,
            _ => {
                return Err(StoreError::Invariant(
                    "invalid active policy activation state",
                ));
            }
        };
        let tightening_deadline: Option<chrono::DateTime<chrono::Utc>> =
            row.try_get("tightening_deadline")?;
        if state != PolicyActivationState::Active
            && let Some(deadline) = tightening_deadline
        {
            organization.pending_tightening_deadline = Some(
                organization
                    .pending_tightening_deadline
                    .map_or(deadline, |current| current.min(deadline)),
            );
        }
        let activation = PolicyActivationSnapshot {
            id: PolicyActivationId::from_uuid(row.try_get("id")?),
            organization_id,
            key,
            desired_epoch: nonempty(
                row.try_get("desired_epoch")?,
                "invalid desired activation epoch",
            )?,
            desired_version_id: row.try_get("desired_version_id")?,
            desired_generation: positive_u64(
                row.try_get("desired_generation")?,
                "invalid desired activation generation",
            )?,
            active_epoch: row.try_get("active_epoch")?,
            active_version_id: row.try_get("active_version_id")?,
            active_generation: row
                .try_get::<Option<i64>, _>("active_generation")?
                .map(|value| positive_u64(value, "invalid active activation generation"))
                .transpose()?,
            prior_epoch: row.try_get("prior_epoch")?,
            prior_version_id: row.try_get("prior_version_id")?,
            prior_generation: row
                .try_get::<Option<i64>, _>("prior_generation")?
                .map(|value| positive_u64(value, "invalid prior activation generation"))
                .transpose()?,
            candidate_fence: row.try_get("candidate_fence")?,
            state,
            tightening_deadline,
            prior_cutoff_at: row.try_get("prior_cutoff_at")?,
        };
        if activations.insert(key, activation).is_some() {
            return Err(StoreError::Invariant(
                "multiple unfinished activations reference one policy",
            ));
        }
    }
    Ok(activations)
}

async fn load_pricing_policy_versions(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<HashMap<PricingPolicyVersionId, PricingPolicyVersionSnapshot>, StoreError> {
    let rows = sqlx::query(
        "SELECT version.id,version.pricing_policy_id,version.generation,version.rates,
                version.rounding_policy,version.organization_usable,policy.status
         FROM pricing_policy_versions version
         JOIN pricing_policies policy ON policy.id=version.pricing_policy_id",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut versions = HashMap::with_capacity(rows.len());
    for row in rows {
        let id = PricingPolicyVersionId::from_uuid(row.try_get("id")?);
        let rates: PricingRates = serde_json::from_value(row.try_get("rates")?)
            .map_err(|_| StoreError::Invariant("invalid pricing rates"))?;
        if rates.currency != "USD"
            || rates.cost_nanos_per_unit.is_empty()
            || rates.cost_nanos_per_unit.len() > 64
            || rates.cost_nanos_per_unit.iter().any(|(dimension, cost)| {
                dimension.is_empty()
                    || dimension.len() > 128
                    || dimension.chars().any(char::is_control)
                    || *cost == 0
            })
        {
            return Err(StoreError::Invariant("invalid pricing rates"));
        }
        let rounding_policy: PricingRoundingPolicy =
            serde_json::from_value(row.try_get("rounding_policy")?)
                .map_err(|_| StoreError::Invariant("invalid pricing rounding policy"))?;
        if rounding_policy.quantum_units == 0 {
            return Err(StoreError::Invariant("invalid pricing rounding policy"));
        }
        let snapshot = PricingPolicyVersionSnapshot {
            id,
            pricing_policy_id: PricingPolicyId::from_uuid(row.try_get("pricing_policy_id")?),
            generation: positive_u64(row.try_get("generation")?, "invalid pricing generation")?,
            rates,
            rounding_policy,
            organization_usable: row.try_get("organization_usable")?,
            policy_active: row.try_get::<String, _>("status")? == "active",
        };
        if versions.insert(id, snapshot).is_some() {
            return Err(StoreError::Invariant("duplicate pricing policy version"));
        }
    }
    Ok(versions)
}

fn parse_budget_policy(row: &PgRow) -> Result<BudgetPolicySnapshot, StoreError> {
    let status: String = row.try_get("status")?;
    let active_version = row
        .try_get::<Option<Uuid>, _>("version_id")?
        .map(|id| {
            Ok::<BudgetPolicyVersionSnapshot, StoreError>(BudgetPolicyVersionSnapshot {
                id: BudgetPolicyVersionId::from_uuid(id),
                generation: positive_u64(row.try_get("generation")?, "invalid budget generation")?,
                recovery_generation: u64::try_from(row.try_get::<i64, _>("recovery_generation")?)
                    .map_err(|_| {
                    StoreError::Invariant("invalid recovery generation")
                })?,
                epoch: nonempty(row.try_get("epoch")?, "invalid budget epoch")?,
                mode: parse_enum(row.try_get("mode")?, "invalid budget mode")?,
                limit_cost_nanos: parse_u128_text(row, "limit_cost_nanos")?,
                recovery_incident_cap_nanos: parse_u128_text(row, "recovery_incident_cap_nanos")?,
                recovery_epoch_cap_nanos: parse_u128_text(row, "recovery_epoch_cap_nanos")?,
                estimate_policy: typed_column(row, "estimate_policy", "invalid estimate policy")?,
                allowance_policy: typed_column(
                    row,
                    "allowance_policy",
                    "invalid allowance policy",
                )?,
                failure_policy: typed_column(row, "failure_policy", "invalid failure policy")?,
                recovery_policy: typed_column(row, "recovery_policy", "invalid recovery policy")?,
            })
        })
        .transpose()?;
    Ok(BudgetPolicySnapshot {
        id: BudgetPolicyId::from_uuid(row.try_get("id")?),
        active: status == "active",
        active_version,
    })
}

async fn load_rate_policies(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<HashMap<RatePolicyId, RatePolicySnapshot>, StoreError> {
    let rows = sqlx::query(
        "SELECT policy.id, policy.status,
                version.id AS version_id, version.generation, version.epoch,
                version.requests_per_minute, version.input_units_per_minute,
                version.grant_mode, version.grant_policy, version.concurrency_mode,
                version.concurrency_limit, version.lease_seconds, version.max_stream_seconds
         FROM gateway_key_rate_policies policy
         LEFT JOIN gateway_key_rate_policy_versions version
           ON version.id=policy.active_version_id AND version.rate_policy_id=policy.id",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut policies = HashMap::with_capacity(rows.len());
    for row in rows {
        let status: String = row.try_get("status")?;
        let active_version = row
            .try_get::<Option<Uuid>, _>("version_id")?
            .map(|id| {
                Ok::<RatePolicyVersionSnapshot, StoreError>(RatePolicyVersionSnapshot {
                    id: RatePolicyVersionId::from_uuid(id),
                    generation: positive_u64(
                        row.try_get("generation")?,
                        "invalid rate generation",
                    )?,
                    epoch: nonempty(row.try_get("epoch")?, "invalid rate epoch")?,
                    requests_per_minute: positive_u32(
                        row.try_get("requests_per_minute")?,
                        "invalid requests per minute",
                    )?,
                    input_units_per_minute: row
                        .try_get::<Option<i64>, _>("input_units_per_minute")?
                        .map(|value| positive_u64(value, "invalid input units per minute"))
                        .transpose()?,
                    grant_mode: nonempty(row.try_get("grant_mode")?, "invalid grant mode")?,
                    grant_policy: typed_column(&row, "grant_policy", "invalid grant policy")?,
                    concurrency_mode: row.try_get("concurrency_mode")?,
                    concurrency_limit: row
                        .try_get::<Option<i32>, _>("concurrency_limit")?
                        .map(|value| positive_u32(value, "invalid concurrency limit"))
                        .transpose()?,
                    lease_seconds: row
                        .try_get::<Option<i32>, _>("lease_seconds")?
                        .map(|value| positive_u32(value, "invalid lease seconds"))
                        .transpose()?,
                    max_stream_seconds: positive_u32(
                        row.try_get("max_stream_seconds")?,
                        "invalid max stream seconds",
                    )?,
                })
            })
            .transpose()?;
        let policy = RatePolicySnapshot {
            id: RatePolicyId::from_uuid(row.try_get("id")?),
            active: status == "active",
            active_version,
        };
        if policies.insert(policy.id, policy).is_some() {
            return Err(StoreError::Invariant("duplicate gateway rate policy"));
        }
    }
    Ok(policies)
}

async fn load_reliability_policies(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<HashMap<ReliabilityPolicyId, ReliabilityPolicySnapshot>, StoreError> {
    let rows = sqlx::query(
        "SELECT id, attempt_policy, deadline_policy, retry_policy, failover_policy,
                commitment_policy, health_policy, circuit_policy, probe_policy,
                status, config_version
         FROM reliability_policies",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut policies = HashMap::with_capacity(rows.len());
    for row in rows {
        let id = ReliabilityPolicyId::from_uuid(row.try_get("id")?);
        let policy = ReliabilityPolicySnapshot::from_json(
            id,
            row.try_get("attempt_policy")?,
            row.try_get("deadline_policy")?,
            row.try_get("retry_policy")?,
            row.try_get("failover_policy")?,
            row.try_get("commitment_policy")?,
            row.try_get("health_policy")?,
            row.try_get("circuit_policy")?,
            row.try_get("probe_policy")?,
            positive_u64(
                row.try_get("config_version")?,
                "invalid reliability config version",
            )?,
            row.try_get::<String, _>("status")? == "active",
        )
        .map_err(StoreError::Invariant)?;
        if policies.insert(policy.id, policy).is_some() {
            return Err(StoreError::Invariant("duplicate reliability policy"));
        }
    }
    Ok(policies)
}

async fn load_endpoints(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<HashMap<EndpointId, EndpointRecord>, StoreError> {
    let rows = sqlx::query(
        "SELECT endpoint.id, endpoint.adapter_kind, endpoint.base_url, endpoint.region,
                endpoint.api_version, endpoint.network_policy_id, endpoint.safe_headers,
                endpoint.status, endpoint.config_version,
                network.status AS network_status, network.dns_policy, network.address_policy,
                network.proxy_url, network.tls_policy, network.custom_ca_secret_id,
                network.custom_ca_generation,network.redirect_policy,
                network.connection_policy, network.body_policy,
                network.config_version AS network_config_version,
                ca.scope_kind AS ca_scope_kind,ca.organization_id AS ca_organization_id,
                ca.owner_kind AS ca_owner_kind,ca.owner_id AS ca_owner_id,
                ca.owner_generation AS ca_owner_generation,ca.secret_version AS ca_secret_version,
                ca.field_purpose AS ca_field_purpose,ca.custody_provider_id AS ca_provider_id,
                ca.provider_format_version AS ca_provider_format,ca.context_version AS ca_context_version,
                ca.opaque_envelope AS ca_opaque_envelope
         FROM upstream_endpoints endpoint
         JOIN egress_network_policies network ON network.id=endpoint.network_policy_id
         LEFT JOIN protected_secret_versions ca ON ca.id=network.custom_ca_secret_id",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut endpoints = HashMap::with_capacity(rows.len());
    for row in rows {
        let id = EndpointId::from_uuid(row.try_get("id")?);
        let adapter: EndpointAdapterKind =
            parse_enum(row.try_get("adapter_kind")?, "invalid endpoint adapter")?;
        let base_url = parse_endpoint_url(&row.try_get::<String, _>("base_url")?)?;
        if adapter == EndpointAdapterKind::OpenaiCodex
            && base_url.as_str() != crate::adapters::provider::codex::RESPONSES_BASE_URL
        {
            return Err(StoreError::Invariant("invalid Codex endpoint authority"));
        }
        let safe_headers = parse_safe_headers(row.try_get("safe_headers")?)?;
        let network_configuration = parse_network_configuration(&row)?;
        let custom_ca = parse_custom_ca(&row, &network_configuration)?;
        let snapshot = EndpointSnapshot {
            id,
            adapter,
            base_url,
            region: row.try_get("region")?,
            api_version: row.try_get("api_version")?,
            network_policy_id: NetworkPolicyId::from_uuid(row.try_get("network_policy_id")?),
            safe_headers,
            config_version: positive_u64(
                row.try_get("config_version")?,
                "invalid endpoint config version",
            )?,
            active: row.try_get::<String, _>("status")? == "active",
        };
        let record = EndpointRecord {
            snapshot,
            network_active: row.try_get::<String, _>("network_status")? == "active",
            network_configuration,
            custom_ca,
        };
        if endpoints.insert(id, record).is_some() {
            return Err(StoreError::Invariant("duplicate upstream endpoint"));
        }
    }
    Ok(endpoints)
}

async fn load_gateway_policy_ceilings(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<GatewayPolicyCeilingsSnapshot, StoreError> {
    let row = sqlx::query(
        "SELECT key_budget_max_limit_cost_nanos::text AS key_budget_max,
                byok_origin_budget_max_limit_cost_nanos::text AS byok_budget_max,
                max_recovery_incident_cap_nanos::text AS incident_cap,
                max_recovery_epoch_cap_nanos::text AS epoch_cap,
                max_requests_per_minute,max_input_units_per_minute,max_concurrency,
                max_stream_seconds,allowed_budget_modes,allowed_rate_grant_modes,
                allowed_concurrency_modes
         FROM gateway_policy_ceilings WHERE singleton=true",
    )
    .fetch_one(&mut **transaction)
    .await?;
    let budget_modes =
        serde_json::from_value::<Vec<BudgetMode>>(row.try_get("allowed_budget_modes")?)
            .map_err(|_| StoreError::Invariant("invalid allowed gateway budget modes"))?
            .into_iter()
            .collect::<BTreeSet<_>>();
    let rate_modes = string_set_column(
        &row,
        "allowed_rate_grant_modes",
        &["local_grants", "strict"],
        "invalid allowed rate grant modes",
    )?;
    let concurrency_modes = string_set_column(
        &row,
        "allowed_concurrency_modes",
        &["approximate", "strict"],
        "invalid allowed concurrency modes",
    )?;
    if budget_modes.is_empty()
        || !budget_modes
            .iter()
            .all(|mode| matches!(mode, BudgetMode::Enforce | BudgetMode::RecordOnly))
    {
        return Err(StoreError::Invariant(
            "invalid allowed gateway budget modes",
        ));
    }
    let snapshot = GatewayPolicyCeilingsSnapshot {
        key_budget_max_limit_cost_nanos: positive_u128_text(
            &row.try_get::<String, _>("key_budget_max")?,
            "invalid key budget ceiling",
        )?,
        byok_origin_budget_max_limit_cost_nanos: positive_u128_text(
            &row.try_get::<String, _>("byok_budget_max")?,
            "invalid BYOK budget ceiling",
        )?,
        max_recovery_incident_cap_nanos: parse_u128_value(
            &row.try_get::<String, _>("incident_cap")?,
            "invalid recovery incident ceiling",
        )?,
        max_recovery_epoch_cap_nanos: parse_u128_value(
            &row.try_get::<String, _>("epoch_cap")?,
            "invalid recovery epoch ceiling",
        )?,
        max_requests_per_minute: positive_u32(
            row.try_get("max_requests_per_minute")?,
            "invalid requests-per-minute ceiling",
        )?,
        max_input_units_per_minute: positive_u64(
            row.try_get("max_input_units_per_minute")?,
            "invalid input-units ceiling",
        )?,
        max_concurrency: positive_u32(
            row.try_get("max_concurrency")?,
            "invalid concurrency ceiling",
        )?,
        max_stream_seconds: positive_u32(
            row.try_get("max_stream_seconds")?,
            "invalid stream ceiling",
        )?,
        allowed_budget_modes: budget_modes,
        allowed_rate_grant_modes: rate_modes,
        allowed_concurrency_modes: concurrency_modes,
    };
    if snapshot.max_recovery_incident_cap_nanos > snapshot.max_recovery_epoch_cap_nanos
        || snapshot.max_stream_seconds > 86_400
    {
        return Err(StoreError::Invariant("invalid gateway policy ceilings"));
    }
    Ok(snapshot)
}

fn string_set_column(
    row: &PgRow,
    column: &str,
    allowed: &[&str],
    error: &'static str,
) -> Result<BTreeSet<String>, StoreError> {
    let values = serde_json::from_value::<Vec<String>>(row.try_get(column)?)
        .map_err(|_| StoreError::Invariant(error))?;
    let set = values.iter().cloned().collect::<BTreeSet<_>>();
    if set.is_empty()
        || set.len() != values.len()
        || !set.iter().all(|value| allowed.contains(&value.as_str()))
    {
        return Err(StoreError::Invariant(error));
    }
    Ok(set)
}

fn parse_network_configuration(row: &PgRow) -> Result<EgressNetworkConfiguration, StoreError> {
    let configuration = serde_json::json!({
        "dns": object_column(row, "dns_policy", "invalid DNS policy")?,
        "address": object_column(row, "address_policy", "invalid address policy")?,
        "proxy_url": row.try_get::<Option<String>, _>("proxy_url")?,
        "tls": object_column(row, "tls_policy", "invalid TLS policy")?,
        "redirect": object_column(row, "redirect_policy", "invalid redirect policy")?,
        "connection": object_column(row, "connection_policy", "invalid connection policy")?,
        "body": object_column(row, "body_policy", "invalid body policy")?,
        "custom_ca_secret_id": row.try_get::<Option<Uuid>, _>("custom_ca_secret_id")?,
        "custom_ca_generation": u64::try_from(row.try_get::<i64, _>("custom_ca_generation")?)
            .map_err(|_| StoreError::Invariant("invalid custom CA generation"))?,
        "config_version": positive_u64(
            row.try_get("network_config_version")?,
            "invalid network config version",
        )?,
    });
    serde_json::from_value(configuration)
        .map_err(|_| StoreError::Invariant("invalid egress network policy"))
}

fn parse_custom_ca(
    row: &PgRow,
    configuration: &EgressNetworkConfiguration,
) -> Result<Option<ProtectedSecretRecord>, StoreError> {
    let Some(material_id) = configuration.custom_ca_secret_id else {
        return Ok(None);
    };
    let owner_kind =
        row.try_get::<Option<String>, _>("ca_owner_kind")?
            .ok_or(StoreError::Invariant(
                "custom CA protected record is missing",
            ))?;
    let owner_id = row
        .try_get::<Option<Uuid>, _>("ca_owner_id")?
        .ok_or(StoreError::Invariant("custom CA owner is missing"))?;
    let owner_generation = positive_u64(
        row.try_get::<Option<i64>, _>("ca_owner_generation")?
            .ok_or(StoreError::Invariant("custom CA generation is missing"))?,
        "invalid custom CA generation",
    )?;
    let expected_owner = row.try_get::<Uuid, _>("network_policy_id")?;
    if row
        .try_get::<Option<String>, _>("ca_scope_kind")?
        .as_deref()
        != Some("system")
        || row
            .try_get::<Option<Uuid>, _>("ca_organization_id")?
            .is_some()
        || owner_kind != "egress_network_policy"
        || owner_id != expected_owner
        || owner_generation != configuration.custom_ca_generation
        || positive_u64(
            row.try_get::<Option<i64>, _>("ca_secret_version")?
                .ok_or(StoreError::Invariant("custom CA secret version is missing"))?,
            "invalid custom CA secret version",
        )? != configuration.custom_ca_generation
        || row
            .try_get::<Option<String>, _>("ca_field_purpose")?
            .as_deref()
            != Some("custom_ca_bundle")
    {
        return Err(StoreError::Invariant(
            "custom CA protected record does not match egress policy",
        ));
    }
    Ok(Some(ProtectedSecretRecord {
        material_id,
        scope: SecretScopeRecord::System,
        owner_kind,
        owner_id,
        owner_generation,
        secret_version: configuration.custom_ca_generation,
        field_purpose: "custom_ca_bundle".to_owned(),
        provider_id: row
            .try_get::<Option<String>, _>("ca_provider_id")?
            .ok_or(StoreError::Invariant("custom CA provider is missing"))?,
        provider_format_version: u32::try_from(
            row.try_get::<Option<i32>, _>("ca_provider_format")?
                .ok_or(StoreError::Invariant("custom CA format is missing"))?,
        )
        .map_err(|_| StoreError::Invariant("invalid custom CA format"))?,
        context_version: u32::try_from(
            row.try_get::<Option<i32>, _>("ca_context_version")?
                .ok_or(StoreError::Invariant(
                    "custom CA context version is missing",
                ))?,
        )
        .map_err(|_| StoreError::Invariant("invalid custom CA context version"))?,
        envelope: row
            .try_get::<Option<Vec<u8>>, _>("ca_opaque_envelope")?
            .ok_or(StoreError::Invariant("custom CA envelope is missing"))?,
    }))
}

fn validate_network_configuration(
    configuration: &EgressNetworkConfiguration,
) -> Result<(), &'static str> {
    if !configuration.dns.revalidate_on_connect
        || configuration.dns.max_resolved_addresses == 0
        || configuration.dns.max_resolved_addresses > 32
        || !configuration.tls.verify_hostname
        || !configuration.tls.verify_certificate
        || !matches!(configuration.tls.minimum_version.as_str(), "1.2" | "1.3")
        || configuration.redirect.max_redirects != 0
        || !(100..=60_000).contains(&configuration.connection.connect_timeout_ms)
        || !(1_000..=600_000).contains(&configuration.connection.request_timeout_ms)
        || !(1_000..=600_000).contains(&configuration.connection.pool_idle_timeout_ms)
        || !(1..=256).contains(&configuration.connection.max_idle_connections_per_host)
        || !(1..=64 * 1024 * 1024).contains(&configuration.body.max_request_body_bytes)
        || !(1..=512 * 1024 * 1024).contains(&configuration.body.max_response_body_bytes)
    {
        return Err("egress_policy_unsupported_or_unsafe");
    }
    if configuration.address.allowed_cidrs.len() > 64
        || configuration.address.denied_cidrs.len() > 64
        || configuration
            .address
            .allowed_cidrs
            .iter()
            .chain(&configuration.address.denied_cidrs)
            .any(|network| network.parse::<IpNet>().is_err())
    {
        return Err("egress_address_policy_invalid");
    }
    if configuration.proxy_url.is_some() {
        return Err("egress_proxy_target_enforcement_unavailable");
    }
    Ok(())
}

async fn load_credentials(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<HashMap<CredentialId, CredentialRecord>, StoreError> {
    let rows = sqlx::query(
        "SELECT credential.id, credential.resource_scope_kind, credential.organization_id,
                credential.credential_kind, credential.secret_source_kind,
                credential.injection_kind, credential.administrative_status,
                credential.authentication_status, credential.current_secret_version,
                credential.state_identity_version,
                version.id AS version_id, version.version, version.credential_state_identity_version,
                version.protected_secret_version_id, version.source_configuration,
                version.safe_fingerprint, version.state AS version_state,
                protected.scope_kind AS protected_scope_kind,
                protected.organization_id AS protected_organization_id,
                protected.owner_kind, protected.owner_id, protected.owner_generation,
                protected.secret_version AS protected_secret_version,
                protected.field_purpose, protected.custody_provider_id,
                protected.provider_format_version, protected.context_version,
                protected.opaque_envelope
         FROM upstream_credentials credential
         LEFT JOIN upstream_credential_secret_versions version
           ON version.credential_id=credential.id
          AND version.version=credential.current_secret_version
         LEFT JOIN protected_secret_versions protected
           ON protected.id=version.protected_secret_version_id",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut credentials = HashMap::with_capacity(rows.len());
    for row in rows {
        let id = CredentialId::from_uuid(row.try_get("id")?);
        let scope: CatalogScopeKind = parse_enum(
            row.try_get("resource_scope_kind")?,
            "invalid credential scope",
        )?;
        let organization_id = row
            .try_get::<Option<Uuid>, _>("organization_id")?
            .map(OrganizationId::from_uuid);
        validate_scope(scope, organization_id, "invalid credential scope binding")?;
        let source_kind: CredentialSourceKind = parse_enum(
            row.try_get("secret_source_kind")?,
            "invalid credential source kind",
        )?;
        let state_identity_version = positive_u64(
            row.try_get("state_identity_version")?,
            "invalid credential state identity version",
        )?;
        let selected = match row.try_get::<Option<Uuid>, _>("version_id")? {
            None => None,
            Some(version_id) => {
                if row.try_get::<String, _>("version_state")? != "current"
                    || row.try_get::<i64, _>("credential_state_identity_version")?
                        != i64::try_from(state_identity_version)
                            .map_err(|_| StoreError::Invariant("credential version overflow"))?
                {
                    return Err(StoreError::Invariant(
                        "selected credential version is not current for state identity",
                    ));
                }
                let source = match source_kind {
                    CredentialSourceKind::EncryptedDatabase => CapturedSecretSource::Protected(
                        parse_protected_secret(&row, scope, organization_id, id)?,
                    ),
                    _ => CapturedSecretSource::External(
                        row.try_get::<Option<serde_json::Value>, _>("source_configuration")?
                            .ok_or(StoreError::Invariant(
                                "external credential source configuration is missing",
                            ))?,
                    ),
                };
                Some(SelectedCredentialVersion {
                    id: CredentialSecretVersionId::from_uuid(version_id),
                    version: row.try_get("version")?,
                    safe_fingerprint: digest_array(row.try_get("safe_fingerprint")?)?,
                    source,
                })
            }
        };
        if row
            .try_get::<Option<i64>, _>("current_secret_version")?
            .is_some()
            != selected.is_some()
        {
            return Err(StoreError::Invariant(
                "credential selected secret cannot be resolved",
            ));
        }
        let record = CredentialRecord {
            scope,
            organization_id,
            kind: parse_enum(row.try_get("credential_kind")?, "invalid credential kind")?,
            source_kind,
            injection_kind: parse_injection_kind(&row.try_get::<String, _>("injection_kind")?)?,
            state_identity_version,
            administrative_active: row.try_get::<String, _>("administrative_status")? == "active",
            authentication_ready: row.try_get::<String, _>("authentication_status")? == "ready",
            selected,
        };
        if credentials.insert(id, record).is_some() {
            return Err(StoreError::Invariant("duplicate upstream credential"));
        }
    }
    Ok(credentials)
}

fn parse_protected_secret(
    row: &PgRow,
    credential_scope: CatalogScopeKind,
    organization_id: Option<OrganizationId>,
    credential_id: CredentialId,
) -> Result<ProtectedSecretRecord, StoreError> {
    let material_id = row
        .try_get::<Option<Uuid>, _>("protected_secret_version_id")?
        .ok_or(StoreError::Invariant(
            "protected credential material is missing",
        ))?;
    let scope = match row
        .try_get::<Option<String>, _>("protected_scope_kind")?
        .as_deref()
    {
        Some("system") => SecretScopeRecord::System,
        Some("organization") => SecretScopeRecord::Organization(
            row.try_get::<Option<Uuid>, _>("protected_organization_id")?
                .map(OrganizationId::from_uuid)
                .ok_or(StoreError::Invariant(
                    "protected organization secret lacks organization",
                ))?,
        ),
        _ => return Err(StoreError::Invariant("invalid protected secret scope")),
    };
    let scope_matches = matches!(
        (&scope, credential_scope, organization_id),
        (
            SecretScopeRecord::System,
            CatalogScopeKind::Deployment,
            None
        )
    ) || matches!(
        (&scope, credential_scope, organization_id),
        (
            SecretScopeRecord::Organization(protected),
            CatalogScopeKind::Organization,
            Some(expected)
        ) if *protected == expected
    );
    let owner_kind = row
        .try_get::<Option<String>, _>("owner_kind")?
        .ok_or(StoreError::Invariant("protected owner kind is missing"))?;
    let owner_id = row
        .try_get::<Option<Uuid>, _>("owner_id")?
        .ok_or(StoreError::Invariant("protected owner ID is missing"))?;
    let owner_generation = positive_u64(
        row.try_get::<Option<i64>, _>("owner_generation")?
            .ok_or(StoreError::Invariant(
                "protected owner generation is missing",
            ))?,
        "invalid protected owner generation",
    )?;
    let secret_version = positive_u64(
        row.try_get::<Option<i64>, _>("protected_secret_version")?
            .ok_or(StoreError::Invariant("protected secret version is missing"))?,
        "invalid protected secret version",
    )?;
    let selected_version = positive_u64(
        row.try_get("version")?,
        "invalid selected credential version",
    )?;
    let state_identity = positive_u64(
        row.try_get("credential_state_identity_version")?,
        "invalid selected state identity",
    )?;
    let field_purpose = row
        .try_get::<Option<String>, _>("field_purpose")?
        .ok_or(StoreError::Invariant("protected field purpose is missing"))?;
    if !scope_matches
        || owner_kind != "upstream_credential"
        || owner_id != credential_id.as_uuid()
        || owner_generation != state_identity
        || secret_version != selected_version
        || field_purpose != "upstream_credential_material"
    {
        return Err(StoreError::Invariant(
            "protected credential context does not match selected version",
        ));
    }
    Ok(ProtectedSecretRecord {
        material_id,
        scope,
        owner_kind,
        owner_id,
        owner_generation,
        secret_version,
        field_purpose,
        provider_id: row
            .try_get::<Option<String>, _>("custody_provider_id")?
            .ok_or(StoreError::Invariant("custody provider ID is missing"))?,
        provider_format_version: positive_u32(
            row.try_get::<Option<i32>, _>("provider_format_version")?
                .ok_or(StoreError::Invariant("provider format version is missing"))?,
            "invalid provider format version",
        )?,
        context_version: positive_u32(
            row.try_get::<Option<i32>, _>("context_version")?
                .ok_or(StoreError::Invariant("context version is missing"))?,
            "invalid context version",
        )?,
        envelope: row
            .try_get::<Option<Vec<u8>>, _>("opaque_envelope")?
            .ok_or(StoreError::Invariant("protected envelope is missing"))?,
    })
}

async fn load_deployments(
    transaction: &mut Transaction<'_, Postgres>,
    endpoints: &HashMap<EndpointId, EndpointRecord>,
    credentials: &HashMap<CredentialId, CredentialRecord>,
    pricing_policy_versions: &HashMap<PricingPolicyVersionId, PricingPolicyVersionSnapshot>,
) -> Result<
    (
        HashMap<DeploymentId, DeploymentSnapshot>,
        HashMap<CredentialClientKey, ClientBuild>,
    ),
    StoreError,
> {
    let rows = sqlx::query(
        "SELECT id, resource_scope_kind, organization_id, endpoint_id, credential_id,
                transport_kind, upstream_model_id, capability_set, context_limits,
                state_isolation_profile, pricing_policy_version_id, unpriced, status,
                config_version
         FROM model_deployments",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut deployments = HashMap::with_capacity(rows.len());
    let mut builds = HashMap::new();
    for row in rows {
        let id = DeploymentId::from_uuid(row.try_get("id")?);
        let scope: CatalogScopeKind = parse_enum(
            row.try_get("resource_scope_kind")?,
            "invalid deployment scope",
        )?;
        let organization_id = row
            .try_get::<Option<Uuid>, _>("organization_id")?
            .map(OrganizationId::from_uuid);
        validate_scope(scope, organization_id, "invalid deployment scope binding")?;
        let endpoint_id = EndpointId::from_uuid(row.try_get("endpoint_id")?);
        let endpoint = endpoints
            .get(&endpoint_id)
            .ok_or(StoreError::Invariant("deployment endpoint is missing"))?;
        let credential_id = CredentialId::from_uuid(row.try_get("credential_id")?);
        let credential = credentials
            .get(&credential_id)
            .ok_or(StoreError::Invariant("deployment credential is missing"))?;
        if scope != credential.scope || organization_id != credential.organization_id {
            return Err(StoreError::Invariant(
                "deployment and credential scope do not match",
            ));
        }
        let transport_kind: TransportKind =
            parse_enum(row.try_get("transport_kind")?, "invalid transport kind")?;
        if !compatible_endpoint_credential_transport(
            endpoint.snapshot.adapter,
            credential.kind,
            transport_kind,
        ) {
            return Err(StoreError::Invariant(
                "unsupported endpoint credential transport tuple",
            ));
        }
        let capabilities = parse_unique_set(
            row.try_get("capability_set")?,
            "invalid deployment capability set",
        )?;
        let selected = credential.selected.as_ref();
        let mut operational = row.try_get::<String, _>("status")? == "active"
            && endpoint.snapshot.active
            && endpoint.network_active
            && credential.administrative_active
            && credential.authentication_ready
            && selected.is_some();
        let (secret_version_id, secret_version) = selected
            .map(|selected| (selected.id, selected.version))
            .unwrap_or((CredentialSecretVersionId::from_uuid(Uuid::nil()), 0));
        let pricing_policy_version_id = row
            .try_get::<Option<Uuid>, _>("pricing_policy_version_id")?
            .map(PricingPolicyVersionId::from_uuid);
        let pricing = pricing_policy_version_id
            .map(|id| {
                pricing_policy_versions
                    .get(&id)
                    .cloned()
                    .map(Arc::new)
                    .ok_or(StoreError::Invariant(
                        "deployment pricing policy version is missing",
                    ))
            })
            .transpose()?;
        if let Some(pricing) = &pricing {
            if scope == CatalogScopeKind::Organization && !pricing.organization_usable {
                return Err(StoreError::Invariant(
                    "organization deployment references a non-usable pricing version",
                ));
            }
            operational &= pricing.policy_active;
        }
        let snapshot = DeploymentSnapshot {
            id,
            scope,
            organization_id,
            endpoint_id,
            endpoint_adapter: endpoint.snapshot.adapter,
            endpoint_config_version: i64::try_from(endpoint.snapshot.config_version)
                .map_err(|_| StoreError::Invariant("endpoint config version overflow"))?,
            credential_id,
            credential_state_identity_version: credential.state_identity_version,
            credential_secret_version_id: secret_version_id,
            credential_secret_version: secret_version,
            credential_kind: credential.kind,
            transport_kind,
            upstream_model_id: nonempty(
                row.try_get("upstream_model_id")?,
                "empty upstream model ID",
            )?,
            capabilities,
            context_limits: object_column(&row, "context_limits", "invalid context limits")?,
            state_isolation_profile: object_column(
                &row,
                "state_isolation_profile",
                "invalid state isolation profile",
            )?,
            pricing_policy_version_id,
            pricing,
            config_version: positive_u64(
                row.try_get("config_version")?,
                "invalid deployment config version",
            )?,
            origin: scope.accounting_origin(),
            operational,
        };
        if row.try_get::<bool, _>("unpriced")? == snapshot.pricing_policy_version_id.is_some() {
            return Err(StoreError::Invariant(
                "invalid deployment pricing selection",
            ));
        }
        if let Some(selected) = selected {
            let key = snapshot.client_key();
            let build = ClientBuild {
                key: key.clone(),
                credential_kind: credential.kind,
                adapter: endpoint.snapshot.adapter,
                base_url: endpoint.snapshot.base_url.clone(),
                region: endpoint.snapshot.region.clone(),
                safe_headers: endpoint.snapshot.safe_headers.clone(),
                source_kind: credential.source_kind,
                injection_kind: credential.injection_kind,
                safe_fingerprint: selected.safe_fingerprint,
                source: selected.source.clone(),
                network_configuration: endpoint.network_configuration.clone(),
                custom_ca: endpoint.custom_ca.clone(),
            };
            if let Some(existing) = builds.insert(key, build) {
                if client_build_fingerprint(&existing)
                    != client_build_fingerprint(
                        builds.get(&snapshot.client_key()).expect("inserted"),
                    )
                {
                    return Err(StoreError::Invariant("credential client key is ambiguous"));
                }
            }
        }
        if deployments.insert(id, snapshot).is_some() {
            return Err(StoreError::Invariant("duplicate model deployment"));
        }
    }
    Ok((deployments, builds))
}

fn apply_deployment_grants(
    organizations: &HashMap<OrganizationId, OrganizationSnapshot>,
    deployments: &mut HashMap<DeploymentId, DeploymentSnapshot>,
) {
    for deployment in deployments.values_mut() {
        if let Some(organization_id) = deployment.organization_id {
            let organization_allows =
                organizations
                    .get(&organization_id)
                    .is_some_and(|organization| {
                        organization.active
                            && organization
                                .endpoint_grants
                                .contains(&deployment.endpoint_id)
                    });
            deployment.operational &= organization_allows;
        }
    }
}

async fn load_routes(
    transaction: &mut Transaction<'_, Postgres>,
    organizations: &HashMap<OrganizationId, OrganizationSnapshot>,
    reliability_policies: &HashMap<ReliabilityPolicyId, ReliabilityPolicySnapshot>,
    deployments: &HashMap<DeploymentId, DeploymentSnapshot>,
) -> Result<HashMap<RouteId, RouteSnapshot>, StoreError> {
    let rows = sqlx::query(
        "SELECT route.id, route.resource_scope_kind, route.organization_id,
                route.owner_user_id, route.owner_membership_id, route.model_key,
                route.ingress_protocol_family, route.required_base_capabilities,
                route.selection_policy, route.reliability_policy_id, route.request_policy,
                route.status, route.config_version,
                CASE WHEN route.resource_scope_kind='deployment' THEN true ELSE EXISTS(
                    SELECT 1 FROM memberships membership
                    WHERE membership.id=route.owner_membership_id
                      AND membership.organization_id=route.organization_id
                      AND membership.user_id=route.owner_user_id
                      AND membership.status='active'
                ) END AS owner_active
         FROM model_routes route",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let target_rows = sqlx::query(
        "SELECT id, route_id, deployment_id, affinity_identity, priority, weight,
                narrowing_constraints, timeout_overrides
         FROM route_targets WHERE enabled=true
         ORDER BY route_id, priority, id",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut targets: HashMap<RouteId, Vec<TargetSnapshot>> = HashMap::new();
    for row in target_rows {
        let route_id = RouteId::from_uuid(row.try_get("route_id")?);
        let affinity: [u8; 16] = row
            .try_get::<Vec<u8>, _>("affinity_identity")?
            .try_into()
            .map_err(|_| StoreError::Invariant("invalid target affinity identity"))?;
        let narrowing_constraints: crate::domain::TargetNarrowingConstraints = typed_column(
            &row,
            "narrowing_constraints",
            "invalid target narrowing constraints",
        )?;
        let timeout_overrides: crate::domain::TargetTimeoutOverrides = typed_column(
            &row,
            "timeout_overrides",
            "invalid target timeout overrides",
        )?;
        if !narrowing_constraints.is_valid() || !timeout_overrides.is_valid() {
            return Err(StoreError::Invariant(
                "target narrowing constraints or timeout overrides are invalid",
            ));
        }
        targets.entry(route_id).or_default().push(TargetSnapshot {
            id: TargetId::from_uuid(row.try_get("id")?),
            deployment_id: DeploymentId::from_uuid(row.try_get("deployment_id")?),
            affinity_identity: affinity,
            priority: u8::try_from(row.try_get::<i16, _>("priority")?)
                .map_err(|_| StoreError::Invariant("invalid target priority"))?,
            weight: u16::try_from(row.try_get::<i16, _>("weight")?)
                .map_err(|_| StoreError::Invariant("invalid target weight"))?,
            narrowing_constraints,
            timeout_overrides,
        });
    }

    let mut routes = HashMap::with_capacity(rows.len());
    let mut namespaces = BTreeSet::new();
    for row in rows {
        let id = RouteId::from_uuid(row.try_get("id")?);
        let scope: CatalogScopeKind =
            parse_enum(row.try_get("resource_scope_kind")?, "invalid route scope")?;
        let organization_id = row
            .try_get::<Option<Uuid>, _>("organization_id")?
            .map(OrganizationId::from_uuid);
        validate_scope(scope, organization_id, "invalid route scope binding")?;
        let ingress: IngressProtocolFamily = parse_enum(
            row.try_get("ingress_protocol_family")?,
            "invalid ingress protocol family",
        )?;
        let model_key = nonempty(row.try_get("model_key")?, "empty route model key")?;
        if !namespaces.insert((organization_id, ingress, model_key.clone())) {
            return Err(StoreError::Invariant("duplicate route namespace"));
        }
        let reliability_policy_id =
            ReliabilityPolicyId::from_uuid(row.try_get("reliability_policy_id")?);
        let reliability = reliability_policies
            .get(&reliability_policy_id)
            .ok_or(StoreError::Invariant("route reliability policy is missing"))?;
        let required_capabilities = parse_unique_set(
            row.try_get("required_base_capabilities")?,
            "invalid route required capability set",
        )?;
        let route_status: String = row.try_get("status")?;
        if route_status == "draft" {
            targets.remove(&id);
            continue;
        }
        let mut route_targets = targets.remove(&id).unwrap_or_default();
        validate_target_tiers(&route_targets)?;
        for target in &route_targets {
            let deployment = deployments
                .get(&target.deployment_id)
                .ok_or(StoreError::Invariant("route target deployment is missing"))?;
            if compatibility(
                ingress,
                deployment.endpoint_adapter,
                deployment.credential_kind,
                deployment.transport_kind,
            )
            .is_none()
            {
                return Err(StoreError::Invariant(
                    "route target compatibility tuple is unsupported",
                ));
            }
            if !deployment.capabilities.is_superset(&required_capabilities) {
                return Err(StoreError::Invariant(
                    "route target lacks required base capabilities",
                ));
            }
            match (scope, deployment.scope) {
                (
                    CatalogScopeKind::Deployment | CatalogScopeKind::Organization,
                    CatalogScopeKind::Deployment,
                ) => {}
                (CatalogScopeKind::Organization, CatalogScopeKind::Organization)
                    if organization_id == deployment.organization_id => {}
                _ => {
                    return Err(StoreError::Invariant("route target is outside route scope"));
                }
            }
        }
        let mut active = route_status == "active"
            && reliability.active
            && row.try_get::<bool, _>("owner_active")?;
        if let Some(organization_id) = organization_id {
            let organization = organizations
                .get(&organization_id)
                .ok_or(StoreError::Invariant("route organization is missing"))?;
            active &= organization.active
                && organization
                    .reliability_policy_grants
                    .contains(&reliability_policy_id);
            route_targets.retain(|target| {
                deployments
                    .get(&target.deployment_id)
                    .is_some_and(|deployment| {
                        deployment.scope == CatalogScopeKind::Organization
                            || organization.deployment_grants.contains(&deployment.id)
                    })
            });
        }
        active &= route_targets.iter().any(|target| {
            deployments
                .get(&target.deployment_id)
                .is_some_and(|deployment| deployment.operational)
        });
        let selection_policy: crate::domain::RouteSelectionPolicy =
            typed_column(&row, "selection_policy", "invalid route selection policy")?;
        let request_policy: crate::domain::RouteRequestPolicy =
            typed_column(&row, "request_policy", "invalid request policy")?;
        if !selection_policy.is_valid() || !request_policy.is_valid() {
            return Err(StoreError::Invariant("invalid route policy semantics"));
        }
        let route = RouteSnapshot {
            id,
            scope,
            organization_id,
            owner_user_id: row
                .try_get::<Option<Uuid>, _>("owner_user_id")?
                .map(UserId::from_uuid),
            owner_membership_id: row.try_get("owner_membership_id")?,
            model_key,
            ingress_protocol_family: ingress,
            required_base_capabilities: required_capabilities,
            selection_policy,
            reliability_policy_id,
            request_policy,
            config_version: positive_u64(
                row.try_get("config_version")?,
                "invalid route config version",
            )?,
            active,
            targets: route_targets,
        };
        if routes.insert(id, route).is_some() {
            return Err(StoreError::Invariant("duplicate model route"));
        }
    }
    if !targets.is_empty() {
        return Err(StoreError::Invariant("target references unknown route"));
    }
    Ok(routes)
}

async fn load_gateway_keys(
    transaction: &mut Transaction<'_, Postgres>,
    organizations: &HashMap<OrganizationId, OrganizationSnapshot>,
    key_budgets: &HashMap<BudgetPolicyId, BudgetPolicySnapshot>,
    rate_policies: &HashMap<RatePolicyId, RatePolicySnapshot>,
    routes: &HashMap<RouteId, RouteSnapshot>,
) -> Result<HashMap<String, GatewayKeyVerifier>, StoreError> {
    let route_rows = sqlx::query(
        "SELECT gateway_api_key_id, organization_id, route_id FROM gateway_api_key_routes",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut key_routes: HashMap<GatewayKeyId, BTreeSet<RouteId>> = HashMap::new();
    let mut key_route_organizations: HashMap<GatewayKeyId, OrganizationId> = HashMap::new();
    for row in route_rows {
        let key_id = GatewayKeyId::from_uuid(row.try_get("gateway_api_key_id")?);
        let organization_id = OrganizationId::from_uuid(row.try_get("organization_id")?);
        let route_id = RouteId::from_uuid(row.try_get("route_id")?);
        let route = routes
            .get(&route_id)
            .ok_or(StoreError::Invariant("gateway key route is missing"))?;
        let organization = organizations
            .get(&organization_id)
            .ok_or(StoreError::Invariant("gateway key organization is missing"))?;
        if route.scope == CatalogScopeKind::Organization
            && route.organization_id != Some(organization_id)
        {
            return Err(StoreError::Invariant(
                "gateway key route belongs to another organization",
            ));
        }
        let visible = route.organization_id == Some(organization_id)
            || (route.scope == CatalogScopeKind::Deployment
                && organization.system_route_grants.contains_key(&route_id));
        if key_route_organizations
            .insert(key_id, organization_id)
            .is_some_and(|existing| existing != organization_id)
        {
            return Err(StoreError::Invariant(
                "gateway key routes cross organizations",
            ));
        }
        if visible {
            key_routes.entry(key_id).or_default().insert(route_id);
        }
    }

    let rows = sqlx::query(
        "SELECT key.id, key.organization_id, key.issuance_policy_class, key.scopes,
                key.budget_policy_id, key.rate_policy_id, key.status, key.expires_at,
                secret.lookup_id, secret.secret_digest, secret.state, secret.overlap_until
         FROM gateway_api_keys key
         LEFT JOIN gateway_api_key_secret_versions secret
           ON secret.gateway_api_key_id=key.id AND secret.state IN ('current','overlap')
         ORDER BY key.id, secret.state",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut grouped: HashMap<GatewayKeyId, Vec<PgRow>> = HashMap::new();
    for row in rows {
        grouped
            .entry(GatewayKeyId::from_uuid(row.try_get("id")?))
            .or_default()
            .push(row);
    }
    let mut index = HashMap::new();
    for (key_id, rows) in grouped {
        let first = rows
            .first()
            .ok_or(StoreError::Invariant("gateway key row is missing"))?;
        let organization_id = OrganizationId::from_uuid(first.try_get("organization_id")?);
        let organization = organizations
            .get(&organization_id)
            .ok_or(StoreError::Invariant("gateway key organization is missing"))?;
        let status: String = first.try_get("status")?;
        let issuance_policy_class: String = first.try_get("issuance_policy_class")?;
        let global_policy = gateway_policy_section(&organization.api_key_policy, "standard")?;
        let class_policy =
            gateway_policy_section(&organization.api_key_policy, &issuance_policy_class)?;
        let global_enabled = gateway_policy_enabled(global_policy)?;
        let class_enabled = gateway_policy_enabled(class_policy)?;
        let global_scopes = gateway_policy_scopes(global_policy)?;
        let class_scopes = gateway_policy_scopes(class_policy)?;
        let policy_scopes = global_scopes.as_scopes().and_then(|global| {
            class_scopes
                .as_scopes()
                .and_then(|class| global.intersection(class))
        });
        let global_capabilities = gateway_policy_capabilities(global_policy)?;
        let class_capabilities = gateway_policy_capabilities(class_policy)?;
        let capabilities = global_capabilities
            .intersection(&class_capabilities)
            .copied()
            .collect::<BTreeSet<_>>();
        let global_routes = gateway_policy_routes(global_policy)?;
        let class_routes = gateway_policy_routes(class_policy)?;
        let policy_routes = global_routes
            .intersection(&class_routes)
            .copied()
            .collect::<BTreeSet<_>>();
        let current = rows.iter().find(|row| {
            row.try_get::<Option<String>, _>("state")
                .ok()
                .flatten()
                .as_deref()
                == Some("current")
        });
        let visible_route_ids = key_routes.remove(&key_id).unwrap_or_default();
        if status == "active" && current.is_none() {
            return Err(StoreError::Invariant(
                "active gateway key has no current secret",
            ));
        }
        let Some(current) = current else {
            continue;
        };
        let route_ids = visible_route_ids
            .intersection(&policy_routes)
            .copied()
            .collect::<BTreeSet<_>>();
        let budget_policy_id = BudgetPolicyId::from_uuid(first.try_get("budget_policy_id")?);
        if !key_budgets.contains_key(&budget_policy_id) {
            return Err(StoreError::Invariant(
                "gateway key budget policy is missing",
            ));
        }
        let rate_policy_id = first
            .try_get::<Option<Uuid>, _>("rate_policy_id")?
            .map(RatePolicyId::from_uuid);
        if rate_policy_id.is_some_and(|id| !rate_policies.contains_key(&id)) {
            return Err(StoreError::Invariant("gateway key rate policy is missing"));
        }
        let overlap = rows.iter().find(|row| {
            row.try_get::<Option<String>, _>("state")
                .ok()
                .flatten()
                .as_deref()
                == Some("overlap")
        });
        let stored_scopes = serde_json::from_value::<LlmScopeSet>(first.try_get("scopes")?)
            .map_err(|_| StoreError::Invariant("invalid gateway key scopes"))?;
        let effective_scopes = policy_scopes
            .as_ref()
            .and_then(|ceiling| stored_scopes.intersection(ceiling));
        let active = status == "active"
            && organization.active
            && global_enabled
            && class_enabled
            && effective_scopes.is_some()
            && !route_ids.is_empty();
        let verifier = GatewayKeyVerifier {
            key_id,
            organization_id,
            scopes: effective_scopes,
            capabilities,
            route_ids,
            budget_policy_id,
            rate_policy_id,
            current_digest: digest_array(current.try_get("secret_digest")?)?,
            overlap_digest: overlap
                .map(|row| digest_array(row.try_get("secret_digest")?))
                .transpose()?,
            overlap_until: overlap
                .map(|row| row.try_get("overlap_until"))
                .transpose()?
                .flatten(),
            expires_at: first.try_get("expires_at")?,
            active,
        };
        index.insert(current.try_get("lookup_id")?, verifier.clone());
        if let Some(overlap) = overlap {
            index.insert(overlap.try_get("lookup_id")?, verifier);
        }
    }
    if !key_routes.is_empty() {
        return Err(StoreError::Invariant(
            "gateway key route references unknown key",
        ));
    }
    Ok(index)
}

fn gateway_policy_section<'a>(
    policy: &'a serde_json::Value,
    issuance_policy_class: &str,
) -> Result<&'a serde_json::Map<String, serde_json::Value>, StoreError> {
    let section = match issuance_policy_class {
        "standard" => "gateway",
        "member_self_service" => "gateway_member_self_service",
        _ => {
            return Err(StoreError::Invariant(
                "unknown gateway key issuance policy class",
            ));
        }
    };
    policy
        .get(section)
        .and_then(serde_json::Value::as_object)
        .ok_or(StoreError::Invariant(
            "gateway API key policy section is missing",
        ))
}

fn gateway_policy_enabled(
    section: &serde_json::Map<String, serde_json::Value>,
) -> Result<bool, StoreError> {
    section
        .get("enabled")
        .and_then(serde_json::Value::as_bool)
        .ok_or(StoreError::Invariant(
            "gateway key policy enabled flag is missing",
        ))
}

fn gateway_policy_scopes(
    section: &serde_json::Map<String, serde_json::Value>,
) -> Result<crate::domain::LlmScopeCeiling, StoreError> {
    serde_json::from_value(
        section
            .get("allowed_scopes")
            .cloned()
            .ok_or(StoreError::Invariant(
                "gateway policy scope ceiling is missing",
            ))?,
    )
    .map_err(|_| StoreError::Invariant("invalid gateway policy scope ceiling"))
}

fn gateway_policy_capabilities(
    section: &serde_json::Map<String, serde_json::Value>,
) -> Result<BTreeSet<LlmFeatureCapability>, StoreError> {
    let values = serde_json::from_value::<Vec<LlmFeatureCapability>>(
        section
            .get("allowed_capabilities")
            .cloned()
            .ok_or(StoreError::Invariant(
                "gateway policy capability ceiling is missing",
            ))?,
    )
    .map_err(|_| StoreError::Invariant("invalid gateway policy capability ceiling"))?;
    let capabilities = values.iter().copied().collect::<BTreeSet<_>>();
    if capabilities.len() != values.len() {
        return Err(StoreError::Invariant(
            "duplicate gateway policy capability ceiling",
        ));
    }
    Ok(capabilities)
}

fn gateway_policy_routes(
    section: &serde_json::Map<String, serde_json::Value>,
) -> Result<BTreeSet<RouteId>, StoreError> {
    parse_route_id_set(
        section
            .get("allowed_route_ids")
            .cloned()
            .ok_or(StoreError::Invariant(
                "gateway policy route ceiling is missing",
            ))?,
    )
}

fn parse_route_id_set(value: serde_json::Value) -> Result<BTreeSet<RouteId>, StoreError> {
    let values = serde_json::from_value::<Vec<Uuid>>(value)
        .map_err(|_| StoreError::Invariant("invalid gateway policy route ceiling"))?;
    let routes = values
        .iter()
        .copied()
        .map(RouteId::from_uuid)
        .collect::<BTreeSet<_>>();
    if routes.len() != values.len() {
        return Err(StoreError::Invariant(
            "duplicate gateway policy route ceiling",
        ));
    }
    Ok(routes)
}

pub(crate) fn generation_http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().no_proxy()
}

async fn build_client(
    build: &ClientBuild,
    installation_id: Uuid,
    secrets: &SecretService,
    build_fingerprint: [u8; 32],
    egress_dns_overrides: &HashMap<String, SocketAddr>,
) -> Result<CredentialClient, &'static str> {
    validate_network_configuration(&build.network_configuration)?;
    validate_endpoint_for_network_policy(&build.base_url, &build.network_configuration)?;
    validate_default_chain_source_contract(
        build.credential_kind,
        build.source_kind,
        &build.source,
    )?;
    let plaintext = match (&build.source_kind, &build.source) {
        (CredentialSourceKind::EncryptedDatabase, CapturedSecretSource::Protected(record)) => {
            Some(open_protected(record, installation_id, secrets).await?)
        }
        (
            CredentialSourceKind::EnvironmentReference,
            CapturedSecretSource::External(configuration),
        ) => Some(read_environment(configuration)?),
        (
            CredentialSourceKind::MountedFileReference,
            CapturedSecretSource::External(configuration),
        ) => Some(read_mounted_file(configuration)?),
        (CredentialSourceKind::WorkloadIdentity, CapturedSecretSource::External(configuration)) => {
            validate_workload_configuration(configuration)?;
            None
        }
        _ => return Err("credential_source_mismatch"),
    };
    let headers = build_default_headers(&build.safe_headers)?;
    let policy = &build.network_configuration;
    let resolver = EgressResolver::new(policy, egress_dns_overrides)?;
    let custom_ca = if let Some(custom_ca) = &build.custom_ca {
        let pem = open_protected(custom_ca, installation_id, secrets)
            .await
            .map_err(|_| "custom_ca_open_failed")?;
        Some(
            pem.expose(reqwest::Certificate::from_pem)
                .map_err(|_| "custom_ca_bundle_invalid")?,
        )
    } else {
        None
    };
    if policy.proxy_url.is_some() {
        return Err("egress_proxy_target_enforcement_unavailable");
    }
    let endpoint_connect_timeout_ms = u64::from(policy.connection.connect_timeout_ms);
    let http = build_http_client(
        policy,
        &headers,
        &resolver,
        custom_ca.as_ref(),
        endpoint_connect_timeout_ms,
        policy.connection.max_idle_connections_per_host,
    )?;
    let (injection, dynamic_secret) = build_injection(build, plaintext, &http)?;
    Ok(CredentialClient {
        key: build.key.clone(),
        base_url: build.base_url.clone(),
        adapter: build.adapter,
        http,
        endpoint_connect_timeout_ms,
        max_request_body_bytes: policy.body.max_request_body_bytes,
        max_response_body_bytes: policy.body.max_response_body_bytes,
        injection,
        dynamic_secret,
        build_fingerprint,
    })
}

fn build_http_client(
    policy: &EgressNetworkConfiguration,
    headers: &HeaderMap,
    resolver: &EgressResolver,
    custom_ca: Option<&reqwest::Certificate>,
    connect_timeout_ms: u64,
    max_idle_connections_per_host: usize,
) -> Result<reqwest::Client, &'static str> {
    let mut builder = generation_http_client_builder()
        .default_headers(headers.clone())
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_millis(connect_timeout_ms))
        .connector_layer(AttemptConnectTimeoutLayer)
        .timeout(Duration::from_millis(u64::from(
            policy.connection.request_timeout_ms,
        )))
        .pool_idle_timeout(Duration::from_millis(u64::from(
            policy.connection.pool_idle_timeout_ms,
        )))
        .pool_max_idle_per_host(max_idle_connections_per_host)
        .dns_resolver(resolver.clone())
        .min_tls_version(match policy.tls.minimum_version.as_str() {
            "1.3" => reqwest::tls::Version::TLS_1_3,
            _ => reqwest::tls::Version::TLS_1_2,
        });
    if let Some(custom_ca) = custom_ca {
        builder = builder.add_root_certificate(custom_ca.clone());
    }
    builder
        .build()
        .map_err(|_| "credential_client_build_failed")
}

#[derive(Clone)]
struct EgressResolver {
    allowed_cidrs: Arc<Vec<IpNet>>,
    denied_cidrs: Arc<Vec<IpNet>>,
    address_policy: crate::domain::EgressAddressPolicy,
    max_resolved_addresses: usize,
    overrides: Arc<HashMap<String, SocketAddr>>,
}

impl EgressResolver {
    fn new(
        configuration: &EgressNetworkConfiguration,
        overrides: &HashMap<String, SocketAddr>,
    ) -> Result<Self, &'static str> {
        Ok(Self {
            allowed_cidrs: Arc::new(
                configuration
                    .address
                    .allowed_cidrs
                    .iter()
                    .map(|network| network.parse().map_err(|_| "egress_policy_invalid"))
                    .collect::<Result<_, _>>()?,
            ),
            denied_cidrs: Arc::new(
                configuration
                    .address
                    .denied_cidrs
                    .iter()
                    .map(|network| network.parse().map_err(|_| "egress_policy_invalid"))
                    .collect::<Result<_, _>>()?,
            ),
            address_policy: configuration.address.clone(),
            max_resolved_addresses: usize::from(configuration.dns.max_resolved_addresses),
            overrides: Arc::new(overrides.clone()),
        })
    }

    fn allows(&self, address: IpAddr) -> bool {
        if self
            .denied_cidrs
            .iter()
            .any(|network| network.contains(&address))
        {
            return false;
        }
        if self
            .allowed_cidrs
            .iter()
            .any(|network| network.contains(&address))
        {
            return true;
        }
        classify_address(address).is_allowed(&self.address_policy)
    }
}

impl Resolve for EgressResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let resolver = self.clone();
        Box::pin(async move {
            let addresses = match resolver.overrides.get(&host.to_ascii_lowercase()) {
                Some(address) => BTreeSet::from([*address]),
                None => tokio::net::lookup_host((host.as_str(), 0))
                    .await?
                    .collect::<BTreeSet<_>>(),
            };
            if addresses.is_empty()
                || addresses.len() > resolver.max_resolved_addresses
                || addresses
                    .iter()
                    .any(|address| !resolver.allows(address.ip()))
            {
                return Err::<Addrs, _>("egress address policy rejected resolution".into());
            }
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AddressClass {
    Public,
    Private,
    Loopback,
    LinkLocal,
    Metadata,
    Prohibited,
}

impl AddressClass {
    const fn is_allowed(self, policy: &crate::domain::EgressAddressPolicy) -> bool {
        match self {
            Self::Public => true,
            Self::Private => policy.allow_private,
            Self::Loopback => policy.allow_loopback,
            Self::LinkLocal => policy.allow_link_local,
            Self::Metadata => policy.allow_metadata,
            Self::Prohibited => false,
        }
    }
}

fn classify_address(address: IpAddr) -> AddressClass {
    if METADATA_NETWORKS
        .iter()
        .any(|network| network.contains(&address))
    {
        AddressClass::Metadata
    } else if LOOPBACK_NETWORKS
        .iter()
        .any(|network| network.contains(&address))
    {
        AddressClass::Loopback
    } else if LINK_LOCAL_NETWORKS
        .iter()
        .any(|network| network.contains(&address))
    {
        AddressClass::LinkLocal
    } else if PRIVATE_NETWORKS
        .iter()
        .any(|network| network.contains(&address))
    {
        AddressClass::Private
    } else if PROHIBITED_NETWORKS
        .iter()
        .any(|network| network.contains(&address))
    {
        AddressClass::Prohibited
    } else {
        AddressClass::Public
    }
}

fn network_set(values: &[&str]) -> Vec<IpNet> {
    values
        .iter()
        .map(|network| network.parse().expect("static egress network is valid"))
        .collect()
}

static METADATA_NETWORKS: LazyLock<Vec<IpNet>> =
    LazyLock::new(|| network_set(&["169.254.169.254/32", "fd00:ec2::254/128"]));
static LOOPBACK_NETWORKS: LazyLock<Vec<IpNet>> =
    LazyLock::new(|| network_set(&["127.0.0.0/8", "::1/128"]));
static LINK_LOCAL_NETWORKS: LazyLock<Vec<IpNet>> =
    LazyLock::new(|| network_set(&["169.254.0.0/16", "fe80::/10"]));
static PRIVATE_NETWORKS: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    network_set(&[
        "10.0.0.0/8",
        "100.64.0.0/10",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    ])
});
static PROHIBITED_NETWORKS: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    network_set(&[
        "0.0.0.0/8",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/32",
        "2001:2::/48",
        "2001:10::/28",
        "2001:db8::/32",
        "2002::/16",
        "3ffe::/16",
        "ff00::/8",
    ])
});

fn validate_endpoint_for_network_policy(
    endpoint: &url::Url,
    configuration: &EgressNetworkConfiguration,
) -> Result<(), &'static str> {
    if endpoint.scheme() != "https"
        || endpoint.host().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
    {
        return Err("endpoint_url_unsafe");
    }
    if let Some(host) = endpoint.host_str() {
        if host.eq_ignore_ascii_case("localhost")
            || host.to_ascii_lowercase().ends_with(".localhost")
        {
            return Err("endpoint_url_unsafe");
        }
        if let Ok(address) = host.parse::<IpAddr>() {
            let resolver = EgressResolver::new(configuration, &HashMap::new())?;
            if !resolver.allows(address) {
                return Err("endpoint_address_prohibited");
            }
        }
    }
    Ok(())
}

fn build_injection(
    build: &ClientBuild,
    plaintext: Option<SecretPlaintext>,
    http: &reqwest::Client,
) -> Result<(CredentialInjection, Option<SecretPlaintext>), &'static str> {
    if build.credential_kind == CredentialKind::OauthOpenaiCodex {
        if build.adapter != EndpointAdapterKind::OpenaiCodex
            || build.key.transport_kind != TransportKind::OpenaiCodexResponses
        {
            return Err("codex_transport_mismatch");
        }
        let plaintext = plaintext.ok_or("credential_material_missing")?;
        let material = plaintext
            .expose(|bytes| {
                serde_json::from_slice::<crate::adapters::provider::codex::TokenMaterial>(bytes)
            })
            .map_err(|_| "codex_token_material_invalid")?;
        let account_id =
            crate::adapters::provider::codex::account_id_from_token_material(&material)
                .map_err(|_| "codex_token_material_invalid")?;
        let authorization = HeaderValue::from_str(&format!("Bearer {}", material.access_token))
            .map_err(|_| "codex_token_material_invalid")?;
        let account_id =
            HeaderValue::from_str(&account_id).map_err(|_| "codex_account_id_invalid")?;
        return Ok((
            CredentialInjection::Codex {
                authorization,
                account_id,
            },
            None,
        ));
    }
    match build.injection_kind {
        InjectionKind::Bearer => {
            let plaintext = plaintext.ok_or("credential_material_missing")?;
            let value = plaintext
                .expose(HeaderValue::from_bytes)
                .map_err(|_| "credential_material_invalid")?;
            Ok((CredentialInjection::Bearer(value), None))
        }
        InjectionKind::XApiKey => {
            let plaintext = plaintext.ok_or("credential_material_missing")?;
            let value = plaintext
                .expose(HeaderValue::from_bytes)
                .map_err(|_| "credential_material_invalid")?;
            Ok((CredentialInjection::XApiKey(value), None))
        }
        InjectionKind::ApiKeyHeader => {
            let plaintext = plaintext.ok_or("credential_material_missing")?;
            let value = plaintext
                .expose(HeaderValue::from_bytes)
                .map_err(|_| "credential_material_invalid")?;
            Ok((CredentialInjection::ApiKeyHeader(value), None))
        }
        InjectionKind::AwsSigV4 | InjectionKind::GoogleOauth | InjectionKind::AzureBearer => {
            let workload_configuration = match &build.source {
                CapturedSecretSource::External(configuration)
                    if build.source_kind == CredentialSourceKind::WorkloadIdentity =>
                {
                    Some(configuration)
                }
                _ => None,
            };
            let authenticator = crate::adapters::provider::auth::ProviderAuthenticator::build(
                build.credential_kind,
                build.region.as_deref(),
                workload_configuration,
                plaintext,
                http.clone(),
            )
            .map_err(|_| "dynamic_credential_configuration_invalid")?;
            Ok((CredentialInjection::Dynamic(Arc::new(authenticator)), None))
        }
    }
}

async fn open_protected(
    record: &ProtectedSecretRecord,
    installation_id: Uuid,
    secrets: &SecretService,
) -> Result<SecretPlaintext, &'static str> {
    if record.context_version != 1 {
        return Err("credential_context_version_unsupported");
    }
    let scope = match record.scope {
        SecretScopeRecord::System => SecretScope::System,
        SecretScopeRecord::Organization(id) => SecretScope::Organization(
            SecretOrganizationId::new(id.to_string()).map_err(|_| "credential_context_invalid")?,
        ),
    };
    let context = ProtectionContext::new(ProtectionContextParts {
        version: ContextVersion::V1,
        installation_id: InstallationId::new(installation_id.to_string())
            .map_err(|_| "credential_context_invalid")?,
        scope,
        material_id: MaterialId::new(record.material_id.to_string())
            .map_err(|_| "credential_context_invalid")?,
        owner_kind: OwnerKind::new(record.owner_kind.clone())
            .map_err(|_| "credential_context_invalid")?,
        owner_id: OwnerId::new(record.owner_id.to_string())
            .map_err(|_| "credential_context_invalid")?,
        owner_generation: record.owner_generation,
        secret_version: record.secret_version,
        field_purpose: FieldPurpose::new(record.field_purpose.clone())
            .map_err(|_| "credential_context_invalid")?,
        provider_id: ProviderId::new(record.provider_id.clone())
            .map_err(|_| "credential_context_invalid")?,
        provider_format_version: ProviderFormatVersion::new(record.provider_format_version)
            .map_err(|_| "credential_context_invalid")?,
    })
    .map_err(|_| "credential_context_invalid")?;
    let envelope =
        OpaqueEnvelope::new(record.envelope.clone()).map_err(|_| "credential_envelope_invalid")?;
    secrets
        .open(&context, &envelope)
        .await
        .map_err(|_| "credential_open_failed")
}

fn read_environment(configuration: &serde_json::Value) -> Result<SecretPlaintext, &'static str> {
    let name = exact_string_field(configuration, "environment_variable")?;
    if name.len() > MAX_ENVIRONMENT_NAME_LEN
        || !name.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_uppercase() || (index > 0 && byte.is_ascii_digit())
        })
    {
        return Err("credential_source_configuration_invalid");
    }
    let value = std::env::var(name).map_err(|_| "credential_source_unavailable")?;
    SecretPlaintext::new(value.into_bytes()).map_err(|_| "credential_material_invalid")
}

fn read_mounted_file(configuration: &serde_json::Value) -> Result<SecretPlaintext, &'static str> {
    let path = exact_string_field(configuration, "path")?;
    if path.len() > MAX_SOURCE_PATH_LEN || !Path::new(path).is_absolute() {
        return Err("credential_source_configuration_invalid");
    }
    let metadata = std::fs::metadata(path).map_err(|_| "credential_source_unavailable")?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > SecretPlaintext::MAX_LEN as u64
    {
        return Err("credential_material_invalid");
    }
    let value = std::fs::read(path).map_err(|_| "credential_source_unavailable")?;
    SecretPlaintext::new(value).map_err(|_| "credential_material_invalid")
}

fn validate_default_chain_source_contract(
    credential_kind: CredentialKind,
    source_kind: CredentialSourceKind,
    source: &CapturedSecretSource,
) -> Result<(), &'static str> {
    let exact_empty_workload = matches!(
        (&source_kind, source),
        (
            CredentialSourceKind::WorkloadIdentity,
            CapturedSecretSource::External(configuration)
        ) if configuration
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
    );
    match credential_kind {
        CredentialKind::AwsDefaultChain | CredentialKind::GoogleApplicationDefault
            if exact_empty_workload =>
        {
            Ok(())
        }
        CredentialKind::AwsDefaultChain | CredentialKind::GoogleApplicationDefault => {
            Err("default_cloud_chain_source_contract_invalid")
        }
        _ => Ok(()),
    }
}

fn validate_workload_configuration(configuration: &serde_json::Value) -> Result<(), &'static str> {
    let object = configuration
        .as_object()
        .ok_or("credential_source_configuration_invalid")?;
    if object.len() > 16
        || object
            .iter()
            .any(|(key, value)| key.is_empty() || key.len() > 128 || !value.is_string())
    {
        return Err("credential_source_configuration_invalid");
    }
    Ok(())
}

fn exact_string_field<'a>(
    configuration: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, &'static str> {
    let object = configuration
        .as_object()
        .ok_or("credential_source_configuration_invalid")?;
    if object.len() != 1 {
        return Err("credential_source_configuration_invalid");
    }
    object
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("credential_source_configuration_invalid")
}

fn build_default_headers(headers: &HashMap<String, String>) -> Result<HeaderMap, &'static str> {
    let mut values = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        let name =
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| "endpoint_safe_header_invalid")?;
        let value = HeaderValue::from_str(value).map_err(|_| "endpoint_safe_header_invalid")?;
        values.insert(name, value);
    }
    Ok(values)
}

fn client_build_fingerprint(build: &ClientBuild) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"owlrora/runtime-credential-client-build/v1\0");
    digest.update(build.key.credential_id.as_uuid().as_bytes());
    digest.update(build.key.secret_version.to_be_bytes());
    digest.update(build.key.endpoint_id.as_uuid().as_bytes());
    digest.update(build.key.endpoint_config_version.to_be_bytes());
    digest.update(
        serde_json::to_vec(&build.key.transport_kind)
            .expect("closed transport kind serializes canonically"),
    );
    digest.update(build.credential_kind.as_str().as_bytes());
    digest.update(build.safe_fingerprint);
    digest.update(build.base_url.as_str().as_bytes());
    if let Some(region) = &build.region {
        digest.update(region.as_bytes());
    }
    let canonical_headers = build
        .safe_headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<BTreeMap<_, _>>();
    digest.update(
        serde_json::to_vec(&canonical_headers)
            .expect("sorted safe headers serialize canonically for an in-memory fingerprint"),
    );
    digest.update(
        serde_json::to_vec(&build.network_configuration)
            .expect("network configuration serializes canonically for an in-memory fingerprint"),
    );
    if let Some(custom_ca) = &build.custom_ca {
        digest.update(custom_ca.material_id.as_bytes());
        digest.update(custom_ca.owner_generation.to_be_bytes());
        digest.update(Sha256::digest(&custom_ca.envelope));
    }
    match &build.source {
        CapturedSecretSource::Protected(record) => {
            digest.update(record.material_id.as_bytes());
            digest.update(record.owner_generation.to_be_bytes());
            digest.update(record.secret_version.to_be_bytes());
            digest.update(Sha256::digest(&record.envelope));
        }
        CapturedSecretSource::External(configuration) => {
            digest.update(
                serde_json::to_vec(configuration)
                    .expect("source configuration serializes for an in-memory fingerprint"),
            );
        }
    }
    digest.finalize().into()
}

fn parse_endpoint_url(value: &str) -> Result<url::Url, StoreError> {
    let url = value
        .parse::<url::Url>()
        .map_err(|_| StoreError::Invariant("invalid endpoint base URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(StoreError::Invariant("invalid endpoint base URL"));
    }
    Ok(url)
}

fn parse_safe_headers(value: serde_json::Value) -> Result<HashMap<String, String>, StoreError> {
    let object = value
        .as_object()
        .ok_or(StoreError::Invariant("invalid endpoint safe headers"))?;
    if object.len() > 32 {
        return Err(StoreError::Invariant("too many endpoint safe headers"));
    }
    let mut headers = HashMap::with_capacity(object.len());
    for (name, value) in object {
        let normalized = name.to_ascii_lowercase();
        if matches!(
            normalized.as_str(),
            "authorization"
                | "proxy-authorization"
                | "x-api-key"
                | "api-key"
                | "x-goog-api-key"
                | "host"
                | "content-length"
                | "transfer-encoding"
                | "connection"
        ) {
            return Err(StoreError::Invariant(
                "endpoint safe headers contain a reserved header",
            ));
        }
        HeaderName::from_bytes(normalized.as_bytes())
            .map_err(|_| StoreError::Invariant("invalid endpoint safe header name"))?;
        let value = value
            .as_str()
            .ok_or(StoreError::Invariant("invalid endpoint safe header value"))?;
        HeaderValue::from_str(value)
            .map_err(|_| StoreError::Invariant("invalid endpoint safe header value"))?;
        headers.insert(normalized, value.to_owned());
    }
    Ok(headers)
}

fn compatible_endpoint_credential_transport(
    endpoint: EndpointAdapterKind,
    credential: CredentialKind,
    transport: TransportKind,
) -> bool {
    [
        IngressProtocolFamily::AnthropicMessages,
        IngressProtocolFamily::OpenaiChatCompletions,
        IngressProtocolFamily::OpenaiResponses,
        IngressProtocolFamily::GoogleGemini,
    ]
    .into_iter()
    .any(|ingress| compatibility(ingress, endpoint, credential, transport).is_some())
}

fn parse_injection_kind(value: &str) -> Result<InjectionKind, StoreError> {
    match value {
        "bearer" => Ok(InjectionKind::Bearer),
        "x_api_key" => Ok(InjectionKind::XApiKey),
        "api_key_header" => Ok(InjectionKind::ApiKeyHeader),
        "aws_sigv4" => Ok(InjectionKind::AwsSigV4),
        "google_oauth" => Ok(InjectionKind::GoogleOauth),
        "azure_bearer" => Ok(InjectionKind::AzureBearer),
        _ => Err(StoreError::Invariant("invalid credential injection kind")),
    }
}

#[cfg(test)]
mod network_policy_tests {
    use super::*;

    #[test]
    fn default_egress_policy_rejects_special_use_addresses() {
        let configuration = EgressNetworkConfiguration {
            dns: crate::domain::EgressDnsPolicy::default(),
            address: crate::domain::EgressAddressPolicy::default(),
            proxy_url: None,
            tls: crate::domain::EgressTlsPolicy::default(),
            redirect: crate::domain::EgressRedirectPolicy::default(),
            connection: crate::domain::EgressConnectionPolicy::default(),
            body: crate::domain::EgressBodyPolicy::default(),
            custom_ca_secret_id: None,
            custom_ca_generation: 0,
            config_version: 1,
        };
        let resolver = EgressResolver::new(&configuration, &HashMap::new()).unwrap();
        assert!(resolver.allows("8.8.8.8".parse().unwrap()));
        assert!(!resolver.allows("127.0.0.1".parse().unwrap()));
        assert!(!resolver.allows("10.0.0.1".parse().unwrap()));
        assert!(!resolver.allows("169.254.169.254".parse().unwrap()));
        assert!(!resolver.allows("::1".parse().unwrap()));
    }

    #[test]
    fn explicit_allow_cidr_is_narrow_and_deny_wins() {
        let mut configuration = EgressNetworkConfiguration {
            dns: crate::domain::EgressDnsPolicy::default(),
            address: crate::domain::EgressAddressPolicy::default(),
            proxy_url: None,
            tls: crate::domain::EgressTlsPolicy::default(),
            redirect: crate::domain::EgressRedirectPolicy::default(),
            connection: crate::domain::EgressConnectionPolicy::default(),
            body: crate::domain::EgressBodyPolicy::default(),
            custom_ca_secret_id: None,
            custom_ca_generation: 0,
            config_version: 1,
        };
        configuration.address.allowed_cidrs = vec!["10.10.0.0/16".to_owned()];
        configuration.address.denied_cidrs = vec!["10.10.10.0/24".to_owned()];
        let resolver = EgressResolver::new(&configuration, &HashMap::new()).unwrap();
        assert!(resolver.allows("10.10.1.1".parse().unwrap()));
        assert!(!resolver.allows("10.10.10.1".parse().unwrap()));
        assert!(!resolver.allows("10.11.1.1".parse().unwrap()));
    }

    #[test]
    fn unsafe_endpoint_and_policy_features_fail_closed() {
        let mut configuration = EgressNetworkConfiguration {
            dns: crate::domain::EgressDnsPolicy::default(),
            address: crate::domain::EgressAddressPolicy::default(),
            proxy_url: None,
            tls: crate::domain::EgressTlsPolicy::default(),
            redirect: crate::domain::EgressRedirectPolicy::default(),
            connection: crate::domain::EgressConnectionPolicy::default(),
            body: crate::domain::EgressBodyPolicy::default(),
            custom_ca_secret_id: None,
            custom_ca_generation: 0,
            config_version: 1,
        };
        assert!(
            validate_endpoint_for_network_policy(
                &url::Url::parse("https://127.0.0.1/v1").unwrap(),
                &configuration,
            )
            .is_err()
        );
        configuration.redirect.max_redirects = 1;
        assert!(validate_network_configuration(&configuration).is_err());
        configuration.redirect.max_redirects = 0;
        configuration.proxy_url = Some("https://proxy.example".to_owned());
        assert_eq!(
            validate_network_configuration(&configuration),
            Err("egress_proxy_target_enforcement_unavailable")
        );
    }
}

fn validate_scope(
    scope: CatalogScopeKind,
    organization_id: Option<OrganizationId>,
    invariant: &'static str,
) -> Result<(), StoreError> {
    if matches!(
        (scope, organization_id),
        (CatalogScopeKind::Deployment, None) | (CatalogScopeKind::Organization, Some(_))
    ) {
        Ok(())
    } else {
        Err(StoreError::Invariant(invariant))
    }
}

fn validate_target_tiers(targets: &[TargetSnapshot]) -> Result<(), StoreError> {
    let mut weights: HashMap<u8, u16> = HashMap::new();
    for target in targets {
        let total = weights.entry(target.priority).or_default();
        *total = total
            .checked_add(target.weight)
            .ok_or(StoreError::Invariant("route target tier weight overflow"))?;
        if *total > 256 {
            return Err(StoreError::Invariant(
                "route target tier weight exceeds 256",
            ));
        }
    }
    Ok(())
}

fn parse_enum<T: DeserializeOwned>(
    value: String,
    invariant: &'static str,
) -> Result<T, StoreError> {
    serde_json::from_value(serde_json::Value::String(value))
        .map_err(|_| StoreError::Invariant(invariant))
}

fn parse_unique_set<T>(
    value: serde_json::Value,
    invariant: &'static str,
) -> Result<BTreeSet<T>, StoreError>
where
    T: DeserializeOwned + Copy + Ord,
{
    let values: Vec<T> =
        serde_json::from_value(value).map_err(|_| StoreError::Invariant(invariant))?;
    let unique = values.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(StoreError::Invariant(invariant));
    }
    Ok(unique)
}

fn typed_column<T: DeserializeOwned>(
    row: &PgRow,
    name: &str,
    invariant: &'static str,
) -> Result<T, StoreError> {
    serde_json::from_value(row.try_get(name)?).map_err(|_| StoreError::Invariant(invariant))
}

fn object_column(
    row: &PgRow,
    name: &str,
    invariant: &'static str,
) -> Result<serde_json::Value, StoreError> {
    let value: serde_json::Value = row.try_get(name)?;
    require_object(&value, invariant)?;
    Ok(value)
}

fn require_object(value: &serde_json::Value, invariant: &'static str) -> Result<(), StoreError> {
    if value.is_object() {
        Ok(())
    } else {
        Err(StoreError::Invariant(invariant))
    }
}

fn positive_u64(value: i64, invariant: &'static str) -> Result<u64, StoreError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(StoreError::Invariant(invariant))
}

fn positive_u32(value: i32, invariant: &'static str) -> Result<u32, StoreError> {
    u32::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(StoreError::Invariant(invariant))
}

fn parse_u128_value(value: &str, invariant: &'static str) -> Result<u128, StoreError> {
    value.parse().map_err(|_| StoreError::Invariant(invariant))
}

fn positive_u128_text(value: &str, invariant: &'static str) -> Result<u128, StoreError> {
    parse_u128_value(value, invariant)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(StoreError::Invariant(invariant))
}

fn parse_u128_text(row: &PgRow, name: &str) -> Result<u128, StoreError> {
    row.try_get::<String, _>(name)?
        .parse()
        .map_err(|_| StoreError::Invariant("invalid budget amount"))
}

fn nonempty(value: String, invariant: &'static str) -> Result<String, StoreError> {
    if value.is_empty() {
        Err(StoreError::Invariant(invariant))
    } else {
        Ok(value)
    }
}

fn digest_array(value: Vec<u8>) -> Result<[u8; 32], StoreError> {
    value
        .try_into()
        .map_err(|_| StoreError::Invariant("invalid stored digest length"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_configuration_is_exact_and_bounded() {
        assert_eq!(
            exact_string_field(
                &serde_json::json!({"environment_variable":"UPSTREAM_KEY"}),
                "environment_variable"
            )
            .unwrap(),
            "UPSTREAM_KEY"
        );
        assert!(
            exact_string_field(
                &serde_json::json!({"environment_variable":"UPSTREAM_KEY","extra":true}),
                "environment_variable"
            )
            .is_err()
        );
    }

    #[test]
    fn persisted_default_cloud_chain_contracts_fail_closed() {
        for credential_kind in [
            CredentialKind::AwsDefaultChain,
            CredentialKind::GoogleApplicationDefault,
        ] {
            assert!(
                validate_default_chain_source_contract(
                    credential_kind,
                    CredentialSourceKind::WorkloadIdentity,
                    &CapturedSecretSource::External(serde_json::json!({})),
                )
                .is_ok()
            );
            for (source_kind, source) in [
                (
                    CredentialSourceKind::WorkloadIdentity,
                    CapturedSecretSource::External(serde_json::json!({"unexpected":"value"})),
                ),
                (
                    CredentialSourceKind::MountedFileReference,
                    CapturedSecretSource::External(serde_json::json!({"path":"/credentials"})),
                ),
            ] {
                assert_eq!(
                    validate_default_chain_source_contract(credential_kind, source_kind, &source,),
                    Err("default_cloud_chain_source_contract_invalid")
                );
            }
        }
    }

    #[test]
    fn persisted_route_grant_ceilings_reject_explicit_nulls() {
        for value in [
            serde_json::json!({"max_output_units":null}),
            serde_json::json!({"allowed_capabilities":null}),
            serde_json::json!({"request_policy":{"max_stream_seconds":null}}),
        ] {
            assert!(serde_json::from_value::<SystemRouteGrantCeilings>(value).is_err());
        }
    }

    #[test]
    fn endpoint_safe_headers_reject_authority_and_framing_fields() {
        assert!(parse_safe_headers(serde_json::json!({"x-client":"owlrora"})).is_ok());
        assert!(parse_safe_headers(serde_json::json!({"authorization":"secret"})).is_err());
        assert!(parse_safe_headers(serde_json::json!({"content-length":"1"})).is_err());
    }

    #[test]
    fn target_tier_weights_are_bounded() {
        let target = |weight| TargetSnapshot {
            id: TargetId::new(),
            deployment_id: DeploymentId::new(),
            affinity_identity: [0; 16],
            priority: 0,
            weight,
            narrowing_constraints: crate::domain::TargetNarrowingConstraints::default(),
            timeout_overrides: crate::domain::TargetTimeoutOverrides::default(),
        };
        assert!(validate_target_tiers(&[target(128), target(128)]).is_ok());
        assert!(validate_target_tiers(&[target(256), target(1)]).is_err());
    }

    #[test]
    fn secret_debug_types_do_not_expose_material() {
        let plaintext = SecretPlaintext::new(b"super-secret-value".to_vec()).unwrap();
        assert!(!format!("{plaintext:?}").contains("super-secret-value"));
        assert!(!format!("{plaintext:?}").contains("c3VwZXItc2VjcmV0LXZhbHVl"));
    }
}
