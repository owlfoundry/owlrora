use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::Value;

use crate::domain::{
    AccountingOrigin, AuthenticationMethod, BindingId, BrowserLoginProfile, BudgetMode, Capability,
    CapabilityClaimPolicy, ClaimMapping, CredentialId, CredentialKind, CredentialSecretVersionId,
    CredentialSourceKind, DeploymentId, EndpointAdapterKind, EndpointId, GatewayKeyId,
    IngressProtocolFamily, InvitationId, IssuerId, IssuerStatus, JwksSource, JwtRouteCeiling,
    KeyCachePolicy, KeyId, LlmFeatureCapability, LlmScopeSet, ManagementOrganizationCeiling,
    ManagementScopeSet, MaterialVersionId, NetworkPolicyId, OrganizationId, OrganizationRole,
    OrganizationSelector, PolicyId, PricingPolicyId, PricingPolicyVersionId, Principal,
    ReliabilityPolicyId, ResourceScope, RouteId, SessionId, SystemRouteGrantCeilings, TargetId,
    TransportKind, UserId,
};

use super::UpdateField;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserKind {
    Human,
    Synthetic,
}

impl UserKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Synthetic => "synthetic",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
    Active,
    Disabled,
}

impl UserStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct User {
    pub id: UserId,
    pub kind: UserKind,
    pub status: UserStatus,
    pub display_name: String,
    pub primary_email: Option<String>,
    pub created_by_principal: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateUser {
    pub kind: UserKind,
    pub display_name: String,
    pub primary_email: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateUser {
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub display_name: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub primary_email: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub status: UpdateField<UserStatus>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationKind {
    Ordinary,
    Synthetic,
}

impl OrganizationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::Synthetic => "synthetic",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationStatus {
    Active,
    Suspended,
}

impl OrganizationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Organization {
    pub id: OrganizationId,
    pub kind: OrganizationKind,
    pub status: OrganizationStatus,
    pub name: String,
    pub slug: Option<String>,
    pub created_by_principal: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateOrganization {
    pub kind: OrganizationKind,
    pub name: String,
    pub slug: Option<String>,
    pub initial_owner_user_id: UserId,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateOrganization {
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub name: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub slug: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub status: UpdateField<OrganizationStatus>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Membership {
    pub id: String,
    pub organization_id: OrganizationId,
    pub user_id: UserId,
    pub role: OrganizationRole,
    pub status: String,
    pub llm_scope_ceiling: Vec<String>,
    pub llm_capability_ceiling: BTreeSet<crate::domain::LlmFeatureCapability>,
    pub llm_route_ceiling: JwtRouteCeiling,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateMembership {
    pub user_id: UserId,
    pub role: OrganizationRole,
    #[serde(default)]
    pub llm_scope_ceiling: Vec<String>,
    #[serde(default)]
    pub llm_capability_ceiling: BTreeSet<crate::domain::LlmFeatureCapability>,
    pub llm_route_ceiling: JwtRouteCeiling,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateMembership {
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub role: UpdateField<OrganizationRole>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub llm_scope_ceiling: UpdateField<Vec<String>>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub llm_capability_ceiling: UpdateField<BTreeSet<crate::domain::LlmFeatureCapability>>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub llm_route_ceiling: UpdateField<JwtRouteCeiling>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Invitation {
    pub id: InvitationId,
    pub organization_id: OrganizationId,
    pub intended_email: Option<String>,
    pub intended_role: OrganizationRole,
    pub llm_scope_ceiling: Vec<String>,
    pub llm_capability_ceiling: BTreeSet<crate::domain::LlmFeatureCapability>,
    pub llm_route_ceiling: JwtRouteCeiling,
    pub state: String,
    pub expires_at: DateTime<Utc>,
    pub accepted_by_user_id: Option<UserId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateInvitation {
    pub intended_email: Option<String>,
    pub intended_role: OrganizationRole,
    #[serde(default)]
    pub llm_scope_ceiling: Vec<String>,
    #[serde(default)]
    pub llm_capability_ceiling: BTreeSet<crate::domain::LlmFeatureCapability>,
    pub llm_route_ceiling: JwtRouteCeiling,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OneTimeInvitation {
    pub invitation: Invitation,
    pub token: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AcceptInvitation {
    pub token: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    Active,
    Disabled,
    Revoked,
}

impl KeyStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManagementApiKey {
    pub id: KeyId,
    pub resource_scope: ResourceScope,
    pub issuance_policy_class: String,
    pub created_by_principal: Value,
    pub name: String,
    pub key_prefix: String,
    pub scopes: ManagementScopeSet,
    pub capability_ceiling: Value,
    pub status: KeyStatus,
    pub expires_at: Option<DateTime<Utc>>,
    pub current_secret_version_id: MaterialVersionId,
    pub overlap_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateManagementApiKey {
    pub name: String,
    pub scopes: ManagementScopeSet,
    pub capability_ceiling: Value,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OneTimeManagementApiKey {
    pub management_api_key: ManagementApiKey,
    pub key: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateManagementApiKey {
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub name: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub scopes: UpdateField<ManagementScopeSet>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub capability_ceiling: UpdateField<Value>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub status: UpdateField<KeyStatus>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub expires_at: UpdateField<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RotateManagementApiKey {
    #[serde(default = "default_overlap_seconds")]
    pub overlap_seconds: u32,
}

const fn default_overlap_seconds() -> u32 {
    300
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeploymentManagementKeyPolicy {
    pub policy: Value,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateDeploymentManagementKeyPolicy {
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub policy: UpdateField<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OrganizationApiKeyPolicy {
    pub organization_id: OrganizationId,
    pub policy: Value,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateOrganizationApiKeyPolicy {
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub policy: UpdateField<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdministratorGrant {
    pub id: Option<String>,
    pub subject_kind: String,
    pub subject_id: String,
    pub status: String,
    pub built_in: bool,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GrantAdministrator {
    pub subject_kind: String,
    pub subject_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CurrentPrincipal {
    pub principal: Principal,
    pub authentication_method: AuthenticationMethod,
    pub effective_management_scopes: ManagementScopeSet,
    pub resource_scope: ResourceScope,
    pub system_administrator: bool,
    pub allowed_organizations: Vec<AllowedOrganization>,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManagementKeySelfServiceEligibility {
    pub eligible: bool,
    pub allowed_scopes: Vec<String>,
    pub allowed_capabilities: Vec<String>,
    pub max_expiry_days: u64,
    pub max_active_keys: u64,
    pub active_keys: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AllowedOrganization {
    pub organization_id: OrganizationId,
    pub name: String,
    pub access_reason: String,
    pub role: Option<OrganizationRole>,
    pub capabilities: Vec<String>,
    pub management_key_self_service: Option<ManagementKeySelfServiceEligibility>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SessionView {
    pub id: SessionId,
    pub principal: Principal,
    pub authentication_method: AuthenticationMethod,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub current: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SessionCreated {
    pub session: SessionView,
    #[serde(skip_serializing)]
    pub session_cookie: String,
    pub csrf_token: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExternalIdentityIssuer {
    pub id: IssuerId,
    pub name: String,
    pub display_name: String,
    pub issuer: String,
    pub status: IssuerStatus,
    pub jwks_source: JwksSource,
    pub current_verifier_material_version_id: Option<MaterialVersionId>,
    pub allowed_algorithms: Vec<String>,
    pub accepted_audiences: BTreeSet<String>,
    pub subject_claim: String,
    pub claim_mapping: ClaimMapping,
    pub jwt_capability_ceiling: BTreeSet<String>,
    pub management_scope_ceiling: ManagementScopeSet,
    pub management_capability_ceiling: BTreeSet<Capability>,
    pub management_organization_ceiling: ManagementOrganizationCeiling,
    pub llm_scope_ceiling: crate::domain::LlmScopeCeiling,
    pub llm_capability_ceiling: BTreeSet<crate::domain::LlmFeatureCapability>,
    pub capability_claim_policy: CapabilityClaimPolicy,
    pub jwt_route_ceiling: JwtRouteCeiling,
    pub organization_selector: OrganizationSelector,
    pub provisioning_policy_id: Option<PolicyId>,
    pub browser_login: Option<BrowserLoginProfile>,
    pub clock_skew_seconds: u32,
    pub key_cache_policy: KeyCachePolicy,
    pub policy_version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateExternalIdentityIssuer {
    pub name: String,
    pub display_name: String,
    pub issuer: String,
    pub status: IssuerStatus,
    pub jwks_source: JwksSource,
    pub allowed_algorithms: Vec<String>,
    pub accepted_audiences: BTreeSet<String>,
    #[serde(default = "default_subject_claim")]
    pub subject_claim: String,
    #[serde(default)]
    pub claim_mapping: ClaimMapping,
    #[serde(default)]
    pub jwt_capability_ceiling: BTreeSet<String>,
    #[serde(default)]
    pub management_scope_ceiling: ManagementScopeSet,
    #[serde(default)]
    pub management_capability_ceiling: BTreeSet<Capability>,
    pub management_organization_ceiling: ManagementOrganizationCeiling,
    #[serde(default)]
    pub llm_scope_ceiling: crate::domain::LlmScopeCeiling,
    #[serde(default)]
    pub llm_capability_ceiling: BTreeSet<crate::domain::LlmFeatureCapability>,
    pub capability_claim_policy: CapabilityClaimPolicy,
    pub jwt_route_ceiling: JwtRouteCeiling,
    pub organization_selector: OrganizationSelector,
    pub provisioning_policy_id: Option<PolicyId>,
    pub browser_login: Option<BrowserLoginProfile>,
    #[serde(default = "default_clock_skew")]
    pub clock_skew_seconds: u32,
    #[serde(default)]
    pub key_cache_policy: KeyCachePolicy,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateExternalIdentityIssuer {
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub display_name: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub status: UpdateField<IssuerStatus>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub jwks_source: UpdateField<JwksSource>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub allowed_algorithms: UpdateField<Vec<String>>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub accepted_audiences: UpdateField<BTreeSet<String>>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub subject_claim: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub claim_mapping: UpdateField<ClaimMapping>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub jwt_capability_ceiling: UpdateField<BTreeSet<String>>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub management_scope_ceiling: UpdateField<ManagementScopeSet>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub management_capability_ceiling: UpdateField<BTreeSet<Capability>>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub management_organization_ceiling: UpdateField<ManagementOrganizationCeiling>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub llm_scope_ceiling: UpdateField<crate::domain::LlmScopeCeiling>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub llm_capability_ceiling: UpdateField<BTreeSet<crate::domain::LlmFeatureCapability>>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub capability_claim_policy: UpdateField<CapabilityClaimPolicy>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub jwt_route_ceiling: UpdateField<JwtRouteCeiling>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub organization_selector: UpdateField<OrganizationSelector>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub provisioning_policy_id: UpdateField<PolicyId>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub browser_login: UpdateField<BrowserLoginProfile>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub clock_skew_seconds: UpdateField<u32>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub key_cache_policy: UpdateField<KeyCachePolicy>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogStatus {
    Active,
    Disabled,
}

impl CatalogStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatedCatalogStatus {
    Active,
    Disabled,
    ValidationFailed,
}

impl ValidatedCatalogStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::ValidationFailed => "validation_failed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EgressNetworkPolicy {
    pub id: NetworkPolicyId,
    pub name: String,
    pub dns_policy: crate::domain::EgressDnsPolicy,
    pub address_policy: crate::domain::EgressAddressPolicy,
    pub proxy_url: Option<String>,
    pub tls_policy: crate::domain::EgressTlsPolicy,
    pub redirect_policy: crate::domain::EgressRedirectPolicy,
    pub connection_policy: crate::domain::EgressConnectionPolicy,
    pub body_policy: crate::domain::EgressBodyPolicy,
    pub custom_ca: Option<ProtectedSecretMetadata>,
    pub status: CatalogStatus,
    pub config_version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateEgressNetworkPolicy {
    pub name: String,
    #[serde(default)]
    pub dns_policy: crate::domain::EgressDnsPolicy,
    #[serde(default)]
    pub address_policy: crate::domain::EgressAddressPolicy,
    pub proxy_url: Option<String>,
    #[serde(default)]
    pub tls_policy: crate::domain::EgressTlsPolicy,
    #[serde(default)]
    pub redirect_policy: crate::domain::EgressRedirectPolicy,
    #[serde(default)]
    pub connection_policy: crate::domain::EgressConnectionPolicy,
    #[serde(default)]
    pub body_policy: crate::domain::EgressBodyPolicy,
    pub custom_ca_pem: Option<String>,
    #[serde(default = "default_catalog_status")]
    pub status: CatalogStatus,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateEgressNetworkPolicy {
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub name: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub dns_policy: UpdateField<crate::domain::EgressDnsPolicy>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub address_policy: UpdateField<crate::domain::EgressAddressPolicy>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub proxy_url: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub tls_policy: UpdateField<crate::domain::EgressTlsPolicy>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub redirect_policy: UpdateField<crate::domain::EgressRedirectPolicy>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub connection_policy: UpdateField<crate::domain::EgressConnectionPolicy>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub body_policy: UpdateField<crate::domain::EgressBodyPolicy>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub status: UpdateField<CatalogStatus>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReplaceEgressCustomCa {
    pub custom_ca_pem: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProtectedSecretMetadata {
    pub material_id: uuid::Uuid,
    pub custody_provider_id: String,
    pub provider_format_version: u32,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpstreamCredential {
    pub id: CredentialId,
    pub resource_scope: ResourceScope,
    pub name: String,
    pub credential_kind: CredentialKind,
    pub secret_source_kind: CredentialSourceKind,
    pub source_configuration: Value,
    pub injection_kind: String,
    pub sharing_policy: String,
    pub administrative_status: KeyStatus,
    pub authentication_status: String,
    pub current_secret_version: Option<i64>,
    pub state_identity_version: i64,
    pub safe_metadata: Value,
    pub validation_evidence: Option<Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub validated_at: Option<DateTime<Utc>>,
    pub current_secret_version_id: Option<CredentialSecretVersionId>,
    pub overlap_until: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateUpstreamCredential {
    pub name: String,
    pub credential_kind: CredentialKind,
    pub secret_source_kind: CredentialSourceKind,
    #[serde(default)]
    pub source_configuration: Value,
    pub injection_kind: String,
    pub sharing_policy: String,
    pub secret: Option<String>,
    #[serde(default)]
    pub safe_metadata: Value,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateUpstreamCredential {
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub name: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub sharing_policy: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub administrative_status: UpdateField<KeyStatus>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub safe_metadata: UpdateField<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReplaceUpstreamCredentialSecret {
    pub secret: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialLifecycleResult {
    pub credential: UpstreamCredential,
    pub operation: String,
    pub outcome: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CatalogValidationResult<T> {
    pub resource: T,
    pub outcome: String,
    pub evidence: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CodexLoginSession {
    pub id: crate::domain::CredentialLoginSessionId,
    pub credential_id: CredentialId,
    pub state: String,
    pub verification_url: Option<String>,
    pub user_code: Option<String>,
    pub poll_interval_seconds: u32,
    pub expires_at: DateTime<Utc>,
    pub next_poll_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartCodexLogin {}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteCodexLogin {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpstreamEndpoint {
    pub id: EndpointId,
    pub name: String,
    pub adapter_kind: EndpointAdapterKind,
    pub base_url: String,
    pub region: Option<String>,
    pub api_version: Option<String>,
    pub network_policy_id: NetworkPolicyId,
    pub safe_headers: Value,
    pub status: ValidatedCatalogStatus,
    pub config_version: i64,
    pub validation_evidence: Option<Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub validated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateUpstreamEndpoint {
    pub name: String,
    pub adapter_kind: EndpointAdapterKind,
    pub base_url: String,
    pub region: Option<String>,
    pub api_version: Option<String>,
    pub network_policy_id: NetworkPolicyId,
    #[serde(default)]
    pub safe_headers: Value,
    #[serde(default = "default_validated_catalog_status")]
    pub status: ValidatedCatalogStatus,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateUpstreamEndpoint {
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub name: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub base_url: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub region: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub api_version: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub network_policy_id: UpdateField<NetworkPolicyId>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub safe_headers: UpdateField<Value>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub status: UpdateField<ValidatedCatalogStatus>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PricingPolicyVersion {
    pub id: PricingPolicyVersionId,
    pub pricing_policy_id: PricingPolicyId,
    pub generation: i64,
    pub rates: crate::domain::PricingRates,
    pub rounding_policy: crate::domain::PricingRoundingPolicy,
    pub organization_usable: bool,
    pub publication_evidence: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PricingPolicy {
    pub id: PricingPolicyId,
    pub name: String,
    pub status: CatalogStatus,
    pub desired_version_id: Option<PricingPolicyVersionId>,
    pub current_version_id: Option<PricingPolicyVersionId>,
    pub versions: Vec<PricingPolicyVersion>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreatePricingPolicy {
    pub name: String,
    #[serde(default = "default_catalog_status")]
    pub status: CatalogStatus,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdatePricingPolicy {
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub name: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub status: UpdateField<CatalogStatus>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishPricingPolicyVersion {
    pub rates: crate::domain::PricingRates,
    pub rounding_policy: crate::domain::PricingRoundingPolicy,
    #[serde(default)]
    pub organization_usable: bool,
    #[serde(default)]
    pub publication_evidence: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishedPricingPolicyVersion {
    pub pricing_policy: PricingPolicy,
    pub version: PricingPolicyVersion,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReliabilityPolicy {
    pub id: ReliabilityPolicyId,
    pub name: String,
    pub attempt_policy: Value,
    pub deadline_policy: Value,
    pub retry_policy: Value,
    pub failover_policy: Value,
    pub commitment_policy: Value,
    pub health_policy: Value,
    pub circuit_policy: Value,
    pub probe_policy: Value,
    pub status: CatalogStatus,
    pub config_version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateReliabilityPolicy {
    pub name: String,
    pub attempt_policy: Value,
    pub deadline_policy: Value,
    pub retry_policy: Value,
    pub failover_policy: Value,
    pub commitment_policy: Value,
    pub health_policy: Value,
    pub circuit_policy: Value,
    pub probe_policy: Value,
    #[serde(default = "default_catalog_status")]
    pub status: CatalogStatus,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateReliabilityPolicy {
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub name: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub attempt_policy: UpdateField<Value>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub deadline_policy: UpdateField<Value>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub retry_policy: UpdateField<Value>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub failover_policy: UpdateField<Value>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub commitment_policy: UpdateField<Value>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub health_policy: UpdateField<Value>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub circuit_policy: UpdateField<Value>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub probe_policy: UpdateField<Value>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub status: UpdateField<CatalogStatus>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ModelDeployment {
    pub id: DeploymentId,
    pub resource_scope: ResourceScope,
    pub name: String,
    pub endpoint_id: EndpointId,
    pub credential_id: CredentialId,
    pub transport_kind: TransportKind,
    pub upstream_model_id: String,
    pub model_family: Option<String>,
    pub capability_set: BTreeSet<LlmFeatureCapability>,
    pub context_limits: Value,
    pub state_isolation_profile: Value,
    pub pricing_policy_version_id: Option<PricingPolicyVersionId>,
    pub unpriced: bool,
    pub status: ValidatedCatalogStatus,
    pub config_version: i64,
    pub validation_evidence: Option<Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub validated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateModelDeployment {
    pub name: String,
    pub endpoint_id: EndpointId,
    pub credential_id: CredentialId,
    pub transport_kind: TransportKind,
    pub upstream_model_id: String,
    pub model_family: Option<String>,
    pub capability_set: BTreeSet<LlmFeatureCapability>,
    pub context_limits: Value,
    pub state_isolation_profile: Value,
    pub pricing_policy_version_id: Option<PricingPolicyVersionId>,
    #[serde(default)]
    pub unpriced: bool,
    #[serde(default = "default_validated_catalog_status")]
    pub status: ValidatedCatalogStatus,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateModelDeployment {
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub name: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub model_family: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub capability_set: UpdateField<BTreeSet<LlmFeatureCapability>>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub context_limits: UpdateField<Value>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub state_isolation_profile: UpdateField<Value>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub pricing_policy_version_id: UpdateField<PricingPolicyVersionId>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub unpriced: UpdateField<bool>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub status: UpdateField<ValidatedCatalogStatus>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteTargetInput {
    pub id: Option<TargetId>,
    pub deployment_id: DeploymentId,
    pub priority: u8,
    pub weight: u16,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub narrowing_constraints: Value,
    #[serde(default)]
    pub timeout_overrides: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RouteTarget {
    pub id: TargetId,
    pub deployment_id: DeploymentId,
    pub priority: u8,
    pub weight: u16,
    pub enabled: bool,
    pub narrowing_constraints: Value,
    pub timeout_overrides: Value,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Draft,
    Active,
    Disabled,
}

impl RouteStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ModelRoute {
    pub id: RouteId,
    pub resource_scope: ResourceScope,
    pub owner_user_id: Option<UserId>,
    pub model_key: String,
    pub ingress_protocol_family: IngressProtocolFamily,
    pub required_base_capabilities: BTreeSet<LlmFeatureCapability>,
    pub selection_policy: Value,
    pub reliability_policy_id: ReliabilityPolicyId,
    pub request_policy: Value,
    pub status: RouteStatus,
    pub config_version: i64,
    pub targets: Vec<RouteTarget>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateModelRoute {
    pub owner_user_id: Option<UserId>,
    pub model_key: String,
    pub ingress_protocol_family: IngressProtocolFamily,
    pub required_base_capabilities: BTreeSet<LlmFeatureCapability>,
    pub selection_policy: Value,
    pub reliability_policy_id: ReliabilityPolicyId,
    pub request_policy: Value,
    #[serde(default = "default_route_status")]
    pub status: RouteStatus,
    pub targets: Vec<RouteTargetInput>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateModelRoute {
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub required_base_capabilities: UpdateField<BTreeSet<LlmFeatureCapability>>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub selection_policy: UpdateField<Value>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub reliability_policy_id: UpdateField<ReliabilityPolicyId>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub request_policy: UpdateField<Value>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub status: UpdateField<RouteStatus>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub targets: UpdateField<Vec<RouteTargetInput>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransferModelRouteOwnership {
    pub owner_user_id: UserId,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CatalogGrantSet {
    pub resource_ids: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub system_route_ceilings: BTreeMap<String, SystemRouteGrantCeilings>,
}

fn deserialize_catalog_grant_resource_ids<'de, D>(
    deserializer: D,
) -> Result<BTreeSet<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    if values.len() > 4096 {
        return Err(D::Error::custom(
            "catalog grant sets cannot exceed 4096 resources",
        ));
    }
    let unique = values.iter().cloned().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(D::Error::custom(
            "catalog grant resource_ids must not contain duplicates",
        ));
    }
    Ok(unique)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateCatalogGrantSet {
    #[serde(deserialize_with = "deserialize_catalog_grant_resource_ids")]
    pub resource_ids: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub system_route_ceilings: BTreeMap<String, SystemRouteGrantCeilings>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AvailableUpstreamEndpoint {
    pub endpoint: UpstreamEndpoint,
    pub granted: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AvailableModelDeployment {
    pub deployment: ModelDeployment,
    pub granted: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AvailableReliabilityPolicy {
    pub reliability_policy: ReliabilityPolicy,
    pub granted: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AvailableModelRoute {
    pub route: ModelRoute,
    pub granted: bool,
}

fn empty_json_object() -> Value {
    Value::Object(serde_json::Map::new())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GatewayBudgetInput {
    pub limit_cost_nanos: String,
    pub mode: BudgetMode,
    pub epoch: String,
    #[serde(default = "empty_json_object")]
    pub estimate_policy: Value,
    #[serde(default = "empty_json_object")]
    pub allowance_policy: Value,
    #[serde(default = "empty_json_object")]
    pub failure_policy: Value,
    #[serde(default = "empty_json_object")]
    pub recovery_policy: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BudgetPolicyVersionView {
    pub id: String,
    pub generation: u64,
    pub limit_cost_nanos: String,
    pub recovery_incident_cap_nanos: String,
    pub recovery_epoch_cap_nanos: String,
    pub epoch: String,
    pub mode: BudgetMode,
    pub estimate_policy: Value,
    pub allowance_policy: Value,
    pub failure_policy: Value,
    pub recovery_policy: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BudgetPolicyView {
    pub id: String,
    pub organization_id: OrganizationId,
    pub gateway_api_key_id: Option<GatewayKeyId>,
    pub origin: Option<AccountingOrigin>,
    pub status: CatalogStatus,
    pub desired_version: Option<BudgetPolicyVersionView>,
    pub active_version: Option<BudgetPolicyVersionView>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateBudgetPolicy {
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub epoch: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub limit_cost_nanos: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub mode: UpdateField<BudgetMode>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub estimate_policy: UpdateField<Value>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub allowance_policy: UpdateField<Value>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub failure_policy: UpdateField<Value>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub recovery_policy: UpdateField<Value>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub status: UpdateField<CatalogStatus>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BeginBudgetEpoch {
    pub epoch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit_cost_nanos: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<BudgetMode>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GatewayRequestLimitsInput {
    pub epoch: String,
    pub requests_per_minute: u32,
    pub input_units_per_minute: Option<u64>,
    pub grant_mode: String,
    #[serde(default)]
    pub grant_policy: Value,
    pub concurrency_mode: Option<String>,
    pub concurrency_limit: Option<u32>,
    pub lease_seconds: Option<u32>,
    pub max_stream_seconds: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GatewayRequestLimitsView {
    pub policy_id: Option<String>,
    pub organization_id: OrganizationId,
    pub gateway_api_key_id: GatewayKeyId,
    pub status: Option<CatalogStatus>,
    pub desired: Option<GatewayRequestLimitsInput>,
    pub active: Option<GatewayRequestLimitsInput>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateGatewayRequestLimits {
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub limits: UpdateField<GatewayRequestLimitsInput>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub status: UpdateField<CatalogStatus>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GatewayPolicyCeilings {
    pub key_budget_max_limit_cost_nanos: String,
    pub byok_origin_budget_max_limit_cost_nanos: String,
    pub max_recovery_incident_cap_nanos: String,
    pub max_recovery_epoch_cap_nanos: String,
    pub max_requests_per_minute: u32,
    pub max_input_units_per_minute: u64,
    pub max_concurrency: u32,
    pub max_stream_seconds: u32,
    pub allowed_budget_modes: Vec<BudgetMode>,
    pub allowed_rate_grant_modes: Vec<String>,
    pub allowed_concurrency_modes: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateGatewayPolicyCeilings {
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub key_budget_max_limit_cost_nanos: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub byok_origin_budget_max_limit_cost_nanos: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub max_recovery_incident_cap_nanos: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub max_recovery_epoch_cap_nanos: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub max_requests_per_minute: UpdateField<u32>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub max_input_units_per_minute: UpdateField<u64>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub max_concurrency: UpdateField<u32>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub max_stream_seconds: UpdateField<u32>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub allowed_budget_modes: UpdateField<Vec<BudgetMode>>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub allowed_rate_grant_modes: UpdateField<Vec<String>>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub allowed_concurrency_modes: UpdateField<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GatewayApiKey {
    pub id: GatewayKeyId,
    pub organization_id: OrganizationId,
    pub issuance_policy_class: String,
    pub created_by_principal: Value,
    pub name: String,
    pub scopes: LlmScopeSet,
    pub route_ids: BTreeSet<RouteId>,
    pub status: KeyStatus,
    pub expires_at: Option<DateTime<Utc>>,
    pub budget_policy_id: String,
    pub current_secret_version_id: MaterialVersionId,
    pub overlap_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateGatewayApiKey {
    pub name: String,
    pub scopes: LlmScopeSet,
    pub route_ids: BTreeSet<RouteId>,
    pub budget: GatewayBudgetInput,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OneTimeGatewayApiKey {
    pub gateway_api_key: GatewayApiKey,
    pub key: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateGatewayApiKey {
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub name: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub scopes: UpdateField<LlmScopeSet>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub route_ids: UpdateField<BTreeSet<RouteId>>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub status: UpdateField<KeyStatus>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub expires_at: UpdateField<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RotateGatewayApiKey {
    #[serde(default = "default_overlap_seconds")]
    pub overlap_seconds: u32,
}

const fn default_catalog_status() -> CatalogStatus {
    CatalogStatus::Active
}

const fn default_validated_catalog_status() -> ValidatedCatalogStatus {
    ValidatedCatalogStatus::Active
}

const fn default_route_status() -> RouteStatus {
    RouteStatus::Draft
}

const fn default_true() -> bool {
    true
}

fn default_subject_claim() -> String {
    "sub".to_owned()
}

const fn default_clock_skew() -> u32 {
    60
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExternalIdentityBinding {
    pub id: BindingId,
    pub issuer_id: IssuerId,
    pub external_subject: String,
    pub user_id: UserId,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateExternalIdentityBinding {
    pub issuer_id: IssuerId,
    pub external_subject: String,
    pub user_id: UserId,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelinkExternalIdentityBinding {
    pub user_id: UserId,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReplaceBrowserClientSecret {
    pub client_secret: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BrowserLoginValidation {
    pub authorization_endpoint_status: u16,
    pub token_endpoint_status: u16,
    pub client_accepted: Option<bool>,
    pub validated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProvisioningPolicy {
    pub id: PolicyId,
    pub name: String,
    pub status: String,
    pub user_kind: UserKind,
    pub configuration: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateProvisioningPolicy {
    pub name: String,
    pub status: String,
    pub user_kind: UserKind,
    pub configuration: Value,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateProvisioningPolicy {
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub name: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub status: UpdateField<String>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub user_kind: UpdateField<UserKind>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub configuration: UpdateField<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BrowserLoginIssuer {
    pub name: String,
    pub display_name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OidcLoginRedirect {
    pub authorization_url: String,
    #[serde(skip_serializing)]
    pub transaction_token: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OidcCallback {
    pub state: String,
    pub code: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OidcCallbackResult {
    pub session: SessionCreated,
    pub return_to: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditQuery {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub since: Option<DateTime<Utc>>,
    pub before: Option<DateTime<Utc>>,
    pub operation_id: Option<String>,
    pub outcome: Option<String>,
    pub target_resource_kind: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditEntry {
    pub id: String,
    pub actor: Option<Value>,
    pub authentication_evidence: Value,
    pub organization_id: Option<OrganizationId>,
    pub target_resource_kind: String,
    pub target_resource_id: Option<String>,
    pub operation_id: String,
    pub outcome: String,
    pub request_id: String,
    pub changed_fields: Vec<String>,
    pub safe_details: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReadinessView {
    pub ready: bool,
    pub database: String,
    pub runtime_revision: i64,
    pub database_revision: i64,
    pub runtime_age_seconds: i64,
    pub publication_error: Option<String>,
}
