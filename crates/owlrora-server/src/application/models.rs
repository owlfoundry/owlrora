use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::{
    AuthenticationMethod, BindingId, BrowserLoginProfile, CapabilityClaimPolicy, ClaimMapping,
    InvitationId, IssuerId, IssuerStatus, JwksSource, JwtRouteCeiling, KeyCachePolicy, KeyId,
    ManagementOrganizationCeiling, ManagementScopeSet, MaterialVersionId, OrganizationId,
    OrganizationRole, OrganizationSelector, PolicyId, Principal, ResourceScope, SessionId, UserId,
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
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateMembership {
    pub user_id: UserId,
    pub role: OrganizationRole,
    #[serde(default)]
    pub llm_scope_ceiling: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateMembership {
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub role: UpdateField<OrganizationRole>,
    #[serde(default, skip_serializing_if = "UpdateField::is_omitted")]
    pub llm_scope_ceiling: UpdateField<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Invitation {
    pub id: InvitationId,
    pub organization_id: OrganizationId,
    pub intended_email: Option<String>,
    pub intended_role: OrganizationRole,
    pub llm_scope_ceiling: Vec<String>,
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
    pub management_organization_ceiling: ManagementOrganizationCeiling,
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
    pub management_organization_ceiling: ManagementOrganizationCeiling,
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
    pub management_organization_ceiling: UpdateField<ManagementOrganizationCeiling>,
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
