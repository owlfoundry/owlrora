use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, jwk::JwkSet};

use crate::domain::{
    BrowserLoginProfile, Capability, CapabilityClaimPolicy, ClaimMapping, IssuerId, JwksSource,
    KeyCachePolicy, KeyId, ManagementOrganizationCeiling, ManagementScopeSet, OrganizationId,
    OrganizationRole, PolicyId, ResourceScope, UserId,
};

#[derive(Clone, Debug)]
pub struct RuntimeGeneration {
    pub snapshot: Arc<RuntimeSnapshot>,
}

#[derive(Clone, Debug)]
pub struct RuntimeSnapshot {
    pub revision: i64,
    pub built_at: DateTime<Utc>,
    pub identity: IdentitySnapshot,
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
    pub role: OrganizationRole,
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
