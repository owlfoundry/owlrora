use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use super::{
    Capability, LlmFeatureCapability, LlmScopeCeiling, ManagementScopeSet, OrganizationId,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerStatus {
    Active,
    Disabled,
}

impl IssuerStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum JwksSource {
    Https { uri: Url },
    Static { jwks: Value },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityClaimPolicy {
    Ignore,
    OptionalNarrowing,
    RequiredNarrowing,
}

impl CapabilityClaimPolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ignore => "ignore",
            Self::OptionalNarrowing => "optional_narrowing",
            Self::RequiredNarrowing => "required_narrowing",
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimMapping {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management_scopes_claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management_capabilities_claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm_scopes_claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm_capabilities_claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routes_claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organizations_claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name_claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_claim: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagementOrganizationCeiling {
    None,
    AllAuthorized,
    Organizations {
        organization_ids: BTreeSet<OrganizationId>,
    },
}

impl ManagementOrganizationCeiling {
    #[must_use]
    pub fn allows(&self, organization_id: OrganizationId) -> bool {
        match self {
            Self::AllAuthorized => true,
            Self::Organizations { organization_ids } => organization_ids.contains(&organization_id),
            Self::None => false,
        }
    }

    #[must_use]
    pub fn as_optional_vec(&self) -> Option<Vec<OrganizationId>> {
        match self {
            Self::AllAuthorized => None,
            Self::Organizations { organization_ids } => {
                Some(organization_ids.iter().copied().collect())
            }
            Self::None => Some(Vec::new()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum JwtRouteCeiling {
    None,
    AllOrganizationGranted,
    Routes { route_ids: BTreeSet<String> },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OrganizationSelector {
    None,
    SignedClaim { claim: String },
    Header,
    Either { claim: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserClientAuthentication {
    Public,
    ProtectedClientSecret,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserLoginProfile {
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub client_id: String,
    pub client_authentication: BrowserClientAuthentication,
    pub scopes: BTreeSet<String>,
    pub status: IssuerStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyCachePolicy {
    pub refresh_interval_seconds: u32,
    pub material_acceptance_seconds: u32,
    pub max_keys: u16,
    pub max_token_bytes: u32,
}

impl Default for KeyCachePolicy {
    fn default() -> Self {
        Self {
            refresh_interval_seconds: 3600,
            material_acceptance_seconds: 86_400,
            max_keys: 32,
            max_token_bytes: 16_384,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExternalAccessCeiling {
    pub management_access: bool,
    pub management_scopes: ManagementScopeSet,
    pub management_capabilities: BTreeSet<Capability>,
    pub management_organizations: ManagementOrganizationCeiling,
    pub llm_access: bool,
    pub llm_scopes: LlmScopeCeiling,
    pub llm_capabilities: BTreeSet<LlmFeatureCapability>,
    pub llm_routes: JwtRouteCeiling,
    pub organization_selector: OrganizationSelector,
}

impl ExternalAccessCeiling {
    #[must_use]
    pub fn denied() -> Self {
        Self {
            management_access: false,
            management_scopes: ManagementScopeSet::empty(),
            management_capabilities: BTreeSet::new(),
            management_organizations: ManagementOrganizationCeiling::None,
            llm_access: false,
            llm_scopes: LlmScopeCeiling::denied(),
            llm_capabilities: BTreeSet::new(),
            llm_routes: JwtRouteCeiling::None,
            organization_selector: OrganizationSelector::None,
        }
    }
}
