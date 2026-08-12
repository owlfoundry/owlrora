use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    Capability, IssuerId, KeyId, ManagementScopeSet, OrganizationId, ResourceScope, SessionId,
    UserId,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Principal {
    SeedAdmin,
    LocalUser {
        user_id: UserId,
    },
    DeploymentManagementApiKey {
        management_api_key_id: KeyId,
    },
    OrganizationManagementApiKey {
        organization_id: OrganizationId,
        management_api_key_id: KeyId,
    },
}

impl Principal {
    #[must_use]
    pub fn stable_id(&self) -> String {
        match self {
            Self::SeedAdmin => "seed_admin".to_owned(),
            Self::LocalUser { user_id } => user_id.to_string(),
            Self::DeploymentManagementApiKey {
                management_api_key_id,
            }
            | Self::OrganizationManagementApiKey {
                management_api_key_id,
                ..
            } => management_api_key_id.to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationMethod {
    ManagementApiKey,
    ManagementApiKeySession,
    ExternalSession,
    ExternalJwt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthenticatedPrincipal {
    pub principal: Principal,
    pub authentication_method: AuthenticationMethod,
    pub effective_management_scopes: ManagementScopeSet,
    pub credential_capability_ceiling: BTreeSet<Capability>,
    pub effective_system_administrator: bool,
    pub effective_organization_capabilities: BTreeMap<OrganizationId, BTreeSet<Capability>>,
    pub resource_scope: ResourceScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_key_version_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_issuer_id: Option<IssuerId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub management_organization_ceiling: Option<Vec<OrganizationId>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Actor {
    pub principal: Principal,
    pub authentication_method: AuthenticationMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_issuer_id: Option<IssuerId>,
}

impl From<&AuthenticatedPrincipal> for Actor {
    fn from(value: &AuthenticatedPrincipal) -> Self {
        Self {
            principal: value.principal.clone(),
            authentication_method: value.authentication_method,
            session_id: value.session_id,
            external_issuer_id: value.external_issuer_id.clone(),
        }
    }
}
