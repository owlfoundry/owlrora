use std::sync::Arc;

use crate::{
    domain::{AuthenticatedPrincipal, Capability, ManagementScope, OrganizationId},
    runtime::RuntimeGeneration,
};

#[derive(Clone, Debug)]
pub struct RequestIdentity {
    pub principal: AuthenticatedPrincipal,
    pub generation: Arc<RuntimeGeneration>,
    pub request_id: String,
    pub csrf_validated: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum AuthorizationTarget {
    CurrentPrincipal,
    System {
        capability: Capability,
    },
    Organization {
        organization_id: OrganizationId,
        capability: Capability,
    },
    Operations {
        write: bool,
    },
}

impl AuthorizationTarget {
    #[must_use]
    pub const fn required_scope(self) -> ManagementScope {
        match self {
            Self::CurrentPrincipal | Self::System { .. } | Self::Organization { .. } => {
                ManagementScope::Read
            }
            Self::Operations { write: false } => ManagementScope::Read,
            Self::Operations { write: true } => ManagementScope::Write,
        }
    }
}
