use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value).map(Self)
            }
        }
    };
}

id_type!(UserId);
id_type!(OrganizationId);
id_type!(InvitationId);
id_type!(KeyId);
id_type!(SessionId);
id_type!(IssuerId);
id_type!(BindingId);
id_type!(PolicyId);
id_type!(MaterialVersionId);
id_type!(GatewayKeyId);
id_type!(CredentialId);
id_type!(CredentialSecretVersionId);
id_type!(CredentialLoginSessionId);
id_type!(EndpointId);
id_type!(NetworkPolicyId);
id_type!(DeploymentId);
id_type!(PricingPolicyId);
id_type!(PricingPolicyVersionId);
id_type!(ReliabilityPolicyId);
id_type!(RouteId);
id_type!(TargetId);
id_type!(BudgetPolicyId);
id_type!(BudgetPolicyVersionId);
id_type!(RatePolicyId);
id_type!(RatePolicyVersionId);
id_type!(PolicyActivationId);
id_type!(CoordinatorRecoveryId);
id_type!(UsageReceiptId);
