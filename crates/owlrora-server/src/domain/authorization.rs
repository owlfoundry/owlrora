use std::{collections::BTreeSet, fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use super::OrganizationId;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationRole {
    Owner,
    Admin,
    Member,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ManagementScope {
    Read,
    Write,
    Secrets,
    Operations,
    Authority,
}

impl ManagementScope {
    pub const ALL: [Self; 5] = [
        Self::Read,
        Self::Write,
        Self::Secrets,
        Self::Operations,
        Self::Authority,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "management:read",
            Self::Write => "management:write",
            Self::Secrets => "management:secrets",
            Self::Operations => "management:operations",
            Self::Authority => "management:authority",
        }
    }
}

impl Serialize for ManagementScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ManagementScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

impl fmt::Display for ManagementScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ManagementScope {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "management:read" => Ok(Self::Read),
            "management:write" => Ok(Self::Write),
            "management:secrets" => Ok(Self::Secrets),
            "management:operations" => Ok(Self::Operations),
            "management:authority" => Ok(Self::Authority),
            _ => Err(format!("unknown management scope: {value}")),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ManagementScopeSet(BTreeSet<ManagementScope>);

impl ManagementScopeSet {
    #[must_use]
    pub fn all() -> Self {
        Self(ManagementScope::ALL.into_iter().collect())
    }

    #[must_use]
    pub const fn empty() -> Self {
        Self(BTreeSet::new())
    }

    pub fn new(scopes: impl IntoIterator<Item = ManagementScope>) -> Result<Self, String> {
        let scopes = scopes.into_iter().collect::<BTreeSet<_>>();
        if scopes.is_empty() {
            return Err("at least one management scope is required".to_owned());
        }
        Ok(Self(scopes))
    }

    #[must_use]
    pub fn contains(&self, scope: ManagementScope) -> bool {
        self.0.contains(&scope)
    }

    #[must_use]
    pub fn is_superset(&self, other: &Self) -> bool {
        self.0.is_superset(&other.0)
    }

    #[must_use]
    pub fn intersection(&self, other: &Self) -> Self {
        Self(self.0.intersection(&other.0).copied().collect())
    }

    pub fn iter(&self) -> impl Iterator<Item = ManagementScope> + '_ {
        self.0.iter().copied()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResourceScope {
    Deployment,
    Organization { organization_id: OrganizationId },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    SystemAdministration,
    ReadOrganization,
    UpdateOrganization,
    ReadMembers,
    ManageMembers,
    ManageOwners,
    ReadManagementKeys,
    CreateManagementKeys,
    ManageManagementKeys,
    UpdateApiKeyPolicy,
    ReadAudit,
    ManageIdentity,
    ManageSystemKeys,
    ManageSystemOrganizations,
    ManageSystemUsers,
    ManageAdministrators,
    ReadOperations,
    RecoverOperations,
}

impl Capability {
    pub const ALL: [Self; 18] = [
        Self::SystemAdministration,
        Self::ReadOrganization,
        Self::UpdateOrganization,
        Self::ReadMembers,
        Self::ManageMembers,
        Self::ManageOwners,
        Self::ReadManagementKeys,
        Self::CreateManagementKeys,
        Self::ManageManagementKeys,
        Self::UpdateApiKeyPolicy,
        Self::ReadAudit,
        Self::ManageIdentity,
        Self::ManageSystemKeys,
        Self::ManageSystemOrganizations,
        Self::ManageSystemUsers,
        Self::ManageAdministrators,
        Self::ReadOperations,
        Self::RecoverOperations,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SystemAdministration => "system_administration",
            Self::ReadOrganization => "read_organization",
            Self::UpdateOrganization => "update_organization",
            Self::ReadMembers => "read_members",
            Self::ManageMembers => "manage_members",
            Self::ManageOwners => "manage_owners",
            Self::ReadManagementKeys => "read_management_keys",
            Self::CreateManagementKeys => "create_management_keys",
            Self::ManageManagementKeys => "manage_management_keys",
            Self::UpdateApiKeyPolicy => "update_api_key_policy",
            Self::ReadAudit => "read_audit",
            Self::ManageIdentity => "manage_identity",
            Self::ManageSystemKeys => "manage_system_keys",
            Self::ManageSystemOrganizations => "manage_system_organizations",
            Self::ManageSystemUsers => "manage_system_users",
            Self::ManageAdministrators => "manage_administrators",
            Self::ReadOperations => "read_operations",
            Self::RecoverOperations => "recover_operations",
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Capability {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|capability| capability.as_str() == value)
            .ok_or_else(|| format!("unknown capability: {value}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_vocabulary_is_closed() {
        for scope in ManagementScope::ALL {
            assert_eq!(scope.as_str().parse(), Ok(scope));
        }
        assert!("management:*".parse::<ManagementScope>().is_err());
        assert!("management:access".parse::<ManagementScope>().is_err());
    }

    #[test]
    fn intersections_never_expand_scopes() {
        let full = ManagementScopeSet::all();
        let narrow = ManagementScopeSet::new([ManagementScope::Read]).unwrap();
        assert_eq!(full.intersection(&narrow), narrow);
        assert!(full.is_superset(&narrow));
    }
}
