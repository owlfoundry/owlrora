use crate::{ProviderFormatVersion, ProviderId, ValueError};

macro_rules! bounded_identifier {
    ($name:ident, $max:expr) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub const MAX_LEN: usize = $max;

            /// Creates a non-empty bounded canonical identifier.
            ///
            /// # Errors
            ///
            /// Returns [`ValueError`] when empty, oversized, or non-canonical.
            pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
                let value = value.into();
                if value.is_empty() {
                    return Err(ValueError::Empty);
                }
                if value.len() > Self::MAX_LEN {
                    return Err(ValueError::TooLong { max: Self::MAX_LEN });
                }
                if !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-.:/".contains(&byte))
                {
                    return Err(ValueError::InvalidCharacters);
                }
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

bounded_identifier!(InstallationId, 128);
bounded_identifier!(OrganizationId, 128);
bounded_identifier!(MaterialId, 128);
bounded_identifier!(OwnerKind, 64);
bounded_identifier!(OwnerId, 128);
bounded_identifier!(FieldPurpose, 64);

/// Version of the server-owned canonical protection-context encoding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ContextVersion {
    V1,
}

impl ContextVersion {
    const fn wire_value(self) -> u32 {
        match self {
            Self::V1 => 1,
        }
    }
}

/// Immutable resource scope authenticated into a protected envelope.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SecretScope {
    System,
    Organization(OrganizationId),
}

/// Typed source fields for one exact protection context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionContextParts {
    pub version: ContextVersion,
    pub installation_id: InstallationId,
    pub scope: SecretScope,
    pub material_id: MaterialId,
    pub owner_kind: OwnerKind,
    pub owner_id: OwnerId,
    pub owner_generation: u64,
    pub secret_version: u64,
    pub field_purpose: FieldPurpose,
    pub provider_id: ProviderId,
    pub provider_format_version: ProviderFormatVersion,
}

/// Validated exact context and its canonical length-delimited encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionContext {
    parts: ProtectionContextParts,
    canonical: Vec<u8>,
}

impl ProtectionContext {
    /// Validates context counters and constructs canonical versioned bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Zero`] when an owner or secret version is zero.
    pub fn new(parts: ProtectionContextParts) -> Result<Self, ValueError> {
        if parts.owner_generation == 0 || parts.secret_version == 0 {
            return Err(ValueError::Zero);
        }
        let canonical = encode(&parts);
        Ok(Self { parts, canonical })
    }

    #[must_use]
    pub const fn parts(&self) -> &ProtectionContextParts {
        &self.parts
    }

    /// Returns server-defined bytes that custom providers must authenticate exactly.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
}

fn encode(parts: &ProtectionContextParts) -> Vec<u8> {
    let mut output = Vec::with_capacity(512);
    output.extend_from_slice(b"OWLRORA_CONFIGURATION_SECRET_CONTEXT\0");
    output.extend_from_slice(&parts.version.wire_value().to_be_bytes());
    push_text(&mut output, parts.installation_id.as_str());
    match &parts.scope {
        SecretScope::System => output.push(0),
        SecretScope::Organization(organization_id) => {
            output.push(1);
            push_text(&mut output, organization_id.as_str());
        }
    }
    push_text(&mut output, parts.material_id.as_str());
    push_text(&mut output, parts.owner_kind.as_str());
    push_text(&mut output, parts.owner_id.as_str());
    output.extend_from_slice(&parts.owner_generation.to_be_bytes());
    output.extend_from_slice(&parts.secret_version.to_be_bytes());
    push_text(&mut output, parts.field_purpose.as_str());
    push_text(&mut output, parts.provider_id.as_str());
    output.extend_from_slice(&parts.provider_format_version.get().to_be_bytes());
    output
}

fn push_text(output: &mut Vec<u8>, value: &str) {
    let length = u16::try_from(value.len()).expect("bounded identifiers fit in u16");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(scope: SecretScope) -> ProtectionContext {
        ProtectionContext::new(ProtectionContextParts {
            version: ContextVersion::V1,
            installation_id: InstallationId::new("install_01").unwrap(),
            scope,
            material_id: MaterialId::new("secret_01").unwrap(),
            owner_kind: OwnerKind::new("upstream_credential").unwrap(),
            owner_id: OwnerId::new("credential_01").unwrap(),
            owner_generation: 4,
            secret_version: 7,
            field_purpose: FieldPurpose::new("api_key").unwrap(),
            provider_id: ProviderId::new("example-kms").unwrap(),
            provider_format_version: ProviderFormatVersion::new(2).unwrap(),
        })
        .unwrap()
    }

    #[test]
    fn encoding_is_deterministic_and_scope_bound() {
        let organization = SecretScope::Organization(OrganizationId::new("org_01").unwrap());
        let first = context(organization.clone());
        let second = context(organization);
        let system = context(SecretScope::System);

        assert_eq!(first.canonical_bytes(), second.canonical_bytes());
        assert_ne!(first.canonical_bytes(), system.canonical_bytes());
    }

    #[test]
    fn zero_generations_are_rejected() {
        let mut parts = context(SecretScope::System).parts().clone();
        parts.secret_version = 0;

        assert_eq!(ProtectionContext::new(parts), Err(ValueError::Zero));
    }

    #[test]
    fn identifiers_reject_whitespace_and_control_bytes() {
        assert!(OwnerId::new("owner with space").is_err());
        assert!(OwnerId::new("owner\nline").is_err());
        assert!(OwnerId::new("owner_01").is_ok());
    }
}
