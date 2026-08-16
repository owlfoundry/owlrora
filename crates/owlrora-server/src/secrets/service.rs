use std::{collections::BTreeMap, sync::Arc};

use hkdf::Hkdf;
use hmac::{Hmac, Mac as _};
use sha2::Sha256;

use owlrora_key_provider::{
    ConfigurationSecretOpener, ConfigurationSecretSealer, OpaqueEnvelope, OpenSecretRequest,
    ProtectionContext, ProviderError, ProviderFormatVersion, ProviderId, SealSecretRequest,
    SecretPlaintext,
};
use thiserror::Error;

use crate::config::SecretRoot;

use super::{SoftwareSecretError, SoftwareSecretService};

pub const SOFTWARE_PROVIDER_ID: &str = "software-xchacha20-poly1305";
pub const SOFTWARE_FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CustodyPair {
    provider_id: ProviderId,
    format_version: ProviderFormatVersion,
}

impl CustodyPair {
    #[must_use]
    pub fn new(provider_id: ProviderId, format_version: ProviderFormatVersion) -> Self {
        Self {
            provider_id,
            format_version,
        }
    }

    #[must_use]
    pub fn software() -> Self {
        Self {
            provider_id: ProviderId::new(SOFTWARE_PROVIDER_ID)
                .expect("reserved software provider ID is valid"),
            format_version: ProviderFormatVersion::new(SOFTWARE_FORMAT_VERSION)
                .expect("reserved software format version is valid"),
        }
    }

    #[must_use]
    pub fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    #[must_use]
    pub const fn format_version(&self) -> ProviderFormatVersion {
        self.format_version
    }
}

#[derive(Clone)]
struct RegisteredCustody {
    sealer: Arc<dyn ConfigurationSecretSealer>,
    opener: Arc<dyn ConfigurationSecretOpener>,
}

impl std::fmt::Debug for RegisteredCustody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RegisteredCustody(..)")
    }
}

#[derive(Clone, Default)]
pub struct CustodyRegistry {
    pairs: BTreeMap<CustodyPair, RegisteredCustody>,
}

impl std::fmt::Debug for CustodyRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CustodyRegistry")
            .field("pairs", &self.pairs.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum CustodyCompositionError {
    #[error("custom custody sealer and opener provider IDs do not match")]
    ProviderMismatch,
    #[error("custom custody sealer and opener format versions do not match")]
    FormatVersionsMismatch,
    #[error("the bundled software custody provider ID is reserved")]
    ReservedProviderId,
    #[error("custom custody pair is already registered: {provider_id} format {format_version}")]
    DuplicatePair {
        provider_id: String,
        format_version: u32,
    },
    #[error("active custom custody pair is not registered: {provider_id} format {format_version}")]
    MissingActivePair {
        provider_id: String,
        format_version: u32,
    },
}

impl CustodyRegistry {
    pub fn register(
        &mut self,
        sealer: Arc<dyn ConfigurationSecretSealer>,
        opener: Arc<dyn ConfigurationSecretOpener>,
    ) -> Result<(), CustodyCompositionError> {
        let sealer_id = sealer.provider_id();
        let opener_id = opener.provider_id();
        if sealer_id != opener_id {
            return Err(CustodyCompositionError::ProviderMismatch);
        }
        if sealer_id.as_str() == SOFTWARE_PROVIDER_ID {
            return Err(CustodyCompositionError::ReservedProviderId);
        }
        let sealer_versions = sealer.supported_format_versions();
        let opener_versions = opener.supported_format_versions();
        if sealer_versions != opener_versions {
            return Err(CustodyCompositionError::FormatVersionsMismatch);
        }
        for version in sealer_versions.iter() {
            let pair = CustodyPair::new(sealer_id.clone(), version);
            if self.pairs.contains_key(&pair) {
                return Err(CustodyCompositionError::DuplicatePair {
                    provider_id: sealer_id.as_str().to_owned(),
                    format_version: version.get(),
                });
            }
        }
        for version in sealer_versions.iter() {
            self.pairs.insert(
                CustodyPair::new(sealer_id.clone(), version),
                RegisteredCustody {
                    sealer: Arc::clone(&sealer),
                    opener: Arc::clone(&opener),
                },
            );
        }
        Ok(())
    }

    fn contains(&self, pair: &CustodyPair) -> bool {
        self.pairs.contains_key(pair)
    }

    fn get(&self, pair: &CustodyPair) -> Option<&RegisteredCustody> {
        self.pairs.get(pair)
    }
}

#[derive(Debug, Error)]
pub enum SecretServiceError {
    #[error("configuration secret context uses an unsupported context version")]
    UnsupportedContextVersion,
    #[error("configuration secret custody pair is unavailable")]
    MissingExactPair,
    #[error("bundled software custody is unavailable")]
    SoftwareUnavailable,
    #[error(transparent)]
    Software(#[from] SoftwareSecretError),
    #[error("custom configuration secret custody failed")]
    Custom(#[source] ProviderError),
    #[error("configuration secret value is invalid")]
    InvalidValue,
}

pub struct SecretService {
    software: Option<SoftwareSecretService>,
    mac_root: Option<Arc<SecretRoot>>,
    registry: CustodyRegistry,
    write_pair: CustodyPair,
}

impl std::fmt::Debug for SecretService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretService")
            .field("software", &self.software.as_ref().map(|_| "configured"))
            .field("mac_root", &self.mac_root.as_ref().map(|_| "configured"))
            .field("registry", &self.registry)
            .field("write_pair", &self.write_pair)
            .finish()
    }
}

impl SecretService {
    pub(crate) fn new(
        root: Option<Arc<SecretRoot>>,
        registry: CustodyRegistry,
        write_pair: CustodyPair,
    ) -> Result<Self, CustodyCompositionError> {
        if write_pair != CustodyPair::software() && !registry.contains(&write_pair) {
            return Err(CustodyCompositionError::MissingActivePair {
                provider_id: write_pair.provider_id().as_str().to_owned(),
                format_version: write_pair.format_version().get(),
            });
        }
        let software = root
            .clone()
            .map(SoftwareSecretService::new)
            .transpose()
            .expect("validated secret root always derives a software key");
        Ok(Self {
            software,
            mac_root: root,
            registry,
            write_pair,
        })
    }

    pub(crate) fn with_mac_root(mut self, mac_root: Arc<SecretRoot>) -> Self {
        self.mac_root = Some(mac_root);
        self
    }

    #[must_use]
    pub fn write_pair(&self) -> &CustodyPair {
        &self.write_pair
    }

    #[must_use]
    pub fn supports_open_pair(&self, pair: &CustodyPair) -> bool {
        if pair == &CustodyPair::software() {
            self.software.is_some()
        } else {
            self.registry.contains(pair)
        }
    }

    #[must_use]
    pub fn configured_pairs(&self) -> Vec<CustodyPair> {
        let mut pairs = self.registry.pairs.keys().cloned().collect::<Vec<_>>();
        if self.software.is_some() {
            pairs.push(CustodyPair::software());
        }
        pairs.sort();
        pairs
    }

    pub async fn seal(
        &self,
        context: &ProtectionContext,
        plaintext: &SecretPlaintext,
    ) -> Result<OpaqueEnvelope, SecretServiceError> {
        let pair = pair_from_context(context);
        if pair == CustodyPair::software() {
            return self
                .software
                .as_ref()
                .ok_or(SecretServiceError::SoftwareUnavailable)?
                .seal(context, plaintext)
                .map_err(Into::into);
        }
        let registered = self
            .registry
            .get(&pair)
            .ok_or(SecretServiceError::MissingExactPair)?;
        let request = SealSecretRequest {
            context: context.clone(),
            plaintext: SecretPlaintext::new(plaintext.expose(<[u8]>::to_vec))
                .map_err(|_| SecretServiceError::InvalidValue)?,
        };
        registered
            .sealer
            .seal(request)
            .await
            .map(|sealed| sealed.envelope)
            .map_err(SecretServiceError::Custom)
    }

    pub async fn open(
        &self,
        context: &ProtectionContext,
        envelope: &OpaqueEnvelope,
    ) -> Result<SecretPlaintext, SecretServiceError> {
        let pair = pair_from_context(context);
        if pair == CustodyPair::software() {
            return self
                .software
                .as_ref()
                .ok_or(SecretServiceError::SoftwareUnavailable)?
                .open(context, envelope)
                .map_err(Into::into);
        }
        let registered = self
            .registry
            .get(&pair)
            .ok_or(SecretServiceError::MissingExactPair)?;
        let request = OpenSecretRequest {
            context: context.clone(),
            envelope: OpaqueEnvelope::new(envelope.expose(<[u8]>::to_vec))
                .map_err(|_| SecretServiceError::InvalidValue)?,
        };
        registered
            .opener
            .open(request)
            .await
            .map_err(SecretServiceError::Custom)
    }

    pub(crate) fn derive_idempotency_mac_key(
        &self,
        installation_id: uuid::Uuid,
    ) -> Result<[u8; 32], SecretServiceError> {
        derive_mac_key(
            self.mac_root
                .as_ref()
                .ok_or(SecretServiceError::SoftwareUnavailable)?,
            b"owlrora/upstream-credential/replace-secret/idempotency-mac/v1/key",
            installation_id,
        )
    }

    pub(crate) fn safe_fingerprint(
        &self,
        installation_id: uuid::Uuid,
        value: &[u8],
    ) -> Result<[u8; 32], SecretServiceError> {
        let mut key = derive_mac_key(
            self.mac_root
                .as_ref()
                .ok_or(SecretServiceError::SoftwareUnavailable)?,
            b"owlrora/upstream-credential/safe-fingerprint-mac/v1/key",
            installation_id,
        )?;
        let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(&key)
            .map_err(|_| SecretServiceError::SoftwareUnavailable)?;
        key.fill(0);
        mac.update(value);
        Ok(mac.finalize().into_bytes().into())
    }
}

fn derive_mac_key(
    root: &SecretRoot,
    label: &[u8],
    installation_id: uuid::Uuid,
) -> Result<[u8; 32], SecretServiceError> {
    let hkdf = Hkdf::<Sha256>::new(
        Some(b"owlrora/configuration-secret/hkdf-salt/v1"),
        root.expose(),
    );
    let mut info = Vec::with_capacity(label.len() + 16);
    info.extend_from_slice(label);
    info.extend_from_slice(installation_id.as_bytes());
    let mut key = [0_u8; 32];
    hkdf.expand(&info, &mut key)
        .map_err(|_| SecretServiceError::SoftwareUnavailable)?;
    Ok(key)
}

fn pair_from_context(context: &ProtectionContext) -> CustodyPair {
    CustodyPair::new(
        context.parts().provider_id.clone(),
        context.parts().provider_format_version,
    )
}
