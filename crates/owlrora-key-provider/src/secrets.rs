use std::fmt;

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::{
    OpaqueEnvelope, ProtectionContext, ProviderError, ProviderFormatVersions, ProviderId,
    ValueError,
};

/// Bounded confidential plaintext that zeroizes its allocation on drop.
pub struct SecretPlaintext(Zeroizing<Vec<u8>>);

impl SecretPlaintext {
    pub const MAX_LEN: usize = 65_536;

    /// Creates non-empty bounded confidential plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when plaintext is empty or oversized.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, ValueError> {
        let value = Zeroizing::new(value.into());
        if value.is_empty() {
            return Err(ValueError::Empty);
        }
        if value.len() > Self::MAX_LEN {
            return Err(ValueError::TooLong { max: Self::MAX_LEN });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Exposes plaintext only for the duration of the supplied closure.
    pub fn expose<R>(&self, operation: impl FnOnce(&[u8]) -> R) -> R {
        operation(&self.0)
    }
}

impl fmt::Debug for SecretPlaintext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretPlaintext")
            .field("len", &self.len())
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Exact-context request to seal one configuration secret.
pub struct SealSecretRequest {
    pub context: ProtectionContext,
    pub plaintext: SecretPlaintext,
}

impl fmt::Debug for SealSecretRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealSecretRequest")
            .field("context", &self.context)
            .field("plaintext", &self.plaintext)
            .finish()
    }
}

/// Exact-context request to open one configuration secret.
pub struct OpenSecretRequest {
    pub context: ProtectionContext,
    pub envelope: OpaqueEnvelope,
}

impl fmt::Debug for OpenSecretRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenSecretRequest")
            .field("context", &self.context)
            .field("envelope", &self.envelope)
            .finish()
    }
}

/// Successful custom-provider seal result.
#[derive(Debug)]
pub struct SealedSecret {
    pub envelope: OpaqueEnvelope,
}

/// Object-safe custom-provider capability for sealing configuration secrets.
#[async_trait]
pub trait ConfigurationSecretSealer: Send + Sync {
    fn provider_id(&self) -> ProviderId;
    fn supported_format_versions(&self) -> ProviderFormatVersions;

    async fn seal(&self, request: SealSecretRequest) -> Result<SealedSecret, ProviderError>;
}

/// Object-safe custom-provider capability for opening configuration secrets.
#[async_trait]
pub trait ConfigurationSecretOpener: Send + Sync {
    fn provider_id(&self) -> ProviderId;
    fn supported_format_versions(&self) -> ProviderFormatVersions;

    async fn open(&self, request: OpenSecretRequest) -> Result<SecretPlaintext, ProviderError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_debug_is_redacted() {
        let plaintext = SecretPlaintext::new(b"provider secret".to_vec()).unwrap();
        let debug = format!("{plaintext:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("provider secret"));
    }
}
