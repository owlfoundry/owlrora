use std::sync::Arc;

use owlrora_key_provider::{
    ConfigurationSecretOpener, ConfigurationSecretSealer, OpaqueEnvelope, OpenSecretRequest,
    ProviderError, ProviderFormatVersion, ProviderFormatVersions, ProviderId, SealSecretRequest,
    SealedSecret, SecretPlaintext, async_trait,
};

struct IndependentProvider;

fn formats() -> ProviderFormatVersions {
    ProviderFormatVersions::new([ProviderFormatVersion::new(1).unwrap()]).unwrap()
}

#[async_trait]
impl ConfigurationSecretSealer for IndependentProvider {
    fn provider_id(&self) -> ProviderId {
        ProviderId::new("independent").unwrap()
    }

    fn supported_format_versions(&self) -> ProviderFormatVersions {
        formats()
    }

    async fn seal(&self, request: SealSecretRequest) -> Result<SealedSecret, ProviderError> {
        assert!(!request.context.canonical_bytes().is_empty());
        assert!(request.plaintext.expose(|value| !value.is_empty()));
        Ok(SealedSecret {
            envelope: OpaqueEnvelope::new(vec![9; 48]).unwrap(),
        })
    }
}

#[async_trait]
impl ConfigurationSecretOpener for IndependentProvider {
    fn provider_id(&self) -> ProviderId {
        ProviderId::new("independent").unwrap()
    }

    fn supported_format_versions(&self) -> ProviderFormatVersions {
        formats()
    }

    async fn open(&self, request: OpenSecretRequest) -> Result<SecretPlaintext, ProviderError> {
        assert!(!request.context.canonical_bytes().is_empty());
        assert!(request.envelope.expose(|value| !value.is_empty()));
        Ok(SecretPlaintext::new(b"opened".to_vec()).unwrap())
    }
}

#[test]
fn independent_crate_can_construct_both_role_objects() {
    let provider = Arc::new(IndependentProvider);
    let sealer: Arc<dyn ConfigurationSecretSealer> = provider.clone();
    let opener: Arc<dyn ConfigurationSecretOpener> = provider;

    assert_eq!(sealer.provider_id().as_str(), "independent");
    assert_eq!(opener.provider_id().as_str(), "independent");
    assert!(
        sealer
            .supported_format_versions()
            .contains(ProviderFormatVersion::new(1).unwrap())
    );
    assert!(
        opener
            .supported_format_versions()
            .contains(ProviderFormatVersion::new(1).unwrap())
    );
}
