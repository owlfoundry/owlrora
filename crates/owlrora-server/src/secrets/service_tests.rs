use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use owlrora_key_provider::{
    ConfigurationSecretOpener, ConfigurationSecretSealer, ContextVersion, FieldPurpose,
    InstallationId, MaterialId, OpaqueEnvelope, OpenSecretRequest, OwnerId, OwnerKind,
    ProtectionContext, ProtectionContextParts, ProviderError, ProviderErrorClass,
    ProviderFormatVersion, ProviderFormatVersions, ProviderId, RetryClassification,
    SealSecretRequest, SealedSecret, SecretPlaintext, SecretScope, async_trait,
};

use crate::config::SecretRoot;

use super::{
    CustodyCompositionError, CustodyPair, CustodyRegistry, SOFTWARE_PROVIDER_ID, SecretService,
    SecretServiceError,
};

struct TestProvider {
    provider_id: ProviderId,
    versions: ProviderFormatVersions,
    calls: Arc<AtomicUsize>,
    fail: bool,
}

impl TestProvider {
    fn new(provider_id: &str, versions: &[u32], calls: Arc<AtomicUsize>, fail: bool) -> Self {
        Self {
            provider_id: ProviderId::new(provider_id).unwrap(),
            versions: ProviderFormatVersions::new(
                versions
                    .iter()
                    .map(|version| ProviderFormatVersion::new(*version).unwrap()),
            )
            .unwrap(),
            calls,
            fail,
        }
    }

    fn failure() -> ProviderError {
        ProviderError::new(
            ProviderErrorClass::Unavailable,
            RetryClassification::Backoff,
        )
    }
}

#[async_trait]
impl ConfigurationSecretSealer for TestProvider {
    fn provider_id(&self) -> ProviderId {
        self.provider_id.clone()
    }

    fn supported_format_versions(&self) -> ProviderFormatVersions {
        self.versions.clone()
    }

    async fn seal(&self, request: SealSecretRequest) -> Result<SealedSecret, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(Self::failure());
        }
        let bytes = request.plaintext.expose(<[u8]>::to_vec);
        Ok(SealedSecret {
            envelope: OpaqueEnvelope::new(bytes).unwrap(),
        })
    }
}

#[async_trait]
impl ConfigurationSecretOpener for TestProvider {
    fn provider_id(&self) -> ProviderId {
        self.provider_id.clone()
    }

    fn supported_format_versions(&self) -> ProviderFormatVersions {
        self.versions.clone()
    }

    async fn open(&self, request: OpenSecretRequest) -> Result<SecretPlaintext, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(Self::failure());
        }
        SecretPlaintext::new(request.envelope.expose(<[u8]>::to_vec)).map_err(|_| Self::failure())
    }
}

fn pair(provider_id: &str, version: u32) -> CustodyPair {
    CustodyPair::new(
        ProviderId::new(provider_id).unwrap(),
        ProviderFormatVersion::new(version).unwrap(),
    )
}

fn context(pair: &CustodyPair) -> ProtectionContext {
    ProtectionContext::new(ProtectionContextParts {
        version: ContextVersion::V1,
        installation_id: InstallationId::new("installation-01").unwrap(),
        scope: SecretScope::System,
        material_id: MaterialId::new("material-01").unwrap(),
        owner_kind: OwnerKind::new("upstream_credential").unwrap(),
        owner_id: OwnerId::new("credential-01").unwrap(),
        owner_generation: 1,
        secret_version: 1,
        field_purpose: FieldPurpose::new("upstream_credential_material").unwrap(),
        provider_id: pair.provider_id().clone(),
        provider_format_version: pair.format_version(),
    })
    .unwrap()
}

fn register(
    registry: &mut CustodyRegistry,
    sealer: Arc<TestProvider>,
    opener: Arc<TestProvider>,
) -> Result<(), CustodyCompositionError> {
    registry.register(sealer, opener)
}

#[test]
fn registry_rejects_duplicate_mismatched_and_reserved_pairs() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut registry = CustodyRegistry::default();
    register(
        &mut registry,
        Arc::new(TestProvider::new(
            "custom-one",
            &[1],
            Arc::clone(&calls),
            false,
        )),
        Arc::new(TestProvider::new(
            "custom-two",
            &[1],
            Arc::clone(&calls),
            false,
        )),
    )
    .unwrap_err();
    register(
        &mut registry,
        Arc::new(TestProvider::new(
            "custom-one",
            &[1],
            Arc::clone(&calls),
            false,
        )),
        Arc::new(TestProvider::new(
            "custom-one",
            &[2],
            Arc::clone(&calls),
            false,
        )),
    )
    .unwrap_err();
    register(
        &mut registry,
        Arc::new(TestProvider::new(
            SOFTWARE_PROVIDER_ID,
            &[1],
            Arc::clone(&calls),
            false,
        )),
        Arc::new(TestProvider::new(
            SOFTWARE_PROVIDER_ID,
            &[1],
            Arc::clone(&calls),
            false,
        )),
    )
    .unwrap_err();

    register(
        &mut registry,
        Arc::new(TestProvider::new(
            "custom-one",
            &[1],
            Arc::clone(&calls),
            false,
        )),
        Arc::new(TestProvider::new(
            "custom-one",
            &[1],
            Arc::clone(&calls),
            false,
        )),
    )
    .unwrap();
    let duplicate = register(
        &mut registry,
        Arc::new(TestProvider::new(
            "custom-one",
            &[1],
            Arc::clone(&calls),
            false,
        )),
        Arc::new(TestProvider::new("custom-one", &[1], calls, false)),
    )
    .unwrap_err();
    assert!(matches!(
        duplicate,
        CustodyCompositionError::DuplicatePair { .. }
    ));
}

#[tokio::test]
async fn exact_pair_dispatch_never_falls_back_to_another_custom_or_software_pair() {
    let first_calls = Arc::new(AtomicUsize::new(0));
    let second_calls = Arc::new(AtomicUsize::new(0));
    let mut registry = CustodyRegistry::default();
    register(
        &mut registry,
        Arc::new(TestProvider::new(
            "custom-one",
            &[1],
            Arc::clone(&first_calls),
            false,
        )),
        Arc::new(TestProvider::new(
            "custom-one",
            &[1],
            Arc::clone(&first_calls),
            false,
        )),
    )
    .unwrap();
    register(
        &mut registry,
        Arc::new(TestProvider::new(
            "custom-two",
            &[1],
            Arc::clone(&second_calls),
            false,
        )),
        Arc::new(TestProvider::new(
            "custom-two",
            &[1],
            Arc::clone(&second_calls),
            false,
        )),
    )
    .unwrap();
    let service = SecretService::new(
        Some(Arc::new(SecretRoot::from_bytes([7; 32]))),
        registry,
        pair("custom-one", 1),
    )
    .unwrap();
    let plaintext = SecretPlaintext::new(b"secret".to_vec()).unwrap();
    let second_context = context(&pair("custom-two", 1));
    let envelope = service.seal(&second_context, &plaintext).await.unwrap();
    let opened = service.open(&second_context, &envelope).await.unwrap();
    assert_eq!(opened.expose(<[u8]>::to_vec), b"secret");
    assert_eq!(first_calls.load(Ordering::SeqCst), 0);
    assert_eq!(second_calls.load(Ordering::SeqCst), 2);

    let missing_context = context(&pair("custom-missing", 1));
    let missing = service
        .seal(&missing_context, &plaintext)
        .await
        .unwrap_err();
    assert!(matches!(missing, SecretServiceError::MissingExactPair));
    assert_eq!(first_calls.load(Ordering::SeqCst), 0);
    assert_eq!(second_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn provider_failure_is_returned_without_fallback() {
    let failing_calls = Arc::new(AtomicUsize::new(0));
    let fallback_calls = Arc::new(AtomicUsize::new(0));
    let mut registry = CustodyRegistry::default();
    register(
        &mut registry,
        Arc::new(TestProvider::new(
            "failing",
            &[1],
            Arc::clone(&failing_calls),
            true,
        )),
        Arc::new(TestProvider::new(
            "failing",
            &[1],
            Arc::clone(&failing_calls),
            true,
        )),
    )
    .unwrap();
    register(
        &mut registry,
        Arc::new(TestProvider::new(
            "fallback",
            &[1],
            Arc::clone(&fallback_calls),
            false,
        )),
        Arc::new(TestProvider::new(
            "fallback",
            &[1],
            Arc::clone(&fallback_calls),
            false,
        )),
    )
    .unwrap();
    let service = SecretService::new(
        Some(Arc::new(SecretRoot::from_bytes([9; 32]))),
        registry,
        pair("failing", 1),
    )
    .unwrap();
    let plaintext = SecretPlaintext::new(b"secret".to_vec()).unwrap();
    let error = service
        .seal(&context(&pair("failing", 1)), &plaintext)
        .await
        .unwrap_err();
    assert!(matches!(error, SecretServiceError::Custom(_)));
    assert_eq!(failing_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
}
