use std::sync::Arc;

use owlrora_server::{
    ServerBuilder,
    config::ServerConfig,
    key_provider::{
        ConfigurationSecretOpener, ConfigurationSecretSealer, OpaqueEnvelope, OpenSecretRequest,
        ProviderError, ProviderFormatVersion, ProviderFormatVersions, ProviderId,
        SealSecretRequest, SealedSecret, SecretPlaintext, async_trait,
    },
};

struct IndependentCustody;

fn versions() -> ProviderFormatVersions {
    ProviderFormatVersions::new([ProviderFormatVersion::new(7).unwrap()]).unwrap()
}

#[async_trait]
impl ConfigurationSecretSealer for IndependentCustody {
    fn provider_id(&self) -> ProviderId {
        ProviderId::new("independent-custody").unwrap()
    }

    fn supported_format_versions(&self) -> ProviderFormatVersions {
        versions()
    }

    async fn seal(&self, request: SealSecretRequest) -> Result<SealedSecret, ProviderError> {
        Ok(SealedSecret {
            envelope: OpaqueEnvelope::new(request.plaintext.expose(<[u8]>::to_vec)).unwrap(),
        })
    }
}

#[async_trait]
impl ConfigurationSecretOpener for IndependentCustody {
    fn provider_id(&self) -> ProviderId {
        ProviderId::new("independent-custody").unwrap()
    }

    fn supported_format_versions(&self) -> ProviderFormatVersions {
        versions()
    }

    async fn open(&self, request: OpenSecretRequest) -> Result<SecretPlaintext, ProviderError> {
        Ok(SecretPlaintext::new(request.envelope.expose(<[u8]>::to_vec)).unwrap())
    }
}

#[test]
fn independent_crate_can_configure_public_server_builder_without_private_modules() {
    let config = Arc::new(ServerConfig {
        address: "127.0.0.1:0".parse().unwrap(),
        profile: owlrora_server::config::DeploymentProfile::HealthOnly,
        database_url: None,
        public_origin: None,
        seed_admin_key_version_id: None,
        secret_root: None,
        redis_url: None,
        node_instance_id: None,
        operator_networks: vec!["127.0.0.0/8".parse().unwrap()],
        database_max_connections: 2,
        redis_pool_size: 1,
        redis_connect_timeout: std::time::Duration::from_millis(100),
        redis_command_timeout: std::time::Duration::from_millis(100),
        policy_activation_timeout: std::time::Duration::from_secs(30),
        policy_retirement_grace: std::time::Duration::from_mins(1),
        session_lifetime: std::time::Duration::from_hours(1),
        max_security_snapshot_age: std::time::Duration::from_secs(30),
        usage_flush_interval: std::time::Duration::from_secs(5),
        usage_max_aggregate_keys: 4096,
        usage_max_pending_batches: 16,
        gateway_max_in_flight: 4096,
        gateway_endpoint_max_in_flight: 512,
        gateway_credential_max_in_flight: 512,
        gateway_deployment_max_in_flight: 256,
        gateway_websocket_max_connections: 1024,
        gemini_query_key_compatibility: false,
    });
    let provider = Arc::new(IndependentCustody);
    let builder = ServerBuilder::new(config)
        .register_secret_custody(provider.clone(), provider)
        .unwrap()
        .with_secret_write_format(
            ProviderId::new("independent-custody").unwrap(),
            ProviderFormatVersion::new(7).unwrap(),
        );

    assert!(format!("{builder:?}").contains("independent-custody"));
}
