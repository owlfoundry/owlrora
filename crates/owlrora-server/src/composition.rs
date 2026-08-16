use std::{collections::HashMap, future::Future, io, net::SocketAddr, sync::Arc};

use axum::Router;
use owlrora_key_provider::{
    ConfigurationSecretOpener, ConfigurationSecretSealer, FieldPurpose, InstallationId, MaterialId,
    OwnerId, OwnerKind, ProtectionContext, ProtectionContextParts, ProviderFormatVersion,
    ProviderId, SecretPlaintext, SecretScope,
};
use rand::RngCore as _;
use sqlx::Row as _;
use tokio::net::TcpListener;
use uuid::Uuid;

use crate::{
    StartupError,
    adapters::{coordinator::RedisCoordinator, postgres::PgStore},
    application::Application,
    config::{DeploymentProfile, SecretRoot, ServerConfig},
    console_router, health_router, http,
    runtime::RuntimePublisher,
    secrets::{CustodyCompositionError, CustodyPair, CustodyRegistry, SecretService},
    shutdown_signal,
};

const MAC_ROOT_OWNER_KIND: &str = "system_secret_authority";
const MAC_ROOT_FIELD_PURPOSE: &str = "server_mac_root";
const MAC_ROOT_OWNER_ID: Uuid = Uuid::from_u128(0x019b_25d7_ef79_7000_8000_0000_0000_0001);
const MAC_ROOT_MATERIAL_ID: Uuid = Uuid::from_u128(0x019b_25d7_ef79_7000_8000_0000_0000_0002);

/// High-level composition API for trusted statically linked custody implementations.
pub struct ServerBuilder {
    config: Arc<ServerConfig>,
    registry: CustodyRegistry,
    write_pair: CustodyPair,
    egress_dns_overrides: HashMap<String, SocketAddr>,
}

impl std::fmt::Debug for ServerBuilder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServerBuilder")
            .field("config", &self.config)
            .field("registry", &self.registry)
            .field("write_pair", &self.write_pair)
            .field(
                "egress_dns_override_count",
                &self.egress_dns_overrides.len(),
            )
            .finish()
    }
}

impl ServerBuilder {
    #[must_use]
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            config,
            registry: CustodyRegistry::default(),
            write_pair: CustodyPair::software(),
            egress_dns_overrides: HashMap::new(),
        }
    }

    pub fn register_secret_custody(
        mut self,
        sealer: Arc<dyn ConfigurationSecretSealer>,
        opener: Arc<dyn ConfigurationSecretOpener>,
    ) -> Result<Self, CustodyCompositionError> {
        self.registry.register(sealer, opener)?;
        Ok(self)
    }

    #[must_use]
    pub fn with_secret_write_format(
        mut self,
        provider_id: ProviderId,
        format_version: ProviderFormatVersion,
    ) -> Self {
        self.write_pair = CustodyPair::new(provider_id, format_version);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_test_egress_dns_override(
        mut self,
        host: impl Into<String>,
        address: SocketAddr,
    ) -> Self {
        self.egress_dns_overrides
            .insert(host.into().to_ascii_lowercase(), address);
        self
    }

    pub async fn build(self) -> Result<BuiltServer, StartupError> {
        if self.config.profile == DeploymentProfile::HealthOnly {
            return Ok(BuiltServer {
                router: health_router(),
                runtime: None,
                application: None,
            });
        }
        let database_url = self
            .config
            .database_url
            .as_deref()
            .ok_or(StartupError::MissingConfiguration("OWLRORA_DATABASE_URL"))?;
        if self.write_pair == CustodyPair::software() && self.config.secret_root.is_none() {
            return Err(StartupError::MissingConfiguration("OWLRORA_SECRET_ROOT"));
        }
        let store = PgStore::connect(database_url, self.config.database_max_connections).await?;
        let mut secrets = SecretService::new(
            self.config.secret_root.clone(),
            self.registry,
            self.write_pair,
        )?;
        validate_persisted_custody_pairs(&store, &secrets).await?;
        validate_inline_oidc_custody_pairs(&store, &secrets).await?;
        if self.config.secret_root.is_none() {
            let mac_root = load_or_initialize_custom_mac_root(&store, &secrets).await?;
            secrets = secrets.with_mac_root(Arc::new(mac_root));
        }
        let secrets = Arc::new(secrets);
        let redis_url = self
            .config
            .redis_url
            .as_ref()
            .ok_or(StartupError::MissingConfiguration("OWLRORA_REDIS_URL"))?;
        let coordinator = Arc::new(
            RedisCoordinator::connect(
                redis_url,
                self.config.redis_pool_size,
                self.config.redis_connect_timeout,
                self.config.redis_command_timeout,
            )
            .await?,
        );
        let runtime = RuntimePublisher::start_with_egress_dns_overrides(
            store.clone(),
            Arc::clone(&secrets),
            self.egress_dns_overrides,
        )
        .await?;
        let application = Arc::new(
            Application::new(
                store,
                Arc::clone(&runtime),
                Arc::clone(&self.config),
                secrets,
            )?
            .with_coordinator(coordinator),
        );
        if self.config.profile.management_workers_enabled() {
            application.start_identity_refresh_controller();
            application.start_codex_credential_workers();
            application.start_policy_activation_worker();
        }
        let mut router = if self.config.profile.management_enabled() {
            console_router()
        } else {
            health_router()
        };
        if self.config.profile.management_enabled() {
            router = router.merge(http::management_router(Arc::clone(&application)));
        }
        if self.config.profile.gateway_enabled() {
            router = router.merge(http::gateway_router(Arc::clone(&application)));
        }
        Ok(BuiltServer {
            router,
            runtime: Some(runtime),
            application: Some(application),
        })
    }
}

/// A fully composed server and the runtime resources it owns.
pub struct BuiltServer {
    router: Router,
    runtime: Option<Arc<RuntimePublisher>>,
    application: Option<Arc<Application>>,
}

impl BuiltServer {
    #[must_use]
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn runtime(&self) -> Option<Arc<RuntimePublisher>> {
        self.runtime.clone()
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn application(&self) -> Option<Arc<Application>> {
        self.application.clone()
    }

    pub fn into_parts(self) -> (Router, Option<Arc<RuntimePublisher>>) {
        (self.router, self.runtime)
    }

    pub async fn serve(self, listener: TcpListener) -> io::Result<()> {
        self.serve_with_shutdown(listener, shutdown_signal()).await
    }

    pub async fn serve_with_shutdown<F>(self, listener: TcpListener, shutdown: F) -> io::Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let Self {
            router,
            runtime,
            application,
        } = self;
        if let Some(application) = &application
            && application.config().profile.gateway_workers_enabled()
        {
            application.start_gateway_workers().await;
        }
        let result = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown)
        .await;
        if let Some(application) = application {
            application.shutdown_gateway_workers().await;
        }
        if let Some(runtime) = runtime {
            runtime.shutdown().await;
        }
        result
    }
}

async fn validate_persisted_custody_pairs(
    store: &PgStore,
    secrets: &SecretService,
) -> Result<(), StartupError> {
    let rows = sqlx::query(
        "SELECT DISTINCT custody_provider_id,provider_format_version,context_version
         FROM protected_secret_versions",
    )
    .fetch_all(store.pool())
    .await?;
    for row in rows {
        let context_version: i32 = row.try_get("context_version")?;
        let provider_id = ProviderId::new(row.try_get::<String, _>("custody_provider_id")?)
            .map_err(|_| StartupError::InvalidCustodyMetadata)?;
        let format_version = ProviderFormatVersion::new(
            u32::try_from(row.try_get::<i32, _>("provider_format_version")?)
                .map_err(|_| StartupError::InvalidCustodyMetadata)?,
        )
        .map_err(|_| StartupError::InvalidCustodyMetadata)?;
        if context_version != 1
            || !secrets.supports_open_pair(&CustodyPair::new(provider_id, format_version))
        {
            return Err(StartupError::UnsupportedPersistedCustody);
        }
    }
    Ok(())
}

async fn validate_inline_oidc_custody_pairs(
    store: &PgStore,
    secrets: &SecretService,
) -> Result<(), StartupError> {
    let rows = sqlx::query(
        "SELECT DISTINCT pkce_custody_provider_id AS provider_id,
                pkce_provider_format_version AS format_version,pkce_context_version AS context_version
         FROM oidc_login_states WHERE consumed_at IS NULL AND expires_at>now()
         UNION
         SELECT DISTINCT custody_provider_id AS provider_id,
                provider_format_version AS format_version,context_version
         FROM protected_secret_versions
         WHERE owner_kind='identity_issuer' AND field_purpose='oidc_client_secret'",
    )
    .fetch_all(store.pool())
    .await?;
    for row in rows {
        let context_version: i32 = row.try_get("context_version")?;
        let provider_id = ProviderId::new(row.try_get::<String, _>("provider_id")?)
            .map_err(|_| StartupError::InvalidCustodyMetadata)?;
        let format_version = ProviderFormatVersion::new(
            u32::try_from(row.try_get::<i32, _>("format_version")?)
                .map_err(|_| StartupError::InvalidCustodyMetadata)?,
        )
        .map_err(|_| StartupError::InvalidCustodyMetadata)?;
        if context_version != 1
            || !secrets.supports_open_pair(&CustodyPair::new(provider_id, format_version))
        {
            return Err(StartupError::UnsupportedPersistedCustody);
        }
    }
    Ok(())
}

async fn load_or_initialize_custom_mac_root(
    store: &PgStore,
    secrets: &SecretService,
) -> Result<SecretRoot, StartupError> {
    let existing = sqlx::query(
        "SELECT custody_provider_id,provider_format_version,context_version,opaque_envelope
         FROM protected_secret_versions
         WHERE owner_kind=$1 AND owner_id=$2 AND owner_generation=1
           AND secret_version=1 AND field_purpose=$3",
    )
    .bind(MAC_ROOT_OWNER_KIND)
    .bind(MAC_ROOT_OWNER_ID)
    .bind(MAC_ROOT_FIELD_PURPOSE)
    .fetch_optional(store.pool())
    .await?;
    if let Some(row) = existing {
        return open_mac_root(store, secrets, &row).await;
    }

    let pair = secrets.write_pair().clone();
    let context = mac_root_context(store.installation_id(), &pair)?;
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let plaintext =
        SecretPlaintext::new(bytes.to_vec()).map_err(|_| StartupError::InvalidCustodyMetadata)?;
    bytes.fill(0);
    let envelope = secrets
        .seal(&context, &plaintext)
        .await
        .map_err(StartupError::SecretService)?;
    let inserted = sqlx::query(
        "INSERT INTO protected_secret_versions(
            id,scope_kind,organization_id,owner_kind,owner_id,owner_generation,secret_version,
            field_purpose,custody_provider_id,provider_format_version,context_version,opaque_envelope
         ) VALUES ($1,'system',NULL,$2,$3,1,1,$4,$5,$6,1,$7)
         ON CONFLICT (owner_kind,owner_id,owner_generation,secret_version,field_purpose)
         DO NOTHING",
    )
    .bind(MAC_ROOT_MATERIAL_ID)
    .bind(MAC_ROOT_OWNER_KIND)
    .bind(MAC_ROOT_OWNER_ID)
    .bind(MAC_ROOT_FIELD_PURPOSE)
    .bind(pair.provider_id().as_str())
    .bind(i32::try_from(pair.format_version().get()).map_err(|_| StartupError::InvalidCustodyMetadata)?)
    .bind(envelope.expose(<[u8]>::to_vec))
    .execute(store.pool())
    .await?
    .rows_affected();
    if inserted == 1 {
        return plaintext
            .expose(|value| value.try_into())
            .map(SecretRoot::from_bytes)
            .map_err(|_| StartupError::InvalidCustodyMetadata);
    }
    let row = sqlx::query(
        "SELECT custody_provider_id,provider_format_version,context_version,opaque_envelope
         FROM protected_secret_versions
         WHERE owner_kind=$1 AND owner_id=$2 AND owner_generation=1
           AND secret_version=1 AND field_purpose=$3",
    )
    .bind(MAC_ROOT_OWNER_KIND)
    .bind(MAC_ROOT_OWNER_ID)
    .bind(MAC_ROOT_FIELD_PURPOSE)
    .fetch_one(store.pool())
    .await?;
    open_mac_root(store, secrets, &row).await
}

async fn open_mac_root(
    store: &PgStore,
    secrets: &SecretService,
    row: &sqlx::postgres::PgRow,
) -> Result<SecretRoot, StartupError> {
    if row.try_get::<i32, _>("context_version")? != 1 {
        return Err(StartupError::UnsupportedPersistedCustody);
    }
    let pair = CustodyPair::new(
        ProviderId::new(row.try_get::<String, _>("custody_provider_id")?)
            .map_err(|_| StartupError::InvalidCustodyMetadata)?,
        ProviderFormatVersion::new(
            u32::try_from(row.try_get::<i32, _>("provider_format_version")?)
                .map_err(|_| StartupError::InvalidCustodyMetadata)?,
        )
        .map_err(|_| StartupError::InvalidCustodyMetadata)?,
    );
    let context = mac_root_context(store.installation_id(), &pair)?;
    let envelope =
        owlrora_key_provider::OpaqueEnvelope::new(row.try_get::<Vec<u8>, _>("opaque_envelope")?)
            .map_err(|_| StartupError::InvalidCustodyMetadata)?;
    let plaintext = secrets
        .open(&context, &envelope)
        .await
        .map_err(StartupError::SecretService)?;
    plaintext
        .expose(|value| value.try_into())
        .map(SecretRoot::from_bytes)
        .map_err(|_| StartupError::InvalidCustodyMetadata)
}

fn mac_root_context(
    installation_id: Uuid,
    pair: &CustodyPair,
) -> Result<ProtectionContext, StartupError> {
    ProtectionContext::new(ProtectionContextParts {
        version: owlrora_key_provider::ContextVersion::V1,
        installation_id: InstallationId::new(installation_id.to_string())
            .map_err(|_| StartupError::InvalidCustodyMetadata)?,
        scope: SecretScope::System,
        material_id: MaterialId::new(MAC_ROOT_MATERIAL_ID.to_string())
            .map_err(|_| StartupError::InvalidCustodyMetadata)?,
        owner_kind: OwnerKind::new(MAC_ROOT_OWNER_KIND)
            .map_err(|_| StartupError::InvalidCustodyMetadata)?,
        owner_id: OwnerId::new(MAC_ROOT_OWNER_ID.to_string())
            .map_err(|_| StartupError::InvalidCustodyMetadata)?,
        owner_generation: 1,
        secret_version: 1,
        field_purpose: FieldPurpose::new(MAC_ROOT_FIELD_PURPOSE)
            .map_err(|_| StartupError::InvalidCustodyMetadata)?,
        provider_id: pair.provider_id().clone(),
        provider_format_version: pair.format_version(),
    })
    .map_err(|_| StartupError::InvalidCustodyMetadata)
}
