use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tokio::sync::Semaphore;

use crate::domain::IssuerId;

use crate::{
    adapters::{coordinator::RedisCoordinator, postgres::PgStore, provider::codex::CodexAdapter},
    config::ServerConfig,
    gateway::{
        GatewayAdmissionState, TargetProbeObservation, TargetProbeWorker, TargetProtectionState,
        UsageAggregator, UsageConfig, UsageStatus,
    },
    runtime::RuntimePublisher,
    secrets::SecretService,
};

#[derive(Debug, Default)]
pub(crate) struct IssuerRefreshSchedule {
    pub(crate) in_flight: HashSet<IssuerId>,
    pub(crate) next_allowed: HashMap<IssuerId, Instant>,
}

#[derive(Clone, Debug)]
struct RateWindow {
    started_at: Instant,
    count: u32,
}

#[derive(Debug, Default)]
pub(crate) struct OidcLoginRateState {
    deployment: Option<RateWindow>,
    issuers: HashMap<String, RateWindow>,
    sources: HashMap<(IpAddr, String), RateWindow>,
}

impl OidcLoginRateState {
    pub(crate) fn check(
        &mut self,
        source: IpAddr,
        issuer: &str,
    ) -> Result<(), crate::application::ApplicationError> {
        const WINDOW: Duration = Duration::from_secs(60);
        let now = Instant::now();
        self.issuers
            .retain(|_, window| now.duration_since(window.started_at) < WINDOW);
        self.sources
            .retain(|_, window| now.duration_since(window.started_at) < WINDOW);
        check_optional_window(&mut self.deployment, now, WINDOW, 600)?;
        check_window(
            self.issuers.entry(issuer.to_owned()).or_insert(RateWindow {
                started_at: now,
                count: 0,
            }),
            now,
            WINDOW,
            120,
        )?;
        if self.sources.len() >= 10_000 && !self.sources.contains_key(&(source, issuer.to_owned()))
        {
            return Err(crate::application::ApplicationError::RateLimited);
        }
        check_window(
            self.sources
                .entry((source, issuer.to_owned()))
                .or_insert(RateWindow {
                    started_at: now,
                    count: 0,
                }),
            now,
            WINDOW,
            10,
        )
    }
}

fn check_window(
    window: &mut RateWindow,
    now: Instant,
    duration: Duration,
    maximum: u32,
) -> Result<(), crate::application::ApplicationError> {
    if now.duration_since(window.started_at) >= duration {
        window.started_at = now;
        window.count = 0;
    }
    if window.count >= maximum {
        return Err(crate::application::ApplicationError::RateLimited);
    }
    window.count += 1;
    Ok(())
}

fn check_optional_window(
    window: &mut Option<RateWindow>,
    now: Instant,
    duration: Duration,
    maximum: u32,
) -> Result<(), crate::application::ApplicationError> {
    let window = window.get_or_insert(RateWindow {
        started_at: now,
        count: 0,
    });
    check_window(window, now, duration, maximum)
}

#[derive(Clone)]
pub struct Application {
    pub(crate) store: PgStore,
    pub(crate) runtime: Arc<RuntimePublisher>,
    pub(crate) config: Arc<ServerConfig>,
    pub(crate) secrets: Arc<SecretService>,
    pub(crate) coordinator: Option<Arc<RedisCoordinator>>,
    pub(crate) gateway_admission: Arc<GatewayAdmissionState>,
    pub(crate) target_protection: Arc<TargetProtectionState>,
    pub(crate) target_probes: Option<Arc<TargetProbeWorker>>,
    pub(crate) usage: Arc<UsageAggregator>,
    pub(crate) websocket_connections: Arc<Semaphore>,
    pub(crate) codex: Arc<CodexAdapter>,
    pub(crate) issuer_refresh_schedule: Arc<Mutex<IssuerRefreshSchedule>>,
    pub(crate) issuer_refresh_permits: Arc<Semaphore>,
    pub(crate) oidc_login_rate: Arc<Mutex<OidcLoginRateState>>,
    pub(crate) oidc_login_permits: Arc<Semaphore>,
    pub(crate) oidc_callback_permits: Arc<Semaphore>,
}

impl std::fmt::Debug for Application {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Application")
            .field("store", &self.store)
            .field("runtime", &self.runtime)
            .field("config", &self.config)
            .field("secrets", &self.secrets)
            .field("coordinator", &self.coordinator)
            .field("gateway_admission", &self.gateway_admission)
            .field("target_protection", &self.target_protection)
            .field(
                "target_probe_observation_count",
                &self.target_probe_observations().len(),
            )
            .field("usage", &self.usage.status())
            .field(
                "available_websocket_connections",
                &self.websocket_connections.available_permits(),
            )
            .field("codex", &self.codex)
            .field("issuer_refresh_schedule", &self.issuer_refresh_schedule)
            .finish_non_exhaustive()
    }
}

impl Application {
    #[must_use]
    pub fn new(
        store: PgStore,
        runtime: Arc<RuntimePublisher>,
        config: Arc<ServerConfig>,
        secrets: Arc<SecretService>,
    ) -> Result<Self, crate::application::ApplicationError> {
        let node_instance_id = config
            .node_instance_id
            .clone()
            .unwrap_or_else(|| "unconfigured".to_owned());
        let usage = UsageAggregator::new(
            store.clone(),
            UsageConfig {
                flush_interval: config.usage_flush_interval,
                max_aggregate_keys: config.usage_max_aggregate_keys,
                max_pending_batches: config.usage_max_pending_batches,
            },
        );
        let websocket_max_connections = config.gateway_websocket_max_connections;
        let target_protection = Arc::new(TargetProtectionState::new(
            config.gateway_max_in_flight,
            config.gateway_endpoint_max_in_flight,
            config.gateway_credential_max_in_flight,
            config.gateway_deployment_max_in_flight,
        ));
        Ok(Self {
            store,
            runtime,
            config,
            secrets,
            coordinator: None,
            gateway_admission: Arc::new(GatewayAdmissionState::new(node_instance_id)),
            target_protection,
            target_probes: None,
            usage,
            websocket_connections: Arc::new(Semaphore::new(websocket_max_connections)),
            codex: Arc::new(
                CodexAdapter::new()
                    .map_err(|_| crate::application::ApplicationError::DependencyUnavailable)?,
            ),
            issuer_refresh_schedule: Arc::new(Mutex::new(IssuerRefreshSchedule::default())),
            issuer_refresh_permits: Arc::new(Semaphore::new(4)),
            oidc_login_rate: Arc::new(Mutex::new(OidcLoginRateState::default())),
            oidc_login_permits: Arc::new(Semaphore::new(16)),
            oidc_callback_permits: Arc::new(Semaphore::new(16)),
        })
    }

    #[must_use]
    pub fn with_coordinator(mut self, coordinator: Arc<RedisCoordinator>) -> Self {
        let node_instance_id = self
            .config
            .node_instance_id
            .clone()
            .unwrap_or_else(|| "unconfigured".to_owned());
        self.target_probes = Some(TargetProbeWorker::new(
            Arc::clone(&self.runtime),
            Arc::clone(&coordinator),
            Arc::clone(&self.target_protection),
            node_instance_id,
        ));
        self.coordinator = Some(coordinator);
        self
    }

    pub async fn start_gateway_workers(&self) {
        self.usage.start().await;
        if let Some(coordinator) = &self.coordinator {
            self.gateway_admission.start(Arc::clone(coordinator)).await;
        }
        if let Some(target_probes) = &self.target_probes {
            target_probes.start().await;
        }
    }

    pub async fn shutdown_gateway_workers(&self) {
        if let Some(target_probes) = &self.target_probes {
            target_probes.shutdown().await;
        }
        self.gateway_admission
            .shutdown(self.coordinator.as_ref())
            .await;
        self.usage.shutdown().await;
    }

    #[must_use]
    pub(crate) fn usage_status(&self) -> UsageStatus {
        self.usage.status()
    }

    #[must_use]
    pub(crate) fn target_probe_observations(&self) -> Vec<TargetProbeObservation> {
        self.target_probes
            .as_ref()
            .map_or_else(Vec::new, |worker| worker.observations())
    }

    #[must_use]
    pub const fn store(&self) -> &PgStore {
        &self.store
    }

    #[must_use]
    pub fn runtime(&self) -> &Arc<RuntimePublisher> {
        &self.runtime
    }

    #[must_use]
    pub(crate) fn config(&self) -> &ServerConfig {
        &self.config
    }

    pub(crate) async fn publish_committed_runtime(
        &self,
        request_id: &str,
        operation_id: &'static str,
    ) {
        if let Err(error) = self.runtime.refresh_now().await {
            tracing::error!(
                request_id,
                operation_id,
                %error,
                "command committed with runtime publication pending"
            );
        }
    }
}
