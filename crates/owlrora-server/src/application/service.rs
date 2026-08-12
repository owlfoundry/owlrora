use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tokio::sync::Semaphore;

use crate::domain::IssuerId;

use crate::{
    adapters::postgres::PgStore, config::ServerConfig, runtime::RuntimePublisher,
    secrets::SoftwareSecretService,
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
    pub(crate) secrets: Arc<SoftwareSecretService>,
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
        secrets: Arc<SoftwareSecretService>,
    ) -> Result<Self, crate::application::ApplicationError> {
        Ok(Self {
            store,
            runtime,
            config,
            secrets,
            issuer_refresh_schedule: Arc::new(Mutex::new(IssuerRefreshSchedule::default())),
            issuer_refresh_permits: Arc::new(Semaphore::new(4)),
            oidc_login_rate: Arc::new(Mutex::new(OidcLoginRateState::default())),
            oidc_login_permits: Arc::new(Semaphore::new(16)),
            oidc_callback_permits: Arc::new(Semaphore::new(16)),
        })
    }

    #[must_use]
    pub const fn store(&self) -> &PgStore {
        &self.store
    }

    #[must_use]
    pub fn runtime(&self) -> &Arc<RuntimePublisher> {
        &self.runtime
    }

    pub(crate) async fn publish_committed_runtime(
        &self,
        request_id: &str,
        operation_id: &'static str,
    ) {
        if let Err(error) = self.runtime.refresh_now(&self.store).await {
            tracing::error!(
                request_id,
                operation_id,
                %error,
                "command committed with runtime publication pending"
            );
        }
    }
}
