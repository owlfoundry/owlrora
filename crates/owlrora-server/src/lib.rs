#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::clone_on_copy,
    clippy::collapsible_if,
    clippy::default_trait_access,
    clippy::double_must_use,
    clippy::duration_suboptimal_units,
    clippy::format_collect,
    clippy::format_push_string,
    clippy::ignored_unit_patterns,
    clippy::items_after_statements,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::match_same_arms,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::needless_borrow,
    clippy::needless_pass_by_value,
    clippy::needless_raw_string_hashes,
    clippy::nonminimal_bool,
    clippy::redundant_closure_for_method_calls,
    clippy::single_char_pattern,
    clippy::single_match_else,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::unnecessary_wraps,
    clippy::unnested_or_patterns,
    clippy::unused_self,
    clippy::useless_conversion,
    clippy::while_let_loop
)]

pub mod adapters;
pub mod application;
pub mod composition;
pub mod config;
pub mod domain;
pub mod gateway;
pub mod http;
pub mod protocols;
pub mod runtime;
pub mod secrets;

#[cfg(test)]
use std::net::SocketAddr;
use std::{borrow::Cow, io, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use rust_embed::Embed;
use thiserror::Error;
use tokio::net::TcpListener;

use crate::{
    adapters::postgres::StoreError,
    application::ApplicationError,
    config::{DeploymentProfile, ServerConfig},
    runtime::RuntimePublisher,
    secrets::{CustodyCompositionError, SecretServiceError, SoftwareSecretError},
};

pub use composition::{BuiltServer, ServerBuilder};
/// Provider-neutral SPI used by trusted statically linked custom custody implementations.
pub use owlrora_key_provider as key_provider;

#[derive(Embed)]
#[folder = "web/dist"]
struct WebAssets;

#[derive(Debug, Error)]
pub enum StartupError {
    #[error("full profile is missing required configuration: {0}")]
    MissingConfiguration(&'static str),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("database operation failed during server composition")]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Secret(#[from] SoftwareSecretError),
    #[error(transparent)]
    CustodyComposition(#[from] CustodyCompositionError),
    #[error(transparent)]
    SecretService(#[from] SecretServiceError),
    #[error(transparent)]
    Coordinator(#[from] crate::adapters::coordinator::CoordinatorError),
    #[error("persisted configuration secret custody metadata is invalid")]
    InvalidCustodyMetadata,
    #[error("persisted configuration secret custody format is not available in this binary")]
    UnsupportedPersistedCustody,
    #[error(transparent)]
    Application(#[from] ApplicationError),
}

/// Builds the embedded-console router used by package smoke tests.
#[must_use]
pub fn app() -> Router {
    console_router()
}

/// Builds a router from validated deployment configuration.
pub async fn configured_app(
    config: Arc<ServerConfig>,
) -> Result<(Router, Option<Arc<RuntimePublisher>>), StartupError> {
    if config.profile == DeploymentProfile::HealthOnly {
        return Ok((health_router(), None));
    }
    Ok(ServerBuilder::new(config).build().await?.into_parts())
}

/// Serves the configured application until a shutdown signal is received.
pub async fn run(listener: TcpListener, config: Arc<ServerConfig>) -> io::Result<()> {
    ServerBuilder::new(config)
        .build()
        .await
        .map_err(|error| io::Error::other(error.to_string()))?
        .serve(listener)
        .await
}

pub(crate) fn health_router() -> Router {
    Router::new().route("/health", get(health))
}

pub(crate) fn console_router() -> Router {
    health_router().fallback(get(frontend))
}

async fn health() -> &'static str {
    "ok"
}

async fn frontend(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if matches!(
        path.split('/').next(),
        Some("api" | "auth" | "v1" | "v1beta" | "health" | "ready")
    ) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = if path.is_empty() { "index.html" } else { path };

    if let Some(asset) = WebAssets::get(path) {
        return asset_response(path, asset.data);
    }
    if std::path::Path::new(path).extension().is_none()
        && let Some(index) = WebAssets::get("index.html")
    {
        return asset_response("index.html", index.data);
    }

    StatusCode::NOT_FOUND.into_response()
}

fn asset_response(path: &str, data: Cow<'static, [u8]>) -> Response {
    let content_type = mime_guess::from_path(path).first_or_octet_stream();
    let mut response = Response::new(Body::from(data));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        content_type
            .as_ref()
            .parse()
            .expect("MIME types are valid header values"),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
            .parse()
            .expect("static CSP is valid"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().expect("static header is valid"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        "no-referrer".parse().expect("static header is valid"),
    );
    response
}

#[cfg(unix)]
pub(crate) async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate()).expect("failed to listen for SIGTERM");
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                tracing::error!(%error, "failed to listen for Ctrl+C");
            }
        }
        _ = terminate.recv() => {}
    }
}

#[cfg(not(unix))]
pub(crate) async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "failed to listen for Ctrl+C");
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::to_bytes, http::Request};
    use tower::ServiceExt as _;

    use super::*;

    #[tokio::test]
    async fn health_endpoint_is_available() {
        let response = app()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body(), 16).await.unwrap().as_ref(),
            b"ok"
        );
    }

    #[tokio::test]
    async fn frontend_is_embedded() {
        let response = app()
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        assert!(
            body.windows(22)
                .any(|window| window == b"<title>OwlRora</title>")
        );
    }

    #[tokio::test]
    async fn frontend_routes_fall_back_to_the_embedded_shell() {
        let response = app()
            .oneshot(Request::get("/example/route").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "text/html");
    }

    #[tokio::test]
    async fn embedded_assets_have_their_expected_content_type() {
        let asset = WebAssets::iter()
            .find(|path| path.ends_with(".css"))
            .expect("the web build should contain a stylesheet");
        let response = app()
            .oneshot(
                Request::get(format!("/{asset}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "text/css");
    }

    #[tokio::test]
    async fn missing_assets_are_not_replaced_with_the_frontend_shell() {
        let response = app()
            .oneshot(
                Request::get("/assets/missing.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn frontend_routes_only_accept_safe_read_methods() {
        let response = app()
            .oneshot(Request::post("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn seed_to_durable_key_session_authority_flow_uses_real_postgres() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter("error")
            .try_init();
        use std::collections::BTreeMap;

        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use serde_json::{Value, json};

        let Ok(database_url) = std::env::var("OWLRORA_TEST_DATABASE_URL") else {
            return;
        };
        let Ok(redis_url) = std::env::var("OWLRORA_TEST_REDIS_URL") else {
            return;
        };
        let _database_guard =
            crate::adapters::postgres::test_support::shared_database_test_lock().await;
        let seed_key = crate::domain::generate_management_key().expose_once();
        let config = Arc::new(
            ServerConfig::from_values(&BTreeMap::from([
                ("OWLRORA_DATABASE_URL".to_owned(), database_url.clone()),
                (
                    "OWLRORA_PUBLIC_ORIGIN".to_owned(),
                    "http://127.0.0.1:8080".to_owned(),
                ),
                ("OWLRORA_REDIS_URL".to_owned(), redis_url),
                (
                    "OWLRORA_NODE_INSTANCE_ID".to_owned(),
                    format!("management-e2e-{}", uuid::Uuid::now_v7()),
                ),
                ("OWLRORA_SEED_ADMIN_API_KEY".to_owned(), seed_key.clone()),
                (
                    "OWLRORA_SECRET_ROOT".to_owned(),
                    URL_SAFE_NO_PAD.encode([9_u8; 32]),
                ),
            ]))
            .unwrap(),
        );
        let (router, runtime) = configured_app(config).await.unwrap();
        let authorization = format!("Bearer {seed_key}");
        let unique = uuid::Uuid::now_v7();

        let mut allowed_operations = Request::get("/api/v1/system/operations/readiness")
            .header(header::AUTHORIZATION, &authorization)
            .body(Body::empty())
            .unwrap();
        allowed_operations
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(
                "127.0.0.1:45123".parse::<SocketAddr>().unwrap(),
            ));
        let response = router.clone().oneshot(allowed_operations).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let mut denied_operations = Request::get("/api/v1/system/operations/readiness")
            .header(header::AUTHORIZATION, &authorization)
            .body(Body::empty())
            .unwrap();
        denied_operations
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(
                "203.0.113.10:45123".parse::<SocketAddr>().unwrap(),
            ));
        let response = router.clone().oneshot(denied_operations).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let create_user = Request::post("/api/v1/system/users/actions/create")
            .header(header::AUTHORIZATION, &authorization)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "kind":"human",
                    "display_name":format!("Test user {unique}"),
                    "primary_email":format!("{unique}@example.test")
                })
                .to_string(),
            ))
            .unwrap();
        let response = router.clone().oneshot(create_user).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let user_etag = response.headers()[header::ETAG]
            .to_str()
            .unwrap()
            .to_owned();
        let user: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        let user_id = user["id"].as_str().unwrap();

        let idempotency_key = format!("module-i-test-{unique}");
        let idempotent_body = json!({
            "kind":"human",
            "display_name":format!("Idempotent user {unique}"),
            "primary_email":format!("idempotent-{unique}@example.test")
        })
        .to_string();
        let first = router
            .clone()
            .oneshot(
                Request::post("/api/v1/system/users/actions/create")
                    .header(header::AUTHORIZATION, &authorization)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", &idempotency_key)
                    .body(Body::from(idempotent_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let first_etag = first.headers()[header::ETAG].clone();
        let first_body = to_bytes(first.into_body(), 64 * 1024).await.unwrap();
        let replay = router
            .clone()
            .oneshot(
                Request::post("/api/v1/system/users/actions/create")
                    .header(header::AUTHORIZATION, &authorization)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", &idempotency_key)
                    .body(Body::from(idempotent_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        assert_eq!(replay.headers()[header::ETAG], first_etag);
        let replay_body = to_bytes(replay.into_body(), 64 * 1024).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&replay_body).unwrap(),
            serde_json::from_slice::<Value>(&first_body).unwrap(),
        );

        let rollback_key = format!("module-i-rollback-{unique}");
        let rejected = router
            .clone()
            .oneshot(
                Request::post("/api/v1/system/organizations/actions/create")
                    .header(header::AUTHORIZATION, &authorization)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", &rollback_key)
                    .body(Body::from(
                        json!({
                            "kind":"ordinary",
                            "name":format!("Rejected organization {unique}"),
                            "slug":format!("rejected-{unique}"),
                            "initial_owner_user_id":uuid::Uuid::now_v7()
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let retry_after_rollback = router
            .clone()
            .oneshot(
                Request::post("/api/v1/system/organizations/actions/create")
                    .header(header::AUTHORIZATION, &authorization)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", &rollback_key)
                    .body(Body::from(
                        json!({
                            "kind":"ordinary",
                            "name":format!("Retry after rollback {unique}"),
                            "slug":format!("retry-{unique}"),
                            "initial_owner_user_id":user_id
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(retry_after_rollback.status(), StatusCode::OK);

        let concurrent_key = format!("module-i-concurrent-{unique}");
        let concurrent_body = json!({
            "kind":"human",
            "display_name":format!("Concurrent idempotency {unique}"),
            "primary_email":null
        })
        .to_string();
        let concurrent_request = |body: String| {
            Request::post("/api/v1/system/users/actions/create")
                .header(header::AUTHORIZATION, &authorization)
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", &concurrent_key)
                .body(Body::from(body))
                .unwrap()
        };
        let (concurrent_a, concurrent_b) = tokio::join!(
            router
                .clone()
                .oneshot(concurrent_request(concurrent_body.clone())),
            router.clone().oneshot(concurrent_request(concurrent_body)),
        );
        let concurrent_a = concurrent_a.unwrap();
        let concurrent_b = concurrent_b.unwrap();
        assert_eq!(concurrent_a.status(), StatusCode::OK);
        assert_eq!(concurrent_b.status(), StatusCode::OK);
        assert_eq!(
            concurrent_a.headers()[header::ETAG],
            concurrent_b.headers()[header::ETAG]
        );
        let concurrent_a = to_bytes(concurrent_a.into_body(), 64 * 1024).await.unwrap();
        let concurrent_b = to_bytes(concurrent_b.into_body(), 64 * 1024).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&concurrent_a).unwrap(),
            serde_json::from_slice::<Value>(&concurrent_b).unwrap(),
        );

        let create_pricing_policy = |name: String| {
            Request::post("/api/v1/system/pricing-policies/actions/create")
                .header(header::AUTHORIZATION, &authorization)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"name":name,"status":"active"}).to_string(),
                ))
                .unwrap()
        };
        let primary_pricing = router
            .clone()
            .oneshot(create_pricing_policy(format!("Pricing A {unique}")))
            .await
            .unwrap();
        assert_eq!(primary_pricing.status(), StatusCode::OK);
        let primary_etag = primary_pricing.headers()[header::ETAG]
            .to_str()
            .unwrap()
            .to_owned();
        let primary_pricing: Value = serde_json::from_slice(
            &to_bytes(primary_pricing.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let primary_id = primary_pricing["id"].as_str().unwrap();
        let alternate_pricing = router
            .clone()
            .oneshot(create_pricing_policy(format!("Pricing B {unique}")))
            .await
            .unwrap();
        assert_eq!(alternate_pricing.status(), StatusCode::OK);
        let alternate_etag = alternate_pricing.headers()[header::ETAG]
            .to_str()
            .unwrap()
            .to_owned();
        let alternate_pricing: Value = serde_json::from_slice(
            &to_bytes(alternate_pricing.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let alternate_id = alternate_pricing["id"].as_str().unwrap();
        let publish_key = format!("pricing-publish-{unique}");
        let publish_body = json!({
            "rates":{
                "currency":"USD",
                "cost_nanos_per_unit":{"input_token":10}
            },
            "rounding_policy":{"mode":"nearest","quantum_units":1},
            "organization_usable":true,
            "publication_evidence":{}
        })
        .to_string();
        let publish_request = |pricing_id: &str, etag: &str| {
            Request::post(format!(
                "/api/v1/system/pricing-policies/{pricing_id}/actions/publish-version"
            ))
            .header(header::AUTHORIZATION, &authorization)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::IF_MATCH, etag)
            .header("idempotency-key", &publish_key)
            .body(Body::from(publish_body.clone()))
            .unwrap()
        };
        let published_a = router
            .clone()
            .oneshot(publish_request(primary_id, &primary_etag))
            .await
            .unwrap();
        assert_eq!(published_a.status(), StatusCode::OK);
        let published_a_etag = published_a.headers()[header::ETAG]
            .to_str()
            .unwrap()
            .to_owned();
        let published_a_body = to_bytes(published_a.into_body(), 64 * 1024).await.unwrap();
        let cross_resource = router
            .clone()
            .oneshot(publish_request(alternate_id, &alternate_etag))
            .await
            .unwrap();
        assert_eq!(cross_resource.status(), StatusCode::CONFLICT);
        let changed_precondition = router
            .clone()
            .oneshot(publish_request(primary_id, &published_a_etag))
            .await
            .unwrap();
        assert_eq!(changed_precondition.status(), StatusCode::CONFLICT);
        let exact_publish_replay = router
            .clone()
            .oneshot(publish_request(primary_id, &primary_etag))
            .await
            .unwrap();
        assert_eq!(exact_publish_replay.status(), StatusCode::OK);
        assert_eq!(
            exact_publish_replay.headers()[header::ETAG],
            published_a_etag
        );
        let exact_publish_replay = to_bytes(exact_publish_replay.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&exact_publish_replay).unwrap(),
            serde_json::from_slice::<Value>(&published_a_body).unwrap(),
        );

        let create_organization = Request::post("/api/v1/system/organizations/actions/create")
            .header(header::AUTHORIZATION, &authorization)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "kind":"ordinary",
                    "name":format!("Test organization {unique}"),
                    "slug":format!("test-{unique}"),
                    "initial_owner_user_id":user_id
                })
                .to_string(),
            ))
            .unwrap();
        let response = router.clone().oneshot(create_organization).await.unwrap();
        let status = response.status();
        assert_eq!(response.headers()["x-owlrora-command-status"], "committed");
        assert!(matches!(
            response.headers()["x-owlrora-node-publication"]
                .to_str()
                .unwrap(),
            "applied" | "pending"
        ));
        assert!(
            response
                .headers()
                .contains_key("x-owlrora-applied-revision")
        );
        assert!(
            response
                .headers()
                .contains_key("x-owlrora-database-revision")
        );
        let response_body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "runtime publication status: {:?}; response: {}",
            runtime.as_ref().map(|publisher| publisher.status()),
            String::from_utf8_lossy(&response_body),
        );
        let organization: Value = serde_json::from_slice(&response_body).unwrap();
        let organization_id = organization["id"].as_str().unwrap();
        let organization_runtime_id: crate::domain::OrganizationId =
            serde_json::from_value(organization["id"].clone()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if runtime
                    .as_ref()
                    .unwrap()
                    .capture()
                    .snapshot
                    .identity
                    .active_organizations
                    .get(&organization_runtime_id)
                    .copied()
                    == Some(true)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("new organization should reach the runtime generation");

        let usage_range = "start=2026-01-01T00%3A00%3A00Z&end=2026-01-02T00%3A00%3A00Z";
        let system_usage = router
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/system/usage?{usage_range}"))
                    .header(header::AUTHORIZATION, &authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(system_usage.status(), StatusCode::OK);
        let system_usage: Value =
            serde_json::from_slice(&to_bytes(system_usage.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(system_usage["scope"]["kind"], "system");
        assert_eq!(
            system_usage["completeness"]["includes_unflushed_process_facts"],
            false
        );
        assert_eq!(system_usage["logical_requests"]["applicable"], true);

        let system_breakdown = router
            .clone()
            .oneshot(
                Request::get(format!(
                    "/api/v1/system/usage/breakdown?{usage_range}&fact_family=attempts&dimension=origin"
                ))
                .header(header::AUTHORIZATION, &authorization)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(system_breakdown.status(), StatusCode::OK);

        let organization_usage = router
            .clone()
            .oneshot(
                Request::get(format!(
                    "/api/v1/organizations/{organization_id}/usage?{usage_range}"
                ))
                .header(header::AUTHORIZATION, &authorization)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(organization_usage.status(), StatusCode::OK);
        let organization_usage: Value = serde_json::from_slice(
            &to_bytes(organization_usage.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            organization_usage["scope"]["organization_id"],
            organization_id
        );

        let operations_paths = crate::http::operation_catalog()
            .into_iter()
            .filter(|operation| {
                operation.qualification == crate::http::OperationQualification::Operations
                    && operation.mode == crate::http::OperationMode::Query
            })
            .map(|operation| operation.path)
            .collect::<Vec<_>>();
        assert!(!operations_paths.is_empty());
        for path in operations_paths {
            let mut request = Request::get(path)
                .header(header::AUTHORIZATION, &authorization)
                .body(Body::empty())
                .unwrap();
            request.extensions_mut().insert(axum::extract::ConnectInfo(
                "127.0.0.1:45123".parse::<SocketAddr>().unwrap(),
            ));
            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(
                response
                    .headers()
                    .get(header::CACHE_CONTROL)
                    .and_then(|value| value.to_str().ok()),
                Some("no-store"),
                "{path}"
            );
        }

        let ready = router
            .clone()
            .oneshot(Request::get("/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::OK);
        let ready: Value =
            serde_json::from_slice(&to_bytes(ready.into_body(), 64 * 1024).await.unwrap()).unwrap();
        assert_eq!(ready, json!({"status":"ready"}));

        let seed_principal = router
            .clone()
            .oneshot(
                Request::get("/api/v1/me")
                    .header(header::AUTHORIZATION, &authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(seed_principal.status(), StatusCode::OK);
        let seed_principal: Value = serde_json::from_slice(
            &to_bytes(seed_principal.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(seed_principal["system_administrator"], true);
        assert_eq!(
            seed_principal["capabilities"].as_array().unwrap().len(),
            crate::domain::Capability::ALL.len()
        );

        let organization_key = router
            .clone()
            .oneshot(
                Request::post(format!(
                    "/api/v1/organizations/{organization_id}/management-api-keys/actions/create"
                ))
                .header(header::AUTHORIZATION, &authorization)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "name":format!("organization-reader-{unique}"),
                        "scopes":["management:read"],
                        "capability_ceiling":["read_organization", "read_members"],
                        "expires_at":null
                    })
                    .to_string(),
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        let organization_key_status = organization_key.status();
        let organization_key_body = to_bytes(organization_key.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert_eq!(
            organization_key_status,
            StatusCode::OK,
            "organization key response: {}",
            String::from_utf8_lossy(&organization_key_body)
        );
        let organization_key: Value = serde_json::from_slice(&organization_key_body).unwrap();
        let organization_authorization =
            format!("Bearer {}", organization_key["key"].as_str().unwrap());
        let organization_principal = router
            .clone()
            .oneshot(
                Request::get("/api/v1/me")
                    .header(header::AUTHORIZATION, &organization_authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(organization_principal.status(), StatusCode::OK);
        let organization_principal: Value = serde_json::from_slice(
            &to_bytes(organization_principal.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(organization_principal["system_administrator"], false);
        assert_eq!(organization_principal["capabilities"], json!([]));
        assert_eq!(
            organization_principal["allowed_organizations"],
            json!([{
                "organization_id":organization_id,
                "name":organization["name"],
                "access_reason":"organization_key",
                "role":null,
                "capabilities":["read_organization", "read_members"],
                "management_key_self_service":null
            }])
        );
        let organization_page = router
            .clone()
            .oneshot(
                Request::get("/api/v1/me/organizations?limit=1")
                    .header(header::AUTHORIZATION, &organization_authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(organization_page.status(), StatusCode::OK);
        let organization_page: Value = serde_json::from_slice(
            &to_bytes(organization_page.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(organization_page["items"].as_array().unwrap().len(), 1);
        assert_eq!(
            organization_page["items"][0]["organization_id"],
            organization_id
        );
        assert_eq!(organization_page["next_cursor"], Value::Null);
        let denied_usage = router
            .clone()
            .oneshot(
                Request::get(format!(
                    "/api/v1/organizations/{organization_id}/usage?{usage_range}"
                ))
                .header(header::AUTHORIZATION, &organization_authorization)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied_usage.status(), StatusCode::FORBIDDEN);

        let create_key = Request::post("/api/v1/system/management-api-keys/actions/create")
            .header(header::AUTHORIZATION, &authorization)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "name":format!("test-admin-{unique}"),
                    "scopes":[
                        "management:read", "management:write", "management:secrets",
                        "management:operations", "management:authority"
                    ],
                    "capability_ceiling":["system_administration"],
                    "expires_at":null
                })
                .to_string(),
            ))
            .unwrap();
        let response = router.clone().oneshot(create_key).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let key: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        let durable_key_id = key["management_api_key"]["id"].as_str().unwrap();

        let grant = Request::post("/api/v1/system/administrators/actions/grant")
            .header(header::AUTHORIZATION, &authorization)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "subject_kind":"deployment_management_api_key",
                    "subject_id":durable_key_id
                })
                .to_string(),
            ))
            .unwrap();
        let response = router.clone().oneshot(grant).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let administrators = router
            .clone()
            .oneshot(
                Request::get("/api/v1/system/administrators?limit=1")
                    .header(header::AUTHORIZATION, &authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(administrators.status(), StatusCode::OK);
        let administrators: Value = serde_json::from_slice(
            &to_bytes(administrators.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(administrators["items"][0]["subject_kind"], "seed_admin");
        let administrator_cursor = administrators["next_cursor"].as_str().unwrap();
        let next_administrators = router
            .clone()
            .oneshot(
                Request::get(format!(
                    "/api/v1/system/administrators?limit=1&cursor={administrator_cursor}"
                ))
                .header(header::AUTHORIZATION, &authorization)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(next_administrators.status(), StatusCode::OK);
        let next_administrators: Value = serde_json::from_slice(
            &to_bytes(next_administrators.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(next_administrators["items"][0]["built_in"], false);

        let create_limited_key = |name: &str| {
            Request::post("/api/v1/system/management-api-keys/actions/create")
                .header(header::AUTHORIZATION, &authorization)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "name":name,
                        "scopes":["management:read", "management:write"],
                        "capability_ceiling":["system_administration"],
                        "expires_at":null
                    })
                    .to_string(),
                ))
                .unwrap()
        };
        let limited = router
            .clone()
            .oneshot(create_limited_key(&format!("limited-admin-{unique}")))
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::OK);
        let limited: Value =
            serde_json::from_slice(&to_bytes(limited.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        let limited_raw = limited["key"].as_str().unwrap();
        let limited_id = limited["management_api_key"]["id"].as_str().unwrap();
        let target = router
            .clone()
            .oneshot(create_limited_key(&format!("limited-target-{unique}")))
            .await
            .unwrap();
        assert_eq!(target.status(), StatusCode::OK);
        let target: Value =
            serde_json::from_slice(&to_bytes(target.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        let target_id = target["management_api_key"]["id"].as_str().unwrap();
        let grant_limited = router
            .clone()
            .oneshot(
                Request::post("/api/v1/system/administrators/actions/grant")
                    .header(header::AUTHORIZATION, &authorization)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "subject_kind":"deployment_management_api_key",
                            "subject_id":limited_id
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(grant_limited.status(), StatusCode::NO_CONTENT);
        let target_get = router
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/system/management-api-keys/{target_id}"))
                    .header(header::AUTHORIZATION, &authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(target_get.status(), StatusCode::OK);
        let target_etag = target_get.headers()[header::ETAG]
            .to_str()
            .unwrap()
            .to_owned();
        let disabled_target = router
            .clone()
            .oneshot(
                Request::post(format!(
                    "/api/v1/system/management-api-keys/{target_id}/actions/update"
                ))
                .header(header::AUTHORIZATION, &authorization)
                .header(header::IF_MATCH, &target_etag)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"status":"disabled"}).to_string()))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(disabled_target.status(), StatusCode::OK);
        let disabled_target_etag = disabled_target.headers()[header::ETAG]
            .to_str()
            .unwrap()
            .to_owned();
        let limited_reactivation = router
            .clone()
            .oneshot(
                Request::post(format!(
                    "/api/v1/system/management-api-keys/{target_id}/actions/update"
                ))
                .header(header::AUTHORIZATION, format!("Bearer {limited_raw}"))
                .header(header::IF_MATCH, &disabled_target_etag)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"status":"active"}).to_string()))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(limited_reactivation.status(), StatusCode::FORBIDDEN);

        let test_pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        let policy_response = router
            .clone()
            .oneshot(
                Request::get("/api/v1/system/management-api-key-policy")
                    .header(header::AUTHORIZATION, &authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(policy_response.status(), StatusCode::OK);
        let policy_etag = policy_response.headers()[header::ETAG]
            .to_str()
            .unwrap()
            .to_owned();
        let policy: Value = serde_json::from_slice(
            &to_bytes(policy_response.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let original_policy = policy["policy"].clone();
        let active_key_count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM management_api_keys
             WHERE organization_id IS NULL AND status='active'
               AND (expires_at IS NULL OR expires_at > now())",
        )
        .fetch_one(&test_pool)
        .await
        .unwrap();
        assert!(active_key_count >= 2);

        let mut below_count_policy = original_policy.clone();
        below_count_policy["management"]["max_active_keys"] = json!(active_key_count - 1);
        let rejected_policy_limit = router
            .clone()
            .oneshot(
                Request::post("/api/v1/system/management-api-key-policy/actions/update")
                    .header(header::AUTHORIZATION, &authorization)
                    .header(header::IF_MATCH, &policy_etag)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({"policy":below_count_policy}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected_policy_limit.status(), StatusCode::CONFLICT);

        let mut exact_count_policy = original_policy.clone();
        exact_count_policy["management"]["max_active_keys"] = json!(active_key_count);
        let exact_policy_limit = router
            .clone()
            .oneshot(
                Request::post("/api/v1/system/management-api-key-policy/actions/update")
                    .header(header::AUTHORIZATION, &authorization)
                    .header(header::IF_MATCH, &policy_etag)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({"policy":exact_count_policy}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(exact_policy_limit.status(), StatusCode::OK);
        let exact_policy_etag = exact_policy_limit.headers()[header::ETAG]
            .to_str()
            .unwrap()
            .to_owned();

        let seed_reactivation = router
            .clone()
            .oneshot(
                Request::post(format!(
                    "/api/v1/system/management-api-keys/{target_id}/actions/update"
                ))
                .header(header::AUTHORIZATION, &authorization)
                .header(header::IF_MATCH, &disabled_target_etag)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"status":"active"}).to_string()))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(seed_reactivation.status(), StatusCode::CONFLICT);

        let restored_policy = router
            .clone()
            .oneshot(
                Request::post("/api/v1/system/management-api-key-policy/actions/update")
                    .header(header::AUTHORIZATION, &authorization)
                    .header(header::IF_MATCH, &exact_policy_etag)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({"policy":original_policy}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(restored_policy.status(), StatusCode::OK);

        let revoked_limited = router
            .clone()
            .oneshot(
                Request::post(format!(
                    "/api/v1/system/administrators/deployment_management_api_key/{limited_id}/actions/revoke"
                ))
                .header(header::AUTHORIZATION, &authorization)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoked_limited.status(), StatusCode::NO_CONTENT);
        let active_administrators = router
            .clone()
            .oneshot(
                Request::get("/api/v1/system/administrators?limit=100")
                    .header(header::AUTHORIZATION, &authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(active_administrators.status(), StatusCode::OK);
        let active_administrators: Value = serde_json::from_slice(
            &to_bytes(active_administrators.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(
            active_administrators["items"]
                .as_array()
                .unwrap()
                .iter()
                .all(|grant| grant["subject_id"] != limited_id)
        );

        sqlx::query(
            "DELETE FROM oidc_login_states
             WHERE id IN (
                 SELECT id FROM oidc_login_states
                 WHERE expires_at < now()
                    OR (consumed_at IS NOT NULL AND consumed_at < now()-interval '1 hour')
                 ORDER BY expires_at, id LIMIT 500 FOR UPDATE SKIP LOCKED
             )",
        )
        .execute(&test_pool)
        .await
        .unwrap();
        sqlx::query(
            "DELETE FROM idempotency_records
             WHERE (actor_fingerprint, scope_fingerprint, operation_id, idempotency_key) IN (
                 SELECT actor_fingerprint, scope_fingerprint, operation_id, idempotency_key
                 FROM idempotency_records
                 WHERE state='completed' AND expires_at < now()
                 ORDER BY expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED
             )",
        )
        .execute(&test_pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE management_api_key_secret_versions
             SET created_at=now()-interval '30 days'
             WHERE management_api_key_id=$1 AND state='current'",
        )
        .bind(uuid::Uuid::parse_str(durable_key_id).unwrap())
        .execute(&test_pool)
        .await
        .unwrap();
        let rotated = router
            .clone()
            .oneshot(
                Request::post(format!(
                    "/api/v1/system/management-api-keys/{durable_key_id}/actions/rotate"
                ))
                .header(header::AUTHORIZATION, &authorization)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"overlap_seconds":60}).to_string()))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rotated.status(), StatusCode::OK);
        let rotated: Value =
            serde_json::from_slice(&to_bytes(rotated.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        let rotated_key = rotated["key"].as_str().unwrap().to_owned();
        assert!(!rotated_key.is_empty());

        sqlx::query(
            "UPDATE management_api_key_secret_versions
             SET created_at=now()-interval '30 days'
             WHERE management_api_key_id=$1 AND state='current'",
        )
        .bind(uuid::Uuid::parse_str(durable_key_id).unwrap())
        .execute(&test_pool)
        .await
        .unwrap();
        let consecutive_rotation = router
            .clone()
            .oneshot(
                Request::post(format!(
                    "/api/v1/system/management-api-keys/{durable_key_id}/actions/rotate"
                ))
                .header(header::AUTHORIZATION, &authorization)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"overlap_seconds":60}).to_string()))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(consecutive_rotation.status(), StatusCode::OK);
        let rotation_classification = sqlx::query_scalar::<_, String>(
            "SELECT security_classification FROM configuration_journal
             WHERE event_kind='management_api_key.changed'
               AND affected_scope->>'management_api_key_id'=$1
             ORDER BY revision DESC LIMIT 1",
        )
        .bind(durable_key_id)
        .fetch_one(&test_pool)
        .await
        .unwrap();
        assert_eq!(rotation_classification, "tightening");

        let key_authorization = format!("Bearer {rotated_key}");
        let response = router
            .clone()
            .oneshot(
                Request::get("/api/v1/system/users")
                    .header(header::AUTHORIZATION, &key_authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let exchange = Request::post("/auth/v1/management-api-key/session/actions/create")
            .header(header::AUTHORIZATION, &key_authorization)
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(exchange).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let session_cookie = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|value| {
                value
                    .to_str()
                    .ok()?
                    .strip_prefix("owlrora_session=")?
                    .split(';')
                    .next()
                    .map(|value| format!("owlrora_session={value}"))
            })
            .unwrap();
        let session: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        assert!(session.get("session_cookie").is_none());
        let csrf = session["csrf_token"].as_str().unwrap();

        let update_without_origin =
            Request::post(format!("/api/v1/system/users/{user_id}/actions/update"))
                .header(header::COOKIE, &session_cookie)
                .header("x-owlrora-csrf-token", csrf)
                .header(header::IF_MATCH, &user_etag)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"display_name":"Rejected update"}).to_string(),
                ))
                .unwrap();
        let response = router.clone().oneshot(update_without_origin).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let update = Request::post(format!("/api/v1/system/users/{user_id}/actions/update"))
            .header(header::COOKIE, &session_cookie)
            .header("x-owlrora-csrf-token", csrf)
            .header(header::ORIGIN, "http://127.0.0.1:8080")
            .header(header::IF_MATCH, &user_etag)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"display_name":format!("Updated user {unique}")}).to_string(),
            ))
            .unwrap();
        let response = router.clone().oneshot(update).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let policy_response = router
            .clone()
            .oneshot(
                Request::get("/api/v1/system/management-api-key-policy")
                    .header(header::AUTHORIZATION, &authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(policy_response.status(), StatusCode::OK);
        let policy_etag = policy_response.headers()[header::ETAG]
            .to_str()
            .unwrap()
            .to_owned();
        let policy_view: Value = serde_json::from_slice(
            &to_bytes(policy_response.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let mut narrow_policy = policy_view["policy"].clone();
        let original_scopes = narrow_policy["management"]["allowed_scopes"].clone();
        narrow_policy["management"]["allowed_scopes"] = json!(["management:read"]);
        let narrow = router
            .clone()
            .oneshot(
                Request::post("/api/v1/system/management-api-key-policy/actions/update")
                    .header(header::AUTHORIZATION, &authorization)
                    .header(header::IF_MATCH, &policy_etag)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({"policy":narrow_policy}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(narrow.status(), StatusCode::OK);
        let narrow_etag = narrow.headers()[header::ETAG].to_str().unwrap().to_owned();
        let narrow_view: Value =
            serde_json::from_slice(&to_bytes(narrow.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        let mut expanded_policy = narrow_view["policy"].clone();
        expanded_policy["management"]["allowed_scopes"] = original_scopes;
        let expanded = router
            .clone()
            .oneshot(
                Request::post("/api/v1/system/management-api-key-policy/actions/update")
                    .header(header::AUTHORIZATION, &authorization)
                    .header(header::IF_MATCH, &narrow_etag)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({"policy":expanded_policy}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(expanded.status(), StatusCode::OK);

        let denied_direct = router
            .clone()
            .oneshot(
                Request::post("/api/v1/system/users/actions/create")
                    .header(header::AUTHORIZATION, &key_authorization)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "kind":"human",
                            "display_name":"Must stay denied after policy expansion",
                            "primary_email":null
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied_direct.status(), StatusCode::FORBIDDEN);

        let denied_session = router
            .clone()
            .oneshot(
                Request::post("/api/v1/system/users/actions/create")
                    .header(header::COOKIE, &session_cookie)
                    .header("x-owlrora-csrf-token", csrf)
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "kind":"human",
                            "display_name":"Session must stay denied after policy expansion",
                            "primary_email":null
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied_session.status(), StatusCode::UNAUTHORIZED);

        runtime.unwrap().shutdown().await;
    }
}
