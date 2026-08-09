#![forbid(unsafe_code)]

use std::{borrow::Cow, io};

use axum::{
    Router,
    body::Body,
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use rust_embed::Embed;
use tokio::net::TcpListener;

/// Public provider-neutral SPI used by custom statically composed server binaries.
pub use owlrora_key_provider as key_provider;

#[derive(Embed)]
#[folder = "web/dist"]
struct WebAssets;

/// Builds the application router.
pub fn app() -> Router {
    Router::new()
        .route("/health", get(health))
        .fallback(get(frontend))
}

/// Serves the application until a shutdown signal is received.
///
/// # Errors
///
/// Returns an I/O error if the HTTP server fails.
pub async fn run(listener: TcpListener) -> io::Result<()> {
    axum::serve(listener, app())
        .with_graceful_shutdown(shutdown_signal())
        .await
}

async fn health() -> &'static str {
    "ok"
}

async fn frontend(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
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
    response
}

#[cfg(unix)]
async fn shutdown_signal() {
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
async fn shutdown_signal() {
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
}
