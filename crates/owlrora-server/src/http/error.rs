use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use crate::application::ApplicationError;

#[derive(Debug)]
pub struct ApiError {
    error: ApplicationError,
    request_id: String,
}

impl ApiError {
    #[must_use]
    pub fn new(error: ApplicationError, request_id: impl Into<String>) -> Self {
        Self {
            error,
            request_id: request_id.into(),
        }
    }

    #[must_use]
    pub fn validation(message: impl Into<String>, request_id: impl Into<String>) -> Self {
        Self::new(ApplicationError::Validation(message.into()), request_id)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message, details) = match &self.error {
            ApplicationError::AuthenticationRequired => (
                StatusCode::UNAUTHORIZED,
                "authentication_required",
                "Authentication is required.",
                json!({}),
            ),
            ApplicationError::InvalidCredential => (
                StatusCode::UNAUTHORIZED,
                "invalid_credential",
                "The supplied credential is invalid.",
                json!({}),
            ),
            ApplicationError::CredentialInactive => (
                StatusCode::UNAUTHORIZED,
                "credential_inactive",
                "The credential or principal is inactive.",
                json!({}),
            ),
            ApplicationError::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "The requested operation is not permitted.",
                json!({}),
            ),
            ApplicationError::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "The requested resource was not found.",
                json!({}),
            ),
            ApplicationError::PreconditionRequired => (
                StatusCode::PRECONDITION_REQUIRED,
                "precondition_required",
                "The latest resource ETag is required in If-Match.",
                json!({}),
            ),
            ApplicationError::Stale { current_etag } => (
                StatusCode::PRECONDITION_FAILED,
                "stale_representation",
                "The resource changed since it was read.",
                current_etag
                    .as_ref()
                    .map_or_else(|| json!({}), |etag| json!({"current_etag":etag})),
            ),
            ApplicationError::Validation(reason) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "validation_failed",
                "The request failed validation.",
                json!({"reason":bounded(reason)}),
            ),
            ApplicationError::Conflict(reason) => (
                StatusCode::CONFLICT,
                "state_conflict",
                "The requested transition conflicts with current state.",
                json!({"reason":bounded(reason)}),
            ),
            ApplicationError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "The request rate limit was exceeded.",
                json!({"retry_after_seconds":60}),
            ),
            ApplicationError::IdempotencyConflict => (
                StatusCode::CONFLICT,
                "idempotency_conflict",
                "The idempotency key was reused with different input.",
                json!({}),
            ),
            ApplicationError::DependencyUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "dependency_unavailable",
                "A required control-plane dependency is unavailable.",
                json!({}),
            ),
            ApplicationError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "The request could not be completed.",
                json!({}),
            ),
        };
        let mut response = (
            status,
            Json(json!({
                "error": {
                    "code": code,
                    "message": message,
                    "request_id": self.request_id,
                    "details": details,
                }
            })),
        )
            .into_response();
        response.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
        response
    }
}

fn bounded(value: &str) -> Value {
    Value::String(value.chars().take(512).collect())
}
