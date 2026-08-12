use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApplicationError {
    #[error("authentication is required")]
    AuthenticationRequired,
    #[error("the supplied credential is invalid")]
    InvalidCredential,
    #[error("the credential or principal is inactive")]
    CredentialInactive,
    #[error("the requested operation is not permitted")]
    Forbidden,
    #[error("the requested resource was not found")]
    NotFound,
    #[error("a request precondition is required")]
    PreconditionRequired,
    #[error("the resource changed since it was read")]
    Stale { current_etag: Option<String> },
    #[error("the request is invalid: {0}")]
    Validation(String),
    #[error("the requested state transition conflicts with current state: {0}")]
    Conflict(String),
    #[error("the request rate limit was exceeded")]
    RateLimited,
    #[error("the request reused an idempotency key with different input")]
    IdempotencyConflict,
    #[error("a required control-plane dependency is unavailable")]
    DependencyUnavailable,
    #[error("an internal invariant failed")]
    Internal,
}

impl From<crate::adapters::postgres::StoreError> for ApplicationError {
    fn from(error: crate::adapters::postgres::StoreError) -> Self {
        tracing::error!(error = ?error, "persistence operation failed");
        Self::DependencyUnavailable
    }
}

impl From<sqlx::Error> for ApplicationError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(error = %error, "database operation failed");
        Self::DependencyUnavailable
    }
}
