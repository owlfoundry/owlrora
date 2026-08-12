mod auth_routes;
mod identity;
mod keys;
mod tenancy;

pub use auth_routes::*;
pub use identity::*;
pub use keys::*;
pub use tenancy::*;

use axum::{
    Json,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::application::{ApplicationError, EntityTag, IdempotencyReplay, RequestIdentity};

use super::ApiError;

pub(super) fn app_error(error: ApplicationError, identity: &RequestIdentity) -> ApiError {
    ApiError::new(error, identity.request_id.clone())
}

pub(super) fn json_response<T: Serialize>(value: T) -> Response {
    Json(value).into_response()
}

pub(super) fn json_etag_response<T: Serialize>(value: T, etag: &EntityTag) -> Response {
    let mut response = Json(value).into_response();
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(etag.as_str()).expect("opaque ETags are valid headers"),
    );
    response
}

pub(super) fn idempotency_key<'a>(
    headers: &'a HeaderMap,
    identity: &RequestIdentity,
) -> Result<Option<&'a str>, ApiError> {
    headers
        .get("idempotency-key")
        .map(|value| {
            value.to_str().map_err(|_| {
                app_error(
                    ApplicationError::Validation(
                        "Idempotency-Key must be a valid ASCII header".to_owned(),
                    ),
                    identity,
                )
            })
        })
        .transpose()
}

pub(super) fn reject_idempotency_key(
    headers: &HeaderMap,
    identity: &RequestIdentity,
) -> Result<(), ApiError> {
    if headers.contains_key("idempotency-key") {
        return Err(app_error(
            ApplicationError::Validation(
                "this one-time-secret command does not accept Idempotency-Key".to_owned(),
            ),
            identity,
        ));
    }
    Ok(())
}

pub(super) fn idempotency_replay_response(replay: IdempotencyReplay) -> Response {
    let status = StatusCode::from_u16(replay.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = (status, Json(replay.body)).into_response();
    if let Some(etag) = replay.etag
        && let Ok(value) = HeaderValue::from_str(&etag)
    {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

pub(super) fn no_content() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

pub(super) fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
