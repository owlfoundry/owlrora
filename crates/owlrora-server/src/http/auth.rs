use axum::http::{HeaderMap, HeaderValue, header};
use uuid::Uuid;

use crate::{
    application::{Application, ApplicationError, RequestIdentity},
    domain::AuthenticationMethod,
};

use super::ApiError;

const SESSION_COOKIE_NAME: &str = "owlrora_session";
const OIDC_TRANSACTION_COOKIE_NAME: &str = "owlrora_oidc_transaction";
const CSRF_HEADER: &str = "x-owlrora-csrf-token";
const REQUEST_ID_HEADER: &str = "x-request-id";

#[must_use]
pub fn request_id(headers: &HeaderMap) -> String {
    headers
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
        .map(str::to_owned)
        .unwrap_or_else(|| format!("req_{}", Uuid::now_v7()))
}

pub async fn authenticate(
    application: &Application,
    headers: &HeaderMap,
) -> Result<RequestIdentity, ApiError> {
    let request_id = request_id(headers);
    let bearer = bearer(headers).map_err(|error| ApiError::new(error, request_id.clone()))?;
    let session =
        session_cookie(headers).map_err(|error| ApiError::new(error, request_id.clone()))?;
    if bearer.is_some() && session.is_some() {
        return Err(ApiError::new(
            ApplicationError::InvalidCredential,
            request_id,
        ));
    }
    if let Some(bearer) = bearer {
        if bearer.starts_with("owlrora_mgmt_v1.") {
            return application
                .authenticate_management_key(bearer, request_id.clone())
                .map_err(|error| ApiError::new(error, request_id));
        }
        return application
            .authenticate_external_jwt(bearer, request_id.clone())
            .map_err(|error| ApiError::new(error, request_id));
    }
    if let Some(session) = session {
        let csrf = headers
            .get(CSRF_HEADER)
            .and_then(|value| value.to_str().ok());
        return application
            .authenticate_session(session, csrf, request_id.clone())
            .await
            .map_err(|error| ApiError::new(error, request_id));
    }
    Err(ApiError::new(
        ApplicationError::AuthenticationRequired,
        request_id,
    ))
}

pub fn authenticate_management_key_exchange(
    application: &Application,
    headers: &HeaderMap,
) -> Result<RequestIdentity, ApiError> {
    let request_id = request_id(headers);
    let raw = bearer(headers)
        .map_err(|error| ApiError::new(error, request_id.clone()))?
        .ok_or_else(|| {
            ApiError::new(ApplicationError::AuthenticationRequired, request_id.clone())
        })?;
    if !raw.starts_with("owlrora_mgmt_v1.") {
        return Err(ApiError::new(
            ApplicationError::InvalidCredential,
            request_id,
        ));
    }
    application
        .authenticate_management_key(raw, request_id.clone())
        .map_err(|error| ApiError::new(error, request_id))
}

pub fn require_command_security(
    application: &Application,
    identity: &RequestIdentity,
    headers: &HeaderMap,
) -> Result<(), ApiError> {
    if matches!(
        identity.principal.authentication_method,
        AuthenticationMethod::ManagementApiKeySession | AuthenticationMethod::ExternalSession
    ) {
        if !identity.csrf_validated || !origin_matches(application, headers) {
            return Err(ApiError::new(
                ApplicationError::Forbidden,
                identity.request_id.clone(),
            ));
        }
    }
    Ok(())
}

pub fn if_match<'a>(headers: &'a HeaderMap, request_id: &str) -> Result<Option<&'a str>, ApiError> {
    headers
        .get(header::IF_MATCH)
        .map(|value| {
            value.to_str().map_err(|_| {
                ApiError::validation("If-Match is not a valid header value", request_id)
            })
        })
        .transpose()
}

#[must_use]
pub fn session_cookie_header(raw_session: &str, max_age_seconds: u64) -> HeaderValue {
    let value = format!(
        "{SESSION_COOKIE_NAME}={raw_session}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age_seconds}"
    );
    HeaderValue::from_str(&value).expect("canonical session material is a valid cookie value")
}

#[must_use]
pub fn clear_session_cookie_header() -> HeaderValue {
    HeaderValue::from_static("owlrora_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0")
}

#[must_use]
pub fn oidc_transaction_cookie_header(transaction_token: &str) -> HeaderValue {
    let value = format!(
        "{OIDC_TRANSACTION_COOKIE_NAME}={transaction_token}; Path=/auth/v1/issuers/; HttpOnly; Secure; SameSite=Lax; Max-Age=600"
    );
    HeaderValue::from_str(&value).expect("canonical OIDC transaction token is a valid cookie value")
}

#[must_use]
pub fn clear_oidc_transaction_cookie_header() -> HeaderValue {
    HeaderValue::from_static(
        "owlrora_oidc_transaction=; Path=/auth/v1/issuers/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
    )
}

pub fn oidc_transaction_cookie(headers: &HeaderMap) -> Result<&str, ApplicationError> {
    named_cookie(headers, OIDC_TRANSACTION_COOKIE_NAME)?.ok_or(ApplicationError::InvalidCredential)
}

fn bearer(headers: &HeaderMap) -> Result<Option<&str>, ApplicationError> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| ApplicationError::InvalidCredential)?;
    let raw = value
        .strip_prefix("Bearer ")
        .filter(|value| !value.is_empty() && !value.contains(char::is_whitespace))
        .ok_or(ApplicationError::InvalidCredential)?;
    Ok(Some(raw))
}

fn session_cookie(headers: &HeaderMap) -> Result<Option<&str>, ApplicationError> {
    named_cookie(headers, SESSION_COOKIE_NAME)
}

fn named_cookie<'a>(
    headers: &'a HeaderMap,
    cookie_name: &str,
) -> Result<Option<&'a str>, ApplicationError> {
    let Some(value) = headers.get(header::COOKIE) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| ApplicationError::InvalidCredential)?;
    let mut found = None;
    for part in value.split(';') {
        let Some((name, value)) = part.trim().split_once('=') else {
            continue;
        };
        if name == cookie_name {
            if found.is_some() || value.is_empty() {
                return Err(ApplicationError::InvalidCredential);
            }
            found = Some(value);
        }
    }
    Ok(found)
}

fn origin_matches(application: &Application, headers: &HeaderMap) -> bool {
    let Some(expected) = application.config.public_origin.as_ref() else {
        return false;
    };
    let Some(actual) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    actual == expected.origin().ascii_serialization()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_ids_are_bounded_and_invalid_values_are_replaced() {
        let mut headers = HeaderMap::new();
        headers.insert(REQUEST_ID_HEADER, HeaderValue::from_static("client_123"));
        assert_eq!(request_id(&headers), "client_123");
        headers.insert(REQUEST_ID_HEADER, HeaderValue::from_static("invalid value"));
        assert!(request_id(&headers).starts_with("req_"));
    }

    #[test]
    fn duplicate_session_cookies_fail_closed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("owlrora_session=a; owlrora_session=b"),
        );
        assert!(session_cookie(&headers).is_err());
    }
}
