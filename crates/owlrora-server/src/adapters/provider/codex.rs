use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, TimeZone as _, Utc};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const USER_CODE_URL: &str = "https://auth.openai.com/api/accounts/deviceauth/usercode";
const DEVICE_TOKEN_URL: &str = "https://auth.openai.com/api/accounts/deviceauth/token";
const OAUTH_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const REDIRECT_URI: &str = "https://auth.openai.com/deviceauth/callback";
pub const VERIFICATION_URL: &str = "https://auth.openai.com/codex/device";
pub const RESPONSES_BASE_URL: &str = "https://chatgpt.com/backend-api/codex";
pub const LOGIN_LIFETIME_SECONDS: u32 = 15 * 60;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const NETWORK_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct CodexAdapter {
    client: Client,
}

#[derive(Debug, Error)]
pub enum CodexAdapterError {
    #[error("Codex authentication dependency is unavailable")]
    DependencyUnavailable,
    #[error("Codex authentication rejected the request")]
    Rejected,
    #[error("Codex authentication returned an unsupported contract")]
    UnsupportedContract,
}

pub struct DeviceLogin {
    pub polling_material: DevicePollingMaterial,
    pub user_code: String,
    pub interval_seconds: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePollingMaterial {
    pub device_auth_id: String,
    pub user_code: String,
}

pub enum DevicePoll {
    Pending,
    Authorized(AuthorizationGrant),
}

#[derive(Deserialize)]
pub struct AuthorizationGrant {
    authorization_code: String,
    code_challenge: String,
    code_verifier: String,
}

#[derive(Deserialize, Serialize, Zeroize)]
#[zeroize(drop)]
pub struct TokenMaterial {
    pub id_token: String,
    pub access_token: String,
    pub refresh_token: String,
}

pub struct TokenSet {
    pub material: TokenMaterial,
    pub account_id: String,
    pub token_expires_at: Option<DateTime<Utc>>,
}

pub enum RefreshResult {
    Succeeded(TokenSet),
    Rejected,
    TransientFailure,
}

#[derive(Deserialize)]
struct UserCodeResponse {
    device_auth_id: String,
    #[serde(alias = "usercode")]
    user_code: String,
    #[serde(deserialize_with = "deserialize_interval")]
    interval: u32,
}

#[allow(clippy::struct_field_names)]
#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
    access_token: String,
    refresh_token: String,
}

#[allow(clippy::struct_field_names)]
#[derive(Deserialize)]
struct RefreshResponse {
    id_token: String,
    access_token: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Serialize)]
struct RefreshRequest<'a> {
    client_id: &'static str,
    grant_type: &'static str,
    refresh_token: &'a str,
    scope: &'static str,
}

impl CodexAdapter {
    pub fn new() -> Result<Self, CodexAdapterError> {
        let client = Client::builder()
            .https_only(true)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(NETWORK_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| CodexAdapterError::DependencyUnavailable)?;
        Ok(Self { client })
    }

    pub async fn start_device_login(&self) -> Result<DeviceLogin, CodexAdapterError> {
        let response = self
            .client
            .post(USER_CODE_URL)
            .json(&serde_json::json!({"client_id":CLIENT_ID}))
            .send()
            .await
            .map_err(|_| CodexAdapterError::DependencyUnavailable)?;
        if !response.status().is_success() {
            return Err(classify_status(response.status()));
        }
        let response: UserCodeResponse = read_json(response).await?;
        validate_bounded(&response.device_auth_id, 4096)?;
        validate_bounded(&response.user_code, 128)?;
        if !(1..=300).contains(&response.interval) {
            return Err(CodexAdapterError::UnsupportedContract);
        }
        Ok(DeviceLogin {
            polling_material: DevicePollingMaterial {
                device_auth_id: response.device_auth_id,
                user_code: response.user_code.clone(),
            },
            user_code: response.user_code,
            interval_seconds: response.interval,
        })
    }

    pub async fn poll_device_login(
        &self,
        material: &DevicePollingMaterial,
    ) -> Result<DevicePoll, CodexAdapterError> {
        validate_bounded(&material.device_auth_id, 4096)?;
        validate_bounded(&material.user_code, 128)?;
        let response = self
            .client
            .post(DEVICE_TOKEN_URL)
            .json(&serde_json::json!({
                "device_auth_id":material.device_auth_id,
                "user_code":material.user_code,
            }))
            .send()
            .await
            .map_err(|_| CodexAdapterError::DependencyUnavailable)?;
        if matches!(
            response.status(),
            StatusCode::FORBIDDEN | StatusCode::NOT_FOUND
        ) {
            return Ok(DevicePoll::Pending);
        }
        if !response.status().is_success() {
            return Err(classify_status(response.status()));
        }
        let grant: AuthorizationGrant = read_json(response).await?;
        validate_bounded(&grant.authorization_code, 65_536)?;
        validate_bounded(&grant.code_challenge, 4096)?;
        validate_bounded(&grant.code_verifier, 4096)?;
        Ok(DevicePoll::Authorized(grant))
    }

    pub async fn exchange_authorization_code(
        &self,
        grant: AuthorizationGrant,
    ) -> Result<TokenSet, CodexAdapterError> {
        let response = self
            .client
            .post(OAUTH_TOKEN_URL)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", grant.authorization_code.as_str()),
                ("redirect_uri", REDIRECT_URI),
                ("client_id", CLIENT_ID),
                ("code_verifier", grant.code_verifier.as_str()),
            ])
            .send()
            .await
            .map_err(|_| CodexAdapterError::DependencyUnavailable)?;
        if !response.status().is_success() {
            return Err(classify_status(response.status()));
        }
        let response: TokenResponse = read_json(response).await?;
        token_set(TokenMaterial {
            id_token: response.id_token,
            access_token: response.access_token,
            refresh_token: response.refresh_token,
        })
    }

    pub async fn refresh(&self, old: &TokenMaterial) -> Result<RefreshResult, CodexAdapterError> {
        validate_token_material(old)?;
        let response = self
            .client
            .post(OAUTH_TOKEN_URL)
            .json(&RefreshRequest {
                client_id: CLIENT_ID,
                grant_type: "refresh_token",
                refresh_token: &old.refresh_token,
                scope: "openid profile email",
            })
            .send()
            .await
            .map_err(|_| CodexAdapterError::DependencyUnavailable)?;
        if matches!(
            response.status(),
            StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            return Ok(RefreshResult::Rejected);
        }
        if !response.status().is_success() {
            return Ok(RefreshResult::TransientFailure);
        }
        let response: RefreshResponse = read_json(response).await?;
        let material = TokenMaterial {
            id_token: response.id_token,
            access_token: response
                .access_token
                .unwrap_or_else(|| old.access_token.clone()),
            refresh_token: response
                .refresh_token
                .unwrap_or_else(|| old.refresh_token.clone()),
        };
        token_set(material).map(RefreshResult::Succeeded)
    }
}

fn token_set(material: TokenMaterial) -> Result<TokenSet, CodexAdapterError> {
    validate_token_material(&material)?;
    let account_id = account_id_from_token_material(&material)?;
    let claims = parse_jwt_claims(&material.id_token)?;
    let token_expires_at = claims
        .get("exp")
        .and_then(Value::as_i64)
        .and_then(|seconds| Utc.timestamp_opt(seconds, 0).single());
    Ok(TokenSet {
        material,
        account_id,
        token_expires_at,
    })
}

pub(crate) fn account_id_from_token_material(
    material: &TokenMaterial,
) -> Result<String, CodexAdapterError> {
    validate_token_material(material)?;
    let claims = parse_jwt_claims(&material.id_token)?;
    let auth = claims
        .get("https://api.openai.com/auth")
        .and_then(Value::as_object);
    let account_id = auth
        .and_then(|value| value.get("chatgpt_account_id"))
        .and_then(Value::as_str)
        .or_else(|| claims.get("chatgpt_account_id").and_then(Value::as_str))
        .ok_or(CodexAdapterError::UnsupportedContract)?;
    validate_bounded(account_id, 512)?;
    Ok(account_id.to_owned())
}

fn validate_token_material(material: &TokenMaterial) -> Result<(), CodexAdapterError> {
    validate_bounded(&material.id_token, 65_536)?;
    validate_bounded(&material.access_token, 65_536)?;
    validate_bounded(&material.refresh_token, 65_536)
}

fn parse_jwt_claims(token: &str) -> Result<Value, CodexAdapterError> {
    let mut parts = token.split('.');
    let _header = parts.next().ok_or(CodexAdapterError::UnsupportedContract)?;
    let payload = parts.next().ok_or(CodexAdapterError::UnsupportedContract)?;
    let _signature = parts.next().ok_or(CodexAdapterError::UnsupportedContract)?;
    if parts.next().is_some() || payload.len() > MAX_RESPONSE_BYTES * 2 {
        return Err(CodexAdapterError::UnsupportedContract);
    }
    let mut bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| CodexAdapterError::UnsupportedContract)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        bytes.zeroize();
        return Err(CodexAdapterError::UnsupportedContract);
    }
    let result = serde_json::from_slice(&bytes).map_err(|_| CodexAdapterError::UnsupportedContract);
    bytes.zeroize();
    result
}

async fn read_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, CodexAdapterError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(CodexAdapterError::UnsupportedContract);
    }
    let bytes = Zeroizing::new(
        response
            .bytes()
            .await
            .map_err(|_| CodexAdapterError::DependencyUnavailable)?
            .to_vec(),
    );
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(CodexAdapterError::UnsupportedContract);
    }
    serde_json::from_slice(&bytes).map_err(|_| CodexAdapterError::UnsupportedContract)
}

fn classify_status(status: StatusCode) -> CodexAdapterError {
    if status.is_client_error() {
        CodexAdapterError::Rejected
    } else {
        CodexAdapterError::DependencyUnavailable
    }
}

fn validate_bounded(value: &str, maximum: usize) -> Result<(), CodexAdapterError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        Err(CodexAdapterError::UnsupportedContract)
    } else {
        Ok(())
    }
}

fn deserialize_interval<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    let value = String::deserialize(deserializer)?;
    value.trim().parse().map_err(D::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_account_and_expiry_from_id_token() {
        let payload = URL_SAFE_NO_PAD.encode(
            br#"{"exp":1893456000,"https://api.openai.com/auth":{"chatgpt_account_id":"account-1"}}"#,
        );
        let set = token_set(TokenMaterial {
            id_token: format!("e30.{payload}.signature"),
            access_token: "access".to_owned(),
            refresh_token: "refresh".to_owned(),
        })
        .unwrap();
        assert_eq!(set.account_id, "account-1");
        assert!(set.token_expires_at.is_some());
    }

    #[test]
    fn rejects_missing_account_claim() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"user"}"#);
        assert!(
            token_set(TokenMaterial {
                id_token: format!("e30.{payload}.signature"),
                access_token: "access".to_owned(),
                refresh_token: "refresh".to_owned(),
            })
            .is_err()
        );
    }
}
