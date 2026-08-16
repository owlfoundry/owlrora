use std::time::Duration;

use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use owlrora_key_provider::SecretPlaintext;
#[cfg(test)]
use reqsign::aws::StaticCredentialProvider;
use reqsign::{
    aws::{
        AssumeRoleCredentialProvider, DefaultCredentialProvider as AwsDefaultCredentialProvider,
        DefaultSigner, default_signer,
    },
    google::{DefaultSigner as GoogleDefaultSigner, RequestSigner as GoogleRequestSigner},
};
use reqsign_http_send_reqwest::ReqwestHttpSend;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::domain::CredentialKind;

const GOOGLE_CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
const AZURE_COGNITIVE_SCOPE: &str = "https://cognitiveservices.azure.com/.default";
const MAX_WORKLOAD_TOKEN_BYTES: u64 = 256 * 1024;

#[derive(Debug, Error)]
pub enum ProviderAuthError {
    #[error("provider credential configuration is invalid")]
    Configuration,
    #[error("provider credential is unavailable")]
    Unavailable,
    #[error("provider request could not be signed")]
    Signing,
}

pub struct ProviderAuthenticator {
    source: AuthSource,
}

enum AuthSource {
    Aws(DefaultSigner),
    GoogleServiceAccount(GoogleAuth),
    GoogleApplicationDefault(GoogleDefaultSigner),
    Azure(AzureWorkloadAuth),
}

struct GoogleAuth {
    client: reqwest::Client,
    client_email: String,
    token_uri: url::Url,
    encoding_key: EncodingKey,
    cached: Mutex<Option<CachedBearer>>,
}

struct AzureWorkloadAuth {
    client: reqwest::Client,
    tenant_id: String,
    client_id: String,
    token_file: String,
    cached: Mutex<Option<CachedBearer>>,
}

struct CachedBearer {
    value: String,
    refresh_at: Instant,
}

#[cfg(test)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AwsStaticMaterial {
    access_key_id: String,
    secret_access_key: String,
    #[serde(default)]
    session_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AwsAssumeRoleConfiguration {
    role_arn: String,
    #[serde(default = "default_role_session_name")]
    role_session_name: String,
    #[serde(default)]
    external_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AzureWorkloadConfiguration {
    tenant_id: String,
    client_id: String,
    token_file: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GoogleServiceAccountMaterial {
    #[serde(default, rename = "project_id")]
    _project_id: Option<String>,
    client_email: String,
    private_key: String,
    token_uri: String,
}

#[derive(serde::Serialize)]
struct GoogleServiceAccountClaims<'a> {
    iss: &'a str,
    scope: &'static str,
    aud: &'a str,
    iat: i64,
    exp: i64,
}

#[derive(Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    expires_in: u64,
    token_type: String,
}

#[derive(Deserialize)]
struct AzureTokenResponse {
    access_token: String,
    expires_in: u64,
    token_type: String,
}

fn default_role_session_name() -> String {
    "owlrora".to_owned()
}

impl std::fmt::Debug for ProviderAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self.source {
            AuthSource::Aws(_) => "aws_sigv4",
            AuthSource::GoogleServiceAccount(_) | AuthSource::GoogleApplicationDefault(_) => {
                "google_oauth"
            }
            AuthSource::Azure(_) => "azure_workload_identity",
        };
        formatter
            .debug_struct("ProviderAuthenticator")
            .field("kind", &kind)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

impl ProviderAuthenticator {
    pub fn build(
        kind: CredentialKind,
        region: Option<&str>,
        workload_configuration: Option<&serde_json::Value>,
        material: Option<SecretPlaintext>,
        client: reqwest::Client,
    ) -> Result<Self, ProviderAuthError> {
        let source = match kind {
            CredentialKind::AwsDefaultChain => {
                let region = bounded_non_secret(region.ok_or(ProviderAuthError::Configuration)?)?;
                if material.is_some()
                    || !workload_configuration
                        .and_then(serde_json::Value::as_object)
                        .is_some_and(|configuration| configuration.is_empty())
                {
                    return Err(ProviderAuthError::Configuration);
                }
                let context =
                    reqsign::default_context().with_http_send(ReqwestHttpSend::new(client));
                AuthSource::Aws(
                    default_signer("bedrock-runtime", region)
                        .with_context(context)
                        .with_credential_provider(AwsDefaultCredentialProvider::new()),
                )
            }
            CredentialKind::AwsAssumeRole => {
                let region = bounded_non_secret(region.ok_or(ProviderAuthError::Configuration)?)?;
                if material.is_some() {
                    return Err(ProviderAuthError::Configuration);
                }
                let configuration: AwsAssumeRoleConfiguration = serde_json::from_value(
                    workload_configuration
                        .cloned()
                        .ok_or(ProviderAuthError::Configuration)?,
                )
                .map_err(|_| ProviderAuthError::Configuration)?;
                validate_role_configuration(&configuration)?;
                let source_provider = AwsDefaultCredentialProvider::new();
                let context =
                    reqsign::default_context().with_http_send(ReqwestHttpSend::new(client));
                let sts_signer = default_signer("sts", region)
                    .with_context(context.clone())
                    .with_credential_provider(source_provider);
                let mut provider =
                    AssumeRoleCredentialProvider::new(configuration.role_arn, sts_signer)
                        .with_region(region.to_owned())
                        .with_regional_sts_endpoint()
                        .with_role_session_name(configuration.role_session_name);
                if let Some(external_id) = configuration.external_id {
                    provider = provider.with_external_id(external_id);
                }
                AuthSource::Aws(
                    default_signer("bedrock-runtime", region)
                        .with_context(context)
                        .with_credential_provider(provider),
                )
            }
            CredentialKind::GoogleServiceAccount => {
                let material = material.ok_or(ProviderAuthError::Configuration)?;
                let configuration = material
                    .expose(|bytes| serde_json::from_slice::<GoogleServiceAccountMaterial>(bytes))
                    .map_err(|_| ProviderAuthError::Configuration)?;
                AuthSource::GoogleServiceAccount(build_google_auth(configuration, client)?)
            }
            CredentialKind::GoogleApplicationDefault => {
                if material.is_some()
                    || !workload_configuration
                        .and_then(serde_json::Value::as_object)
                        .is_some_and(|configuration| configuration.is_empty())
                {
                    return Err(ProviderAuthError::Configuration);
                }
                let context =
                    reqsign::default_context().with_http_send(ReqwestHttpSend::new(client));
                let signer = reqsign::google::default_signer("")
                    .with_context(context)
                    .with_request_signer(
                        GoogleRequestSigner::new("").with_scope(GOOGLE_CLOUD_PLATFORM_SCOPE),
                    );
                AuthSource::GoogleApplicationDefault(signer)
            }
            CredentialKind::AzureWorkloadIdentity => {
                if material.is_some() {
                    return Err(ProviderAuthError::Configuration);
                }
                let configuration: AzureWorkloadConfiguration = serde_json::from_value(
                    workload_configuration
                        .cloned()
                        .ok_or(ProviderAuthError::Configuration)?,
                )
                .map_err(|_| ProviderAuthError::Configuration)?;
                validate_azure_configuration(&configuration)?;
                AuthSource::Azure(AzureWorkloadAuth {
                    client,
                    tenant_id: configuration.tenant_id,
                    client_id: configuration.client_id,
                    token_file: configuration.token_file,
                    cached: Mutex::new(None),
                })
            }
            _ => return Err(ProviderAuthError::Configuration),
        };
        Ok(Self { source })
    }

    #[cfg(test)]
    pub(crate) fn build_aws_static_fixture(
        region: &str,
        material: SecretPlaintext,
        client: reqwest::Client,
    ) -> Result<Self, ProviderAuthError> {
        let region = bounded_non_secret(region)?;
        let credentials = material
            .expose(|bytes| serde_json::from_slice::<AwsStaticMaterial>(bytes))
            .map_err(|_| ProviderAuthError::Configuration)?;
        let provider = aws_static_provider(&credentials)?;
        let context = reqsign::Context::new().with_http_send(ReqwestHttpSend::new(client));
        Ok(Self {
            source: AuthSource::Aws(
                default_signer("bedrock-runtime", region)
                    .with_context(context)
                    .with_credential_provider(provider),
            ),
        })
    }

    pub async fn apply(
        &self,
        request: &mut reqwest::Request,
        body: &[u8],
    ) -> Result<(), ProviderAuthError> {
        match &self.source {
            AuthSource::Aws(signer) => {
                let mut head = http::Request::builder()
                    .method(request.method().clone())
                    .uri(request.url().as_str())
                    .body(())
                    .map_err(|_| ProviderAuthError::Signing)?
                    .into_parts()
                    .0;
                head.headers = request.headers().clone();
                let payload_hash = format!("{:x}", Sha256::digest(body));
                head.headers.insert(
                    "x-amz-content-sha256",
                    http::HeaderValue::from_str(&payload_hash)
                        .map_err(|_| ProviderAuthError::Signing)?,
                );
                signer
                    .sign(&mut head, None)
                    .await
                    .map_err(|_| ProviderAuthError::Unavailable)?;
                *request.headers_mut() = head.headers;
                Ok(())
            }
            AuthSource::GoogleServiceAccount(auth) => {
                let token = auth.token().await?;
                request
                    .headers_mut()
                    .insert(http::header::AUTHORIZATION, bearer_header(&token)?);
                Ok(())
            }
            AuthSource::GoogleApplicationDefault(signer) => {
                let mut head = http::Request::builder()
                    .method(request.method().clone())
                    .uri(request.url().as_str())
                    .body(())
                    .map_err(|_| ProviderAuthError::Signing)?
                    .into_parts()
                    .0;
                head.headers = request.headers().clone();
                signer
                    .sign(&mut head, None)
                    .await
                    .map_err(|_| ProviderAuthError::Unavailable)?;
                *request.headers_mut() = head.headers;
                Ok(())
            }
            AuthSource::Azure(auth) => {
                let token = auth.token().await?;
                request
                    .headers_mut()
                    .insert(http::header::AUTHORIZATION, bearer_header(&token)?);
                Ok(())
            }
        }
    }
}

fn build_google_auth(
    configuration: GoogleServiceAccountMaterial,
    client: reqwest::Client,
) -> Result<GoogleAuth, ProviderAuthError> {
    if configuration.client_email.is_empty()
        || configuration.client_email.len() > 1024
        || configuration.client_email.chars().any(char::is_control)
        || configuration.private_key.len() > 64 * 1024
    {
        return Err(ProviderAuthError::Configuration);
    }
    let token_uri = configuration
        .token_uri
        .parse::<url::Url>()
        .map_err(|_| ProviderAuthError::Configuration)?;
    if !google_token_uri_allowed(&token_uri) {
        return Err(ProviderAuthError::Configuration);
    }
    let encoding_key = EncodingKey::from_rsa_pem(configuration.private_key.as_bytes())
        .map_err(|_| ProviderAuthError::Configuration)?;
    Ok(GoogleAuth {
        client,
        client_email: configuration.client_email,
        token_uri,
        encoding_key,
        cached: Mutex::new(None),
    })
}

fn google_token_uri_allowed(token_uri: &url::Url) -> bool {
    token_uri.scheme() == "https"
        && matches!(token_uri.host(), Some(url::Host::Domain(_)))
        && token_uri.username().is_empty()
        && token_uri.password().is_none()
        && token_uri.fragment().is_none()
}

impl GoogleAuth {
    async fn token(&self) -> Result<String, ProviderAuthError> {
        let mut cached = self.cached.lock().await;
        if let Some(token) = cached
            .as_ref()
            .filter(|token| token.refresh_at > Instant::now())
        {
            return Ok(token.value.clone());
        }
        let issued_at = Utc::now().timestamp();
        let expires_at = issued_at
            .checked_add(3600)
            .ok_or(ProviderAuthError::Unavailable)?;
        let claims = GoogleServiceAccountClaims {
            iss: &self.client_email,
            scope: GOOGLE_CLOUD_PLATFORM_SCOPE,
            aud: self.token_uri.as_str(),
            iat: issued_at,
            exp: expires_at,
        };
        let assertion = encode(&Header::new(Algorithm::RS256), &claims, &self.encoding_key)
            .map_err(|_| ProviderAuthError::Signing)?;
        let response = self
            .client
            .post(self.token_uri.clone())
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .map_err(|_| ProviderAuthError::Unavailable)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > MAX_WORKLOAD_TOKEN_BYTES)
        {
            return Err(ProviderAuthError::Unavailable);
        }
        let body = response
            .bytes()
            .await
            .map_err(|_| ProviderAuthError::Unavailable)?;
        if u64::try_from(body.len()).unwrap_or(u64::MAX) > MAX_WORKLOAD_TOKEN_BYTES {
            return Err(ProviderAuthError::Unavailable);
        }
        let token: OAuthTokenResponse =
            serde_json::from_slice(&body).map_err(|_| ProviderAuthError::Unavailable)?;
        if !token.token_type.eq_ignore_ascii_case("bearer")
            || token.access_token.is_empty()
            || token.access_token.chars().any(char::is_control)
            || token.expires_in < 60
        {
            return Err(ProviderAuthError::Unavailable);
        }
        *cached = Some(CachedBearer {
            value: token.access_token.clone(),
            refresh_at: Instant::now()
                + Duration::from_secs(token.expires_in.saturating_sub(60).max(1)),
        });
        Ok(token.access_token)
    }
}

impl AzureWorkloadAuth {
    async fn token(&self) -> Result<String, ProviderAuthError> {
        let mut cached = self.cached.lock().await;
        if let Some(token) = cached
            .as_ref()
            .filter(|token| token.refresh_at > Instant::now())
        {
            return Ok(token.value.clone());
        }
        let metadata = tokio::fs::metadata(&self.token_file)
            .await
            .map_err(|_| ProviderAuthError::Unavailable)?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_WORKLOAD_TOKEN_BYTES {
            return Err(ProviderAuthError::Unavailable);
        }
        let assertion = tokio::fs::read_to_string(&self.token_file)
            .await
            .map_err(|_| ProviderAuthError::Unavailable)?;
        let assertion = assertion.trim();
        if assertion.is_empty() || assertion.chars().any(char::is_control) {
            return Err(ProviderAuthError::Unavailable);
        }
        let endpoint = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        );
        let response = self
            .client
            .post(endpoint)
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("scope", AZURE_COGNITIVE_SCOPE),
                ("grant_type", "client_credentials"),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", assertion),
            ])
            .send()
            .await
            .map_err(|_| ProviderAuthError::Unavailable)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > MAX_WORKLOAD_TOKEN_BYTES)
        {
            return Err(ProviderAuthError::Unavailable);
        }
        let token: AzureTokenResponse = response
            .json()
            .await
            .map_err(|_| ProviderAuthError::Unavailable)?;
        if token.token_type != "Bearer"
            || token.access_token.is_empty()
            || token.access_token.chars().any(char::is_control)
            || token.expires_in < 60
        {
            return Err(ProviderAuthError::Unavailable);
        }
        let refresh_seconds = token.expires_in.saturating_sub(60).max(1);
        *cached = Some(CachedBearer {
            value: token.access_token.clone(),
            refresh_at: Instant::now() + Duration::from_secs(refresh_seconds),
        });
        Ok(token.access_token)
    }
}

fn bearer_header(value: &str) -> Result<http::HeaderValue, ProviderAuthError> {
    http::HeaderValue::from_str(&format!("Bearer {value}"))
        .map_err(|_| ProviderAuthError::Unavailable)
}

fn bounded_non_secret(value: &str) -> Result<&str, ProviderAuthError> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        Err(ProviderAuthError::Configuration)
    } else {
        Ok(value)
    }
}

#[cfg(test)]
fn aws_static_provider(
    value: &AwsStaticMaterial,
) -> Result<StaticCredentialProvider, ProviderAuthError> {
    validate_aws_material(value)?;
    let mut provider =
        StaticCredentialProvider::new(&value.access_key_id, &value.secret_access_key);
    if let Some(token) = value.session_token.as_deref() {
        provider = provider.with_session_token(token);
    }
    Ok(provider)
}

#[cfg(test)]
fn validate_aws_material(value: &AwsStaticMaterial) -> Result<(), ProviderAuthError> {
    if value.access_key_id.is_empty()
        || value.access_key_id.len() > 512
        || value.secret_access_key.is_empty()
        || value.secret_access_key.len() > 4096
        || value
            .session_token
            .as_ref()
            .is_some_and(|token| token.is_empty() || token.len() > 65_536)
    {
        Err(ProviderAuthError::Configuration)
    } else {
        Ok(())
    }
}

fn validate_role_configuration(
    value: &AwsAssumeRoleConfiguration,
) -> Result<(), ProviderAuthError> {
    if !value.role_arn.starts_with("arn:")
        || value.role_arn.len() > 2048
        || value.role_session_name.is_empty()
        || value.role_session_name.len() > 64
        || value
            .external_id
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > 1024)
    {
        Err(ProviderAuthError::Configuration)
    } else {
        Ok(())
    }
}

fn validate_azure_configuration(
    value: &AzureWorkloadConfiguration,
) -> Result<(), ProviderAuthError> {
    let uuid_like = |value: &str| uuid::Uuid::parse_str(value).is_ok();
    if !uuid_like(&value.tenant_id)
        || !uuid_like(&value.client_id)
        || value.token_file.is_empty()
        || value.token_file.len() > 4096
        || !std::path::Path::new(&value.token_file).is_absolute()
    {
        Err(ProviderAuthError::Configuration)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn signs_bedrock_request_with_explicit_material() {
        let material = SecretPlaintext::new(
            br#"{"access_key_id":"AKIDFIXTURE","secret_access_key":"fixture-secret","session_token":"fixture-session"}"#.to_vec(),
        )
        .unwrap();
        let auth = ProviderAuthenticator::build_aws_static_fixture(
            "us-west-2",
            material,
            reqwest::Client::new(),
        )
        .unwrap();
        let body = br#"{"fixture":true}"#;
        let mut request = reqwest::Client::new()
            .post("https://bedrock-runtime.us-west-2.amazonaws.com/model/fixture/invoke")
            .header("content-type", "application/json")
            .body(body.to_vec())
            .build()
            .unwrap();
        auth.apply(&mut request, body).await.unwrap();
        assert!(
            request.headers()[http::header::AUTHORIZATION]
                .to_str()
                .unwrap()
                .starts_with("AWS4-HMAC-SHA256 Credential=AKIDFIXTURE/")
        );
        assert_eq!(request.headers()["x-amz-security-token"], "fixture-session");
        assert!(request.headers().contains_key("x-amz-content-sha256"));
        assert!(request.headers().contains_key("x-amz-date"));
    }

    #[test]
    fn aws_default_chain_applies_environment_credentials_in_isolated_process() {
        const CHILD_MARKER: &str = "OWLRORA_AWS_DEFAULT_CHAIN_TEST_CHILD";
        const TEST_NAME: &str = "adapters::provider::auth::tests::aws_default_chain_applies_environment_credentials_in_isolated_process";
        if std::env::var_os(CHILD_MARKER).is_some() {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let workload = serde_json::json!({});
                let auth = ProviderAuthenticator::build(
                    CredentialKind::AwsDefaultChain,
                    Some("us-west-2"),
                    Some(&workload),
                    None,
                    reqwest::Client::new(),
                )
                .unwrap();
                let body = br#"{"fixture":true}"#;
                let mut request = reqwest::Client::new()
                    .post("https://bedrock-runtime.us-west-2.amazonaws.com/model/fixture/invoke")
                    .header("content-type", "application/json")
                    .body(body.to_vec())
                    .build()
                    .unwrap();
                auth.apply(&mut request, body).await.unwrap();
                assert!(
                    request.headers()[http::header::AUTHORIZATION]
                        .to_str()
                        .unwrap()
                        .starts_with("AWS4-HMAC-SHA256 Credential=AKIDENVIRONMENT/")
                );
                assert_eq!(
                    request.headers()["x-amz-security-token"],
                    "environment-session"
                );
            });
            return;
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(TEST_NAME)
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .env("AWS_ACCESS_KEY_ID", "AKIDENVIRONMENT")
            .env("AWS_SECRET_ACCESS_KEY", "environment-secret")
            .env("AWS_SESSION_TOKEN", "environment-session")
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env_remove("AWS_PROFILE")
            .env_remove("AWS_CONFIG_FILE")
            .env_remove("AWS_SHARED_CREDENTIALS_FILE")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn google_adc_uses_generation_client_and_ignores_proxy_environment() {
        const CHILD_MARKER: &str = "OWLRORA_GOOGLE_ADC_CLIENT_TEST_CHILD";
        const TEST_NAME: &str = "adapters::provider::auth::tests::google_adc_uses_generation_client_and_ignores_proxy_environment";
        if std::env::var_os(CHILD_MARKER).is_some() {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let workload = serde_json::json!({});
                let client = crate::runtime::generation_http_client_builder()
                    .build()
                    .unwrap();
                let auth = ProviderAuthenticator::build(
                    CredentialKind::GoogleApplicationDefault,
                    None,
                    Some(&workload),
                    None,
                    client,
                )
                .unwrap();
                let mut request = reqwest::Client::new()
                    .post("https://example.googleapis.com/v1/models")
                    .build()
                    .unwrap();
                auth.apply(&mut request, &[]).await.unwrap();
                assert_eq!(
                    request.headers()[http::header::AUTHORIZATION],
                    "Bearer generation-client-token"
                );
            });
            return;
        }

        use std::io::{Read as _, Write as _};

        let token_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let token_address = token_listener.local_addr().unwrap();
        let proxy_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_address = proxy_listener.local_addr().unwrap();
        let spawn_server = |listener: std::net::TcpListener, response: &'static [u8]| {
            std::thread::spawn(move || {
                listener.set_nonblocking(true).unwrap();
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                loop {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream
                                .set_read_timeout(Some(Duration::from_secs(2)))
                                .unwrap();
                            let mut request = vec![0_u8; 16 * 1024];
                            let read = stream.read(&mut request).unwrap_or(0);
                            request.truncate(read);
                            stream.write_all(response).unwrap();
                            return Some(request);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if std::time::Instant::now() >= deadline {
                                return None;
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("test listener failed: {error}"),
                    }
                }
            })
        };
        let token_body = br#"{"access_token":"generation-client-token","expires_in":3600,"token_type":"Bearer"}"#;
        let token_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            token_body.len(),
            String::from_utf8_lossy(token_body)
        )
        .into_bytes()
        .leak();
        let token_server = spawn_server(token_listener, token_response);
        let proxy_server = spawn_server(
            proxy_listener,
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );

        let directory = std::env::temp_dir().join(format!(
            "owlrora-google-adc-client-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let subject_path = directory.join("subject-token");
        let credentials_path = directory.join("credentials.json");
        std::fs::write(&subject_path, "fixture-subject-token").unwrap();
        std::fs::write(
            &credentials_path,
            serde_json::to_vec(&serde_json::json!({
                "type":"external_account",
                "audience":"fixture-audience",
                "subject_token_type":"urn:ietf:params:oauth:token-type:jwt",
                "token_url":format!("http://{token_address}/token"),
                "credential_source":{
                    "file":subject_path,
                    "format":{"type":"text"}
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(TEST_NAME)
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .env("GOOGLE_APPLICATION_CREDENTIALS", &credentials_path)
            .env("HTTP_PROXY", format!("http://{proxy_address}"))
            .env("HTTPS_PROXY", format!("http://{proxy_address}"))
            .env("ALL_PROXY", format!("http://{proxy_address}"))
            .env("NO_PROXY", "")
            .output()
            .unwrap();
        let token_request = token_server.join().unwrap();
        let proxy_request = proxy_server.join().unwrap();
        std::fs::remove_dir_all(directory).unwrap();
        assert!(
            output.status.success(),
            "child failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&token_request.unwrap()).starts_with("POST /token "),
            "generation client did not call the ADC token endpoint directly"
        );
        assert!(
            proxy_request.is_none(),
            "generation client unexpectedly used an environment proxy"
        );
    }

    #[test]
    fn builds_full_default_cloud_provider_chains_without_static_material() {
        let workload = serde_json::json!({});
        assert!(
            ProviderAuthenticator::build(
                CredentialKind::AwsDefaultChain,
                Some("us-west-2"),
                Some(&workload),
                None,
                reqwest::Client::new(),
            )
            .is_ok()
        );
        assert!(
            ProviderAuthenticator::build(
                CredentialKind::GoogleApplicationDefault,
                None,
                Some(&workload),
                None,
                reqwest::Client::new(),
            )
            .is_ok()
        );
        let unexpected = serde_json::json!({"path":"/tmp/credentials"});
        assert!(
            ProviderAuthenticator::build(
                CredentialKind::GoogleApplicationDefault,
                None,
                Some(&unexpected),
                None,
                reqwest::Client::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn google_token_uri_rejects_literal_addresses_and_unsafe_authority() {
        assert!(google_token_uri_allowed(
            &"https://oauth2.googleapis.com/token".parse().unwrap()
        ));
        assert!(!google_token_uri_allowed(
            &"https://127.0.0.1/token".parse().unwrap()
        ));
        assert!(!google_token_uri_allowed(
            &"https://[::1]/token".parse().unwrap()
        ));
        assert!(google_token_uri_allowed(
            &"https://oauth.example:8443/token".parse().unwrap()
        ));
        assert!(!google_token_uri_allowed(
            &"https://user@oauth.example/token".parse().unwrap()
        ));
    }

    #[test]
    fn rejects_unsafe_workload_configuration() {
        assert!(
            validate_azure_configuration(&AzureWorkloadConfiguration {
                tenant_id: "not-a-tenant".to_owned(),
                client_id: uuid::Uuid::now_v7().to_string(),
                token_file: "relative".to_owned(),
            })
            .is_err()
        );
        assert!(
            validate_role_configuration(&AwsAssumeRoleConfiguration {
                role_arn: "role".to_owned(),
                role_session_name: "owlrora".to_owned(),
                external_id: None,
            })
            .is_err()
        );
    }
}
