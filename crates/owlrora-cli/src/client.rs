use std::{
    collections::BTreeMap,
    fs,
    io::{self, IsTerminal as _, Read},
    path::Path,
    time::Duration,
};

use reqwest::{
    StatusCode, Url,
    blocking::{Client as HttpClient, Response},
    header::{AUTHORIZATION, CONTENT_LENGTH, ETAG, HeaderMap, HeaderValue},
};
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use thiserror::Error;

use crate::{
    contract::{Operation, OperationMode},
    profile::ResolvedProfile,
};

const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Default)]
pub struct Invocation {
    pub path_arguments: BTreeMap<String, String>,
    pub query: BTreeMap<String, String>,
    pub body: Option<Value>,
    pub etag: Option<String>,
    pub idempotency_key: Option<String>,
}

#[derive(Debug)]
pub struct OperationResponse {
    pub status: StatusCode,
    pub body: Value,
    pub etag: Option<String>,
    pub request_id: Option<String>,
}

pub struct ManagementClient {
    http: HttpClient,
    server_url: Url,
    authorization: HeaderValue,
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("invalid server URL {value:?}: {message}")]
    InvalidServerUrl { value: String, message: String },
    #[error(
        "non-loopback plaintext or verification-disabled connections require --allow-insecure-non-loopback"
    )]
    UnsafeTransport,
    #[error("failed to construct the HTTP client: {0}")]
    Build(reqwest::Error),
    #[error("management key contains bytes that cannot be sent in an HTTP header")]
    InvalidManagementKey,
    #[error("missing path argument {0}")]
    MissingPathArgument(String),
    #[error("operation {operation} requires the ETag from the candidate's source GET")]
    MissingEtag { operation: String },
    #[error("request body {path} exceeds the {MAX_REQUEST_BYTES}-byte limit")]
    RequestBodyTooLarge { path: String },
    #[error("failed to read request body from {path}: {source}")]
    ReadRequestBody { path: String, source: io::Error },
    #[error(
        "protected request body file {path} must be a non-symlink regular file owned by the current user with no group or other permissions"
    )]
    UnsafeProtectedRequestFile { path: String },
    #[cfg(not(unix))]
    #[error(
        "protected request body files are unsupported on this platform; use redirected standard input"
    )]
    ProtectedRequestFilesUnsupported,
    #[error("invalid JSON request body from {path}: {source}")]
    InvalidRequestBody {
        path: String,
        source: serde_json::Error,
    },
    #[error("the request failed before a response was received: {message}")]
    QueryTransport { message: String },
    #[error("command response is unavailable and its final outcome is unknown: {message}")]
    CommandOutcomeUnknown { message: String },
    #[error("response exceeds the {MAX_RESPONSE_BYTES}-byte limit")]
    ResponseTooLarge,
    #[error("failed to read the response: {0}")]
    ReadResponse(io::Error),
    #[error("server returned HTTP {status}: {code}: {message}{request_suffix}")]
    Api {
        status: StatusCode,
        code: String,
        message: String,
        request_suffix: String,
        request_id: Option<String>,
    },
    #[error("successful response was not valid JSON")]
    InvalidSuccessResponse,
    #[error("cannot read both the management key and request body from standard input")]
    ConflictingStdin,
    #[error("refusing to read protected secret material from terminal standard input")]
    InteractiveSecretStdin,
    #[error("protected secret standard input must be valid UTF-8")]
    InvalidSecretUtf8,
    #[error("a protected secret can be merged only into a JSON object candidate")]
    SecretCandidateNotObject,
}

impl ClientError {
    pub fn request_id(&self) -> Option<&str> {
        match self {
            Self::Api { request_id, .. } => request_id.as_deref(),
            _ => None,
        }
    }
}

impl ManagementClient {
    pub fn new(profile: ResolvedProfile) -> Result<Self, ClientError> {
        let server_url =
            Url::parse(&profile.server_url).map_err(|error| ClientError::InvalidServerUrl {
                value: profile.server_url.clone(),
                message: error.to_string(),
            })?;
        if !matches!(server_url.scheme(), "http" | "https")
            || server_url.cannot_be_a_base()
            || server_url.host_str().is_none()
            || server_url.query().is_some()
            || server_url.fragment().is_some()
        {
            return Err(ClientError::InvalidServerUrl {
                value: profile.server_url,
                message: "expected an absolute HTTP or HTTPS origin".to_owned(),
            });
        }
        let loopback = is_loopback_host(server_url.host_str().unwrap());
        let insecure =
            server_url.scheme() == "http" || profile.tls_policy.insecure_skip_verification;
        if insecure && !loopback && !profile.tls_policy.allow_insecure_non_loopback {
            return Err(ClientError::UnsafeTransport);
        }
        let http = HttpClient::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(profile.tls_policy.insecure_skip_verification)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("owlrora-cli/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(ClientError::Build)?;
        let authorization =
            HeaderValue::from_str(&format!("Bearer {}", profile.management_api_key))
                .map_err(|_| ClientError::InvalidManagementKey)?;

        Ok(Self {
            http,
            server_url,
            authorization,
        })
    }

    pub fn invoke(
        &self,
        operation: &Operation,
        invocation: &Invocation,
        client_kind: &str,
    ) -> Result<OperationResponse, ClientError> {
        if operation.etag_precondition && invocation.etag.is_none() {
            return Err(ClientError::MissingEtag {
                operation: operation.id.clone(),
            });
        }
        let url = self.operation_url(operation, invocation)?;
        let retry_safe =
            operation.client_generated_idempotency_key && invocation.idempotency_key.is_some();
        let max_attempts = if retry_safe { 2 } else { 1 };
        for attempt in 0..max_attempts {
            let mut request = match operation.method.as_str() {
                "GET" => self.http.get(url.clone()),
                "POST" => self.http.post(url.clone()),
                method => {
                    return Err(ClientError::InvalidServerUrl {
                        value: method.to_owned(),
                        message: "generated contract contains an unsupported method".to_owned(),
                    });
                }
            }
            .header(AUTHORIZATION, self.authorization.clone())
            .header(
                "x-owlrora-client",
                format!("{client_kind}/{}", env!("CARGO_PKG_VERSION")),
            );
            if let Some(etag) = &invocation.etag {
                request = request.header("if-match", etag);
            }
            if let Some(idempotency_key) = &invocation.idempotency_key {
                request = request.header("idempotency-key", idempotency_key);
            }
            if let Some(body) = &invocation.body {
                request = request.json(body);
            }
            let result = request.send().map_or_else(
                |error| {
                    Err(if operation.mode == OperationMode::Command {
                        ClientError::CommandOutcomeUnknown {
                            message: safe_transport_message(&error),
                        }
                    } else {
                        ClientError::QueryTransport {
                            message: safe_transport_message(&error),
                        }
                    })
                },
                |response| parse_response(response, operation),
            );
            match result {
                Err(error) if attempt + 1 < max_attempts && retryable_idempotent_error(&error) => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                result => return result,
            }
        }
        unreachable!("every bounded HTTP attempt returns a result")
    }

    fn operation_url(
        &self,
        operation: &Operation,
        invocation: &Invocation,
    ) -> Result<Url, ClientError> {
        let mut url = self.server_url.clone();
        url.set_path("");
        url.set_query(None);
        {
            let mut segments =
                url.path_segments_mut()
                    .map_err(|()| ClientError::InvalidServerUrl {
                        value: self.server_url.to_string(),
                        message: "URL cannot contain path segments".to_owned(),
                    })?;
            segments.clear();
            for segment in operation
                .path
                .split('/')
                .filter(|segment| !segment.is_empty())
            {
                if let Some(parameter) = segment
                    .strip_prefix('{')
                    .and_then(|segment| segment.strip_suffix('}'))
                {
                    let value = invocation
                        .path_arguments
                        .get(parameter)
                        .ok_or_else(|| ClientError::MissingPathArgument(parameter.to_owned()))?;
                    segments.push(value);
                } else {
                    segments.push(segment);
                }
            }
        }
        if !invocation.query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (name, value) in &invocation.query {
                pairs.append_pair(name, value);
            }
        }
        Ok(url)
    }
}

pub fn load_request_body(
    source: &str,
    explicit_etag: Option<String>,
    protected: bool,
) -> Result<(Value, Option<String>), ClientError> {
    let bytes = if source == "-" {
        if protected && io::stdin().is_terminal() {
            return Err(ClientError::InteractiveSecretStdin);
        }
        read_bounded(io::stdin(), MAX_REQUEST_BYTES).map_err(|source| {
            ClientError::ReadRequestBody {
                path: "standard input".to_owned(),
                source,
            }
        })?
    } else {
        let file = if protected {
            open_protected_request_file(Path::new(source))?
        } else {
            fs::File::open(source).map_err(|source_error| ClientError::ReadRequestBody {
                path: source.to_owned(),
                source: source_error,
            })?
        };
        read_bounded(file, MAX_REQUEST_BYTES).map_err(|source_error| {
            ClientError::ReadRequestBody {
                path: source.to_owned(),
                source: source_error,
            }
        })?
    };
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(ClientError::RequestBodyTooLarge {
            path: source.to_owned(),
        });
    }
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|source_error| ClientError::InvalidRequestBody {
            path: source.to_owned(),
            source: source_error,
        })?;
    if let Some(candidate) = value.get("candidate") {
        let embedded_etag = value.get("etag").and_then(Value::as_str).map(str::to_owned);
        Ok((candidate.clone(), explicit_etag.or(embedded_etag)))
    } else {
        Ok((value, explicit_etag))
    }
}

#[cfg(unix)]
#[allow(clippy::verbose_bit_mask)]
fn open_protected_request_file(path: &Path) -> Result<fs::File, ClientError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let unsafe_file = || ClientError::UnsafeProtectedRequestFile {
        path: path.display().to_string(),
    };
    let before = fs::symlink_metadata(path).map_err(|source| ClientError::ReadRequestBody {
        path: path.display().to_string(),
        source,
    })?;
    let restricted = |metadata: &fs::Metadata| {
        metadata.is_file()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.permissions().mode() & 0o077 == 0
    };
    if !restricted(&before) {
        return Err(unsafe_file());
    }
    let nofollow = i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
        .expect("O_NOFOLLOW fits platform custom flags");
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nofollow)
        .open(path)
        .map_err(|source| ClientError::ReadRequestBody {
            path: path.display().to_string(),
            source,
        })?;
    let after = file
        .metadata()
        .map_err(|source| ClientError::ReadRequestBody {
            path: path.display().to_string(),
            source,
        })?;
    if !restricted(&after) || before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(unsafe_file());
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_protected_request_file(_path: &Path) -> Result<fs::File, ClientError> {
    Err(ClientError::ProtectedRequestFilesUnsupported)
}

pub fn merge_secret_input(candidate: Value, secret: Value) -> Result<Value, ClientError> {
    let Value::Object(mut candidate) = candidate else {
        return Err(ClientError::SecretCandidateNotObject);
    };
    let Value::Object(secret) = secret else {
        return Err(ClientError::SecretCandidateNotObject);
    };
    candidate.extend(secret);
    Ok(Value::Object(candidate))
}

pub fn read_secret_stdin(key_uses_stdin: bool, field: &str) -> Result<Value, ClientError> {
    if key_uses_stdin {
        return Err(ClientError::ConflictingStdin);
    }
    if io::stdin().is_terminal() {
        return Err(ClientError::InteractiveSecretStdin);
    }
    let bytes = read_bounded(io::stdin(), MAX_REQUEST_BYTES).map_err(|source| {
        ClientError::ReadRequestBody {
            path: "standard input".to_owned(),
            source,
        }
    })?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(ClientError::RequestBodyTooLarge {
            path: "standard input".to_owned(),
        });
    }
    let mut secret = String::from_utf8(bytes).map_err(|_| ClientError::InvalidSecretUtf8)?;
    if secret.ends_with('\n') {
        secret.pop();
        if secret.ends_with('\r') {
            secret.pop();
        }
    }
    Ok(Value::Object(
        [(field.to_owned(), Value::String(secret))]
            .into_iter()
            .collect(),
    ))
}

fn parse_response(
    mut response: Response,
    operation: &Operation,
) -> Result<OperationResponse, ClientError> {
    let status = response.status();
    let headers = response.headers().clone();
    let committed = headers
        .get("x-owlrora-command-status")
        .is_some_and(|value| value == "committed");
    if headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > MAX_RESPONSE_BYTES)
    {
        return Err(response_unavailable_error(
            operation,
            status,
            committed,
            "response exceeded the size limit",
            ClientError::ResponseTooLarge,
        ));
    }
    let bytes = read_bounded(&mut response, MAX_RESPONSE_BYTES).map_err(|error| {
        response_unavailable_error(
            operation,
            status,
            committed,
            "response body could not be read",
            ClientError::ReadResponse(error),
        )
    })?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(response_unavailable_error(
            operation,
            status,
            committed,
            "response exceeded the size limit",
            ClientError::ResponseTooLarge,
        ));
    }
    let request_id = response_request_id(&headers, &bytes);
    if !status.is_success() {
        let parsed = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
        let error = parsed.get("error").unwrap_or(&parsed);
        let code = error
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("http_error")
            .to_owned();
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("the server rejected the request")
            .to_owned();
        let request_suffix = request_id
            .as_ref()
            .map_or_else(String::new, |id| format!(" (request {id})"));
        return Err(ClientError::Api {
            status,
            code,
            message,
            request_suffix,
            request_id,
        });
    }
    let body = parse_success_body(&bytes, operation, status, committed)?;
    let etag = headers
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    Ok(OperationResponse {
        status,
        body,
        etag,
        request_id,
    })
}

fn parse_success_body(
    bytes: &[u8],
    operation: &Operation,
    status: StatusCode,
    committed: bool,
) -> Result<Value, ClientError> {
    if bytes.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(bytes).map_err(|_| {
        response_unavailable_error(
            operation,
            status,
            committed,
            "success response contained incomplete or invalid JSON",
            ClientError::InvalidSuccessResponse,
        )
    })
}

fn response_unavailable_error(
    operation: &Operation,
    status: StatusCode,
    committed: bool,
    stage: &str,
    fallback: ClientError,
) -> ClientError {
    if !status.is_success() || operation.mode != OperationMode::Command {
        return fallback;
    }
    let outcome = if committed {
        "the server reported that the command committed"
    } else {
        "the final commit outcome is unknown"
    };
    let recovery = if operation.one_time_secret_response {
        " Inspect safe metadata, disable or revoke potentially undisclosed material, then issue fresh material deliberately."
    } else {
        " Inspect the authoritative resource before deciding whether to issue a new command."
    };
    ClientError::CommandOutcomeUnknown {
        message: format!("{outcome}, but the {stage}.{recovery}"),
    }
}

fn response_request_id(headers: &HeaderMap, bytes: &[u8]) -> Option<String> {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .or_else(|| {
            serde_json::from_slice::<Value>(bytes)
                .ok()?
                .pointer("/error/request_id")?
                .as_str()
                .map(str::to_owned)
        })
}

fn read_bounded(mut reader: impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn retryable_idempotent_error(error: &ClientError) -> bool {
    match error {
        ClientError::CommandOutcomeUnknown { .. } => true,
        ClientError::Api { status, .. } => {
            matches!(status.as_u16(), 408 | 425 | 429 | 500 | 502 | 503 | 504)
        }
        _ => false,
    }
}

fn safe_transport_message(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "request timed out".to_owned()
    } else if error.is_connect() {
        "connection failed".to_owned()
    } else {
        "HTTP transport failed".to_owned()
    }
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_secret_merge_preserves_candidate_fields_and_replaces_only_its_field() {
        let merged = merge_secret_input(
            json!({"name":"credential","secret":"stale"}),
            json!({"secret":"fresh"}),
        )
        .unwrap();
        assert_eq!(merged, json!({"name":"credential","secret":"fresh"}));
        assert!(matches!(
            merge_secret_input(json!([]), json!({"secret":"fresh"})),
            Err(ClientError::SecretCandidateNotObject)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn protected_request_files_require_owner_only_regular_files() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("candidate.json");
        fs::write(&path, br#"{"secret":"protected"}"#).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let (candidate, _) = load_request_body(path.to_str().unwrap(), None, true).unwrap();
        assert_eq!(candidate, json!({"secret":"protected"}));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_request_body(path.to_str().unwrap(), None, true),
            Err(ClientError::UnsafeProtectedRequestFile { .. })
        ));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.path().join("candidate-link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(matches!(
            load_request_body(link.to_str().unwrap(), None, true),
            Err(ClientError::UnsafeProtectedRequestFile { .. })
        ));
    }

    #[test]
    fn loopback_detection_does_not_trust_suffixes() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("::1"));
        assert!(!is_loopback_host("localhost.example.com"));
    }

    #[test]
    fn candidate_envelope_requires_no_submission_time_get() {
        let value = json!({"candidate":{"status":"disabled"},"etag":"\"opaque\""});
        let candidate = value["candidate"].clone();
        assert_eq!(candidate, json!({"status":"disabled"}));
        assert_eq!(value["etag"], "\"opaque\"");
    }

    #[test]
    fn truncated_committed_one_time_response_requires_recovery() {
        let operation = crate::contract::operations()
            .iter()
            .find(|operation| operation.id == "system.management_keys.create")
            .unwrap();
        let error = parse_success_body(b"{", operation, StatusCode::OK, true).unwrap_err();
        let message = error.to_string();
        assert!(matches!(error, ClientError::CommandOutcomeUnknown { .. }));
        assert!(message.contains("reported that the command committed"));
        assert!(message.contains("disable or revoke"));
    }
}
