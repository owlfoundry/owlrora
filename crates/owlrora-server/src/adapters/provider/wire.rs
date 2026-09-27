use std::collections::{BTreeSet, HashMap};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    domain::TransportKind,
    protocols::{NativeRequest, ResponseMode},
    runtime::{EndpointSnapshot, PricingOutcome},
};

const MAX_EVENT_STREAM_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_EVENT_STREAM_HEADERS_BYTES: usize = 64 * 1024;
const MAX_SSE_EVENT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamFraming {
    Json,
    Sse,
    AwsEventStream,
    WebSocket,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsageCompleteness {
    Complete,
    Partial,
    Absent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderUsage {
    pub dimensions: HashMap<String, u64>,
    pub completeness: UsageCompleteness,
}

impl ProviderUsage {
    #[must_use]
    pub fn absent() -> Self {
        Self {
            dimensions: HashMap::new(),
            completeness: UsageCompleteness::Absent,
        }
    }

    #[must_use]
    pub fn price(&self, deployment: &crate::runtime::DeploymentSnapshot) -> Option<PricingOutcome> {
        deployment.price(&self.dimensions)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum WireError {
    #[error("endpoint cannot represent the selected transport")]
    Endpoint,
    #[error("provider response exceeded a framing bound")]
    Bound,
    #[error("provider response framing is invalid")]
    Framing,
}

#[must_use]
pub const fn response_framing(transport: TransportKind, mode: ResponseMode) -> UpstreamFraming {
    match (transport, mode) {
        (TransportKind::AnthropicMessagesBedrock, ResponseMode::Sse) => {
            UpstreamFraming::AwsEventStream
        }
        (TransportKind::OpenaiResponsesWebsocket, _) | (_, ResponseMode::WebSocket) => {
            UpstreamFraming::WebSocket
        }
        (_, ResponseMode::Sse) => UpstreamFraming::Sse,
        (_, ResponseMode::Json) => UpstreamFraming::Json,
    }
}

pub fn adapt_provider_body(
    native: &NativeRequest,
    transport: TransportKind,
    upstream_model_id: &str,
    maximum_output_units: u64,
) -> Result<Vec<u8>, WireError> {
    let mut body = native.envelope.clone();
    let object = body.as_object_mut().ok_or(WireError::Framing)?;
    match transport {
        TransportKind::AnthropicMessagesBedrock => {
            object.remove("model");
            object.remove("stream");
            object.insert(
                "anthropic_version".to_owned(),
                Value::String("bedrock-2023-05-31".to_owned()),
            );
        }
        TransportKind::AnthropicMessagesVertex => {
            object.remove("model");
            object.insert(
                "anthropic_version".to_owned(),
                Value::String("vertex-2023-10-16".to_owned()),
            );
        }
        TransportKind::GoogleGeminiGenerateContent | TransportKind::GoogleVertexGenerateContent => {
        }
        _ => {
            object.insert(
                "model".to_owned(),
                Value::String(upstream_model_id.to_owned()),
            );
        }
    }
    enforce_output_bound(native, object, maximum_output_units);
    if native.intent.response_mode == ResponseMode::Sse
        && matches!(
            transport,
            TransportKind::OpenaiChatCompletions | TransportKind::AzureOpenaiChatCompletions
        )
    {
        let options = object
            .entry("stream_options")
            .or_insert_with(|| Value::Object(Map::new()));
        let options = options.as_object_mut().ok_or(WireError::Framing)?;
        options.insert("include_usage".to_owned(), Value::Bool(true));
    }
    if transport == TransportKind::OpenaiCodexResponses {
        object.remove("max_output_tokens");
        match object.get("instructions") {
            None | Some(Value::Null) => {
                object.insert("instructions".to_owned(), Value::String(String::new()));
            }
            Some(Value::String(_)) => {}
            Some(_) => return Err(WireError::Framing),
        }
    }
    serde_json::to_vec(&body).map_err(|_| WireError::Framing)
}

fn enforce_output_bound(native: &NativeRequest, object: &mut Map<String, Value>, maximum: u64) {
    use crate::domain::IngressProtocolFamily;
    let field = match native.family {
        IngressProtocolFamily::AnthropicMessages => "max_tokens",
        IngressProtocolFamily::OpenaiChatCompletions => {
            if object.contains_key("max_completion_tokens") {
                "max_completion_tokens"
            } else {
                "max_tokens"
            }
        }
        IngressProtocolFamily::OpenaiResponses => "max_output_tokens",
        IngressProtocolFamily::GoogleGemini => {
            let generation = object
                .entry("generationConfig")
                .or_insert_with(|| Value::Object(Map::new()));
            if let Some(generation) = generation.as_object_mut() {
                let current = generation
                    .get("maxOutputTokens")
                    .and_then(Value::as_u64)
                    .unwrap_or(maximum);
                generation.insert(
                    "maxOutputTokens".to_owned(),
                    Value::from(current.min(maximum)),
                );
            }
            return;
        }
    };
    let current = object.get(field).and_then(Value::as_u64).unwrap_or(maximum);
    object.insert(field.to_owned(), Value::from(current.min(maximum)));
}

pub fn upstream_url(
    native: &NativeRequest,
    transport: TransportKind,
    upstream_model_id: &str,
    endpoint: &EndpointSnapshot,
) -> Result<url::Url, WireError> {
    let stream = native.intent.response_mode == ResponseMode::Sse;
    let mut url = endpoint.base_url.clone();
    let segments: Vec<String> = match transport {
        TransportKind::AnthropicMessagesNative => versioned_segments(&url, "v1", &["messages"]),
        TransportKind::AnthropicMessagesBedrock => vec![
            "model".to_owned(),
            upstream_model_id.to_owned(),
            if stream {
                "invoke-with-response-stream"
            } else {
                "invoke"
            }
            .to_owned(),
        ],
        TransportKind::AnthropicMessagesVertex => vec![
            "publishers".to_owned(),
            "anthropic".to_owned(),
            "models".to_owned(),
            format!(
                "{upstream_model_id}:{}",
                if stream {
                    "streamRawPredict"
                } else {
                    "rawPredict"
                }
            ),
        ],
        TransportKind::OpenaiChatCompletions => {
            versioned_segments(&url, "v1", &["chat", "completions"])
        }
        TransportKind::OpenaiResponsesHttp | TransportKind::OpenaiResponsesWebsocket => {
            versioned_segments(&url, "v1", &["responses"])
        }
        TransportKind::OpenaiCodexResponses => vec!["responses".to_owned()],
        TransportKind::AzureOpenaiChatCompletions => vec![
            "openai".to_owned(),
            "deployments".to_owned(),
            upstream_model_id.to_owned(),
            "chat".to_owned(),
            "completions".to_owned(),
        ],
        TransportKind::AzureOpenaiResponses => {
            vec!["openai".to_owned(), "responses".to_owned()]
        }
        TransportKind::GoogleGeminiGenerateContent => versioned_segments(
            &url,
            "v1beta",
            &[
                "models",
                &format!(
                    "{upstream_model_id}:{}",
                    if stream {
                        "streamGenerateContent"
                    } else {
                        "generateContent"
                    }
                ),
            ],
        ),
        TransportKind::GoogleVertexGenerateContent => vec![
            "publishers".to_owned(),
            "google".to_owned(),
            "models".to_owned(),
            format!(
                "{upstream_model_id}:{}",
                if stream {
                    "streamGenerateContent"
                } else {
                    "generateContent"
                }
            ),
        ],
    };
    append_segments(&mut url, &segments)?;
    if stream
        && matches!(
            transport,
            TransportKind::GoogleGeminiGenerateContent | TransportKind::GoogleVertexGenerateContent
        )
    {
        url.query_pairs_mut().append_pair("alt", "sse");
    }
    if matches!(
        transport,
        TransportKind::AzureOpenaiChatCompletions | TransportKind::AzureOpenaiResponses
    ) {
        let version = endpoint.api_version.as_deref().ok_or(WireError::Endpoint)?;
        url.query_pairs_mut().append_pair("api-version", version);
    }
    Ok(url)
}

fn versioned_segments(base: &url::Url, version: &str, tail: &[&str]) -> Vec<String> {
    let base_has_version = base
        .path_segments()
        .and_then(Iterator::last)
        .is_some_and(|segment| segment == version);
    let mut values = Vec::with_capacity(tail.len() + usize::from(!base_has_version));
    if !base_has_version {
        values.push(version.to_owned());
    }
    values.extend(tail.iter().map(|value| (*value).to_owned()));
    values
}

fn append_segments(url: &mut url::Url, segments: &[String]) -> Result<(), WireError> {
    let mut path = url.path_segments_mut().map_err(|_| WireError::Endpoint)?;
    path.pop_if_empty();
    for segment in segments {
        if segment.is_empty() {
            return Err(WireError::Endpoint);
        }
        path.push(segment);
    }
    Ok(())
}

#[must_use]
pub fn response_state_id(transport: TransportKind, value: &Value) -> Option<String> {
    if !matches!(
        transport,
        TransportKind::OpenaiResponsesHttp
            | TransportKind::OpenaiResponsesWebsocket
            | TransportKind::OpenaiCodexResponses
            | TransportKind::AzureOpenaiResponses
    ) {
        return None;
    }
    let candidate = if value
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind.starts_with("response."))
    {
        value.get("response").unwrap_or(value)
    } else {
        value
    };
    candidate
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 1024)
        .map(str::to_owned)
}

#[must_use]
pub fn extract_json_usage(transport: TransportKind, value: &Value) -> ProviderUsage {
    match transport {
        TransportKind::AnthropicMessagesNative
        | TransportKind::AnthropicMessagesBedrock
        | TransportKind::AnthropicMessagesVertex => anthropic_usage(value),
        TransportKind::OpenaiChatCompletions | TransportKind::AzureOpenaiChatCompletions => {
            openai_chat_usage(value)
        }
        TransportKind::OpenaiResponsesHttp
        | TransportKind::OpenaiResponsesWebsocket
        | TransportKind::OpenaiCodexResponses
        | TransportKind::AzureOpenaiResponses => openai_responses_usage(value),
        TransportKind::GoogleGeminiGenerateContent | TransportKind::GoogleVertexGenerateContent => {
            gemini_usage(value)
        }
    }
}

fn anthropic_usage(value: &Value) -> ProviderUsage {
    let usage = value.get("usage").or_else(|| {
        value
            .get("message")
            .and_then(|message| message.get("usage"))
    });
    let Some(usage) = usage else {
        return ProviderUsage::absent();
    };
    let mut dimensions = HashMap::new();
    copy_u64(usage, "input_tokens", "input_tokens", &mut dimensions);
    copy_u64(usage, "output_tokens", "output_tokens", &mut dimensions);
    copy_u64(
        usage,
        "cache_read_input_tokens",
        "cached_input_tokens",
        &mut dimensions,
    );
    copy_u64(
        usage,
        "cache_creation_input_tokens",
        "cache_creation_input_tokens",
        &mut dimensions,
    );
    ProviderUsage {
        completeness: if dimensions.contains_key("input_tokens")
            && dimensions.contains_key("output_tokens")
        {
            UsageCompleteness::Complete
        } else {
            UsageCompleteness::Partial
        },
        dimensions,
    }
}

fn openai_chat_usage(value: &Value) -> ProviderUsage {
    let Some(usage) = value.get("usage") else {
        return ProviderUsage::absent();
    };
    let mut dimensions = HashMap::new();
    copy_u64(usage, "prompt_tokens", "input_tokens", &mut dimensions);
    copy_u64(usage, "completion_tokens", "output_tokens", &mut dimensions);
    copy_nested_u64(
        usage,
        "prompt_tokens_details",
        "cached_tokens",
        "cached_input_tokens",
        &mut dimensions,
    );
    copy_nested_u64(
        usage,
        "completion_tokens_details",
        "reasoning_tokens",
        "reasoning_tokens",
        &mut dimensions,
    );
    normalize_inclusive_input(&mut dimensions);
    complete_token_usage(dimensions)
}

fn openai_responses_usage(value: &Value) -> ProviderUsage {
    let response = value.get("response").unwrap_or(value);
    let Some(usage) = response.get("usage").filter(|usage| !usage.is_null()) else {
        return ProviderUsage::absent();
    };
    let mut dimensions = HashMap::new();
    copy_u64(usage, "input_tokens", "input_tokens", &mut dimensions);
    copy_u64(usage, "output_tokens", "output_tokens", &mut dimensions);
    copy_nested_u64(
        usage,
        "input_tokens_details",
        "cached_tokens",
        "cached_input_tokens",
        &mut dimensions,
    );
    copy_nested_u64(
        usage,
        "output_tokens_details",
        "reasoning_tokens",
        "reasoning_tokens",
        &mut dimensions,
    );
    normalize_inclusive_input(&mut dimensions);
    complete_token_usage(dimensions)
}

fn gemini_usage(value: &Value) -> ProviderUsage {
    let Some(usage) = value.get("usageMetadata") else {
        return ProviderUsage::absent();
    };
    let mut dimensions = HashMap::new();
    copy_u64(usage, "promptTokenCount", "input_tokens", &mut dimensions);
    copy_u64(
        usage,
        "candidatesTokenCount",
        "output_tokens",
        &mut dimensions,
    );
    copy_u64(
        usage,
        "cachedContentTokenCount",
        "cached_input_tokens",
        &mut dimensions,
    );
    copy_u64(
        usage,
        "thoughtsTokenCount",
        "reasoning_tokens",
        &mut dimensions,
    );
    normalize_inclusive_input(&mut dimensions);
    complete_token_usage(dimensions)
}

fn normalize_inclusive_input(dimensions: &mut HashMap<String, u64>) {
    let cached = dimensions.get("cached_input_tokens").copied().unwrap_or(0);
    if let Some(input) = dimensions.get_mut("input_tokens") {
        *input = input.saturating_sub(cached);
    }
}

fn complete_token_usage(dimensions: HashMap<String, u64>) -> ProviderUsage {
    ProviderUsage {
        completeness: if dimensions.contains_key("input_tokens")
            && dimensions.contains_key("output_tokens")
        {
            UsageCompleteness::Complete
        } else {
            UsageCompleteness::Partial
        },
        dimensions,
    }
}

fn copy_u64(value: &Value, field: &str, dimension: &str, output: &mut HashMap<String, u64>) {
    if let Some(quantity) = value.get(field).and_then(Value::as_u64) {
        output.insert(dimension.to_owned(), quantity);
    }
}

fn copy_nested_u64(
    value: &Value,
    object: &str,
    field: &str,
    dimension: &str,
    output: &mut HashMap<String, u64>,
) {
    if let Some(quantity) = value
        .get(object)
        .and_then(|object| object.get(field))
        .and_then(Value::as_u64)
    {
        output.insert(dimension.to_owned(), quantity);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamTerminalOutcome {
    Complete,
    ProviderFailure,
    Incomplete,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum StreamCommitment {
    #[default]
    Pending,
    Ready,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamFailureClass {
    InvalidRequest,
    AuthOrConfiguration,
    RateLimited,
    Overloaded,
    ProviderFailure,
    Unknown,
}

#[derive(Debug, Default)]
pub struct InspectedSseBatch {
    pub bytes: Vec<u8>,
    pub values: Vec<Value>,
    pub error: Option<WireError>,
}

#[derive(Debug, Default)]
pub struct SseInspector {
    pending: Vec<u8>,
    observed_state_ids: BTreeSet<String>,
    latest_usage: Option<ProviderUsage>,
    terminal: Option<StreamTerminalOutcome>,
    commitment: StreamCommitment,
    failure_class: Option<StreamFailureClass>,
    precommit_bytes: u64,
    precommit_events: u64,
}

#[derive(Debug)]
enum SseEventData {
    Empty,
    Done,
    Json(Value),
}

impl SseInspector {
    pub fn push(
        &mut self,
        transport: TransportKind,
        bytes: &[u8],
    ) -> Result<Vec<Value>, WireError> {
        let batch = self.push_frames(transport, bytes);
        match batch.error {
            Some(error) => Err(error),
            None => Ok(batch.values),
        }
    }

    // Preserve complete native frames and semantic order independently of socket
    // chunking. On error the valid prefix remains available to an already-ready
    // stream; a later malformed frame cannot undo earlier commitment evidence.
    pub fn push_frames(&mut self, transport: TransportKind, bytes: &[u8]) -> InspectedSseBatch {
        let mut batch = InspectedSseBatch::default();
        for byte in bytes {
            if self.commitment == StreamCommitment::Pending {
                self.precommit_bytes = self.precommit_bytes.saturating_add(1);
            }
            self.pending.push(*byte);
            if self.pending.len() > MAX_SSE_EVENT_BYTES {
                batch.error = Some(WireError::Bound);
                break;
            }
            let delimiter = if self.pending.ends_with(b"\r\n\r\n") {
                4
            } else if self.pending.ends_with(b"\n\n") {
                2
            } else {
                continue;
            };
            if self.commitment == StreamCommitment::Pending {
                self.precommit_events = self.precommit_events.saturating_add(1);
            }
            let data = match parse_sse_data(&self.pending[..self.pending.len() - delimiter]) {
                Ok(data) => data,
                Err(error) => {
                    batch.error = Some(error);
                    break;
                }
            };
            if let SseEventData::Json(value) = &data
                && let Some(id) = response_state_id(transport, value)
                && !self.observed_state_ids.is_empty()
                && !self.observed_state_ids.contains(&id)
            {
                batch.error = Some(WireError::Framing);
                break;
            }
            batch.bytes.append(&mut self.pending);
            match data {
                SseEventData::Empty => {}
                SseEventData::Done => {
                    if self.commitment == StreamCommitment::Pending {
                        self.commitment = StreamCommitment::Rejected;
                    }
                    if matches!(
                        transport,
                        TransportKind::OpenaiChatCompletions
                            | TransportKind::OpenaiResponsesHttp
                            | TransportKind::OpenaiCodexResponses
                            | TransportKind::AzureOpenaiChatCompletions
                            | TransportKind::AzureOpenaiResponses
                    ) {
                        self.observe_terminal(StreamTerminalOutcome::Complete);
                    }
                }
                SseEventData::Json(value) => {
                    let terminal = stream_terminal_outcome(transport, &value);
                    if terminal == Some(StreamTerminalOutcome::ProviderFailure)
                        && self.failure_class.is_none()
                    {
                        self.failure_class = Some(classify_stream_failure(&value));
                    }
                    if self.commitment == StreamCommitment::Pending {
                        self.commitment =
                            if terminal == Some(StreamTerminalOutcome::ProviderFailure) {
                                StreamCommitment::Rejected
                            } else if stream_establishes_response(transport, &value) {
                                StreamCommitment::Ready
                            } else if terminal == Some(StreamTerminalOutcome::Complete) {
                                StreamCommitment::Rejected
                            } else {
                                StreamCommitment::Pending
                            };
                    }
                    if let Some(terminal) = terminal {
                        self.observe_terminal(terminal);
                    }
                    if let Some(id) = response_state_id(transport, &value) {
                        self.observed_state_ids.insert(id);
                    }
                    let usage = extract_json_usage(transport, &value);
                    if usage.completeness != UsageCompleteness::Absent {
                        if let Some(current) = &mut self.latest_usage {
                            current.dimensions.extend(usage.dimensions);
                            current.completeness =
                                if current.dimensions.contains_key("input_tokens")
                                    && current.dimensions.contains_key("output_tokens")
                                {
                                    UsageCompleteness::Complete
                                } else {
                                    UsageCompleteness::Partial
                                };
                        } else {
                            self.latest_usage = Some(usage);
                        }
                    }
                    batch.values.push(value);
                }
            }
        }
        batch
    }

    #[must_use]
    pub const fn commitment(&self) -> StreamCommitment {
        self.commitment
    }

    #[must_use]
    pub const fn failure_class(&self) -> Option<StreamFailureClass> {
        self.failure_class
    }

    #[must_use]
    pub const fn precommit_size(&self) -> (u64, u64) {
        (self.precommit_bytes, self.precommit_events)
    }

    #[must_use]
    pub fn state_ids(&self) -> &BTreeSet<String> {
        &self.observed_state_ids
    }

    #[must_use]
    pub fn latest_usage(&self) -> ProviderUsage {
        self.latest_usage
            .clone()
            .unwrap_or_else(ProviderUsage::absent)
    }

    #[must_use]
    pub fn terminal_outcome(&self) -> StreamTerminalOutcome {
        if self.pending.iter().any(|byte| !byte.is_ascii_whitespace()) {
            return StreamTerminalOutcome::Incomplete;
        }
        self.terminal.unwrap_or(StreamTerminalOutcome::Incomplete)
    }

    fn observe_terminal(&mut self, outcome: StreamTerminalOutcome) {
        self.terminal = match (self.terminal, outcome) {
            (Some(StreamTerminalOutcome::ProviderFailure), _)
            | (_, StreamTerminalOutcome::ProviderFailure) => {
                Some(StreamTerminalOutcome::ProviderFailure)
            }
            (_, StreamTerminalOutcome::Complete) => Some(StreamTerminalOutcome::Complete),
            (existing, StreamTerminalOutcome::Incomplete) => existing,
        };
    }
}

fn classify_stream_failure(value: &Value) -> StreamFailureClass {
    let error = value.get("error").or_else(|| {
        value
            .get("response")
            .and_then(|response| response.get("error"))
    });
    let error = error.unwrap_or(value);
    // Recognize only explicit native error evidence; unknown failures are not
    // invented overload signals and never gain same-target retry permission.
    for field in ["type", "code", "status"] {
        match error.get(field).and_then(Value::as_str) {
            Some(
                "invalid_request_error"
                | "validation_error"
                | "invalid_argument"
                | "INVALID_ARGUMENT"
                | "content_filter"
                | "content_policy_violation"
                | "safety",
            ) => return StreamFailureClass::InvalidRequest,
            Some(
                "authentication_error"
                | "permission_error"
                | "invalid_api_key"
                | "invalid_token"
                | "UNAUTHENTICATED"
                | "PERMISSION_DENIED",
            ) => return StreamFailureClass::AuthOrConfiguration,
            Some("rate_limit_error" | "rate_limit_exceeded" | "RESOURCE_EXHAUSTED") => {
                return StreamFailureClass::RateLimited;
            }
            Some("overloaded_error" | "server_overloaded" | "UNAVAILABLE") => {
                return StreamFailureClass::Overloaded;
            }
            Some("api_error" | "server_error" | "internal_server_error" | "INTERNAL") => {
                return StreamFailureClass::ProviderFailure;
            }
            _ => {}
        }
    }
    StreamFailureClass::Unknown
}

fn stream_establishes_response(transport: TransportKind, value: &Value) -> bool {
    match transport {
        TransportKind::AnthropicMessagesNative
        | TransportKind::AnthropicMessagesBedrock
        | TransportKind::AnthropicMessagesVertex => match value.get("type").and_then(Value::as_str)
        {
            Some("message_start") => value.get("message").is_some_and(Value::is_object),
            Some("content_block_start") => value.get("content_block").is_some_and(Value::is_object),
            Some("content_block_delta" | "message_delta") => {
                value.get("delta").is_some_and(Value::is_object)
            }
            _ => false,
        },
        TransportKind::OpenaiResponsesHttp
        | TransportKind::OpenaiResponsesWebsocket
        | TransportKind::OpenaiCodexResponses
        | TransportKind::AzureOpenaiResponses => match value.get("type").and_then(Value::as_str) {
            Some(
                "response.created"
                | "response.in_progress"
                | "response.completed"
                | "response.incomplete",
            ) => value.get("response").is_some_and(Value::is_object),
            Some("response.output_item.added" | "response.output_item.done") => {
                value.get("item").is_some_and(Value::is_object)
            }
            Some(kind)
                if kind.starts_with("response.") && kind.rsplit('.').next() == Some("delta") =>
            {
                value.get("delta").is_some_and(|delta| !delta.is_null())
            }
            _ => false,
        },
        TransportKind::OpenaiChatCompletions | TransportKind::AzureOpenaiChatCompletions => value
            .get("choices")
            .and_then(Value::as_array)
            .is_some_and(|choices| {
                choices.iter().any(|choice| {
                    choice.get("delta").is_some_and(Value::is_object)
                        || choice.get("finish_reason").is_some_and(Value::is_string)
                })
            }),
        TransportKind::GoogleGeminiGenerateContent | TransportKind::GoogleVertexGenerateContent => {
            value
                .get("candidates")
                .and_then(Value::as_array)
                .is_some_and(|candidates| {
                    candidates.iter().any(|candidate| {
                        candidate.get("content").is_some_and(Value::is_object)
                            || candidate.get("finishReason").is_some_and(Value::is_string)
                    })
                })
                || value
                    .get("promptFeedback")
                    .and_then(|feedback| feedback.get("blockReason"))
                    .is_some_and(Value::is_string)
        }
    }
}

fn parse_sse_data(event: &[u8]) -> Result<SseEventData, WireError> {
    let text = std::str::from_utf8(event).map_err(|_| WireError::Framing)?;
    let data = text
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim_start)
        .collect::<Vec<_>>()
        .join("\n");
    if data.is_empty() {
        return Ok(SseEventData::Empty);
    }
    if data == "[DONE]" {
        return Ok(SseEventData::Done);
    }
    serde_json::from_str(&data)
        .map(SseEventData::Json)
        .map_err(|_| WireError::Framing)
}

fn stream_terminal_outcome(
    transport: TransportKind,
    value: &Value,
) -> Option<StreamTerminalOutcome> {
    if value.get("error").is_some_and(|error| !error.is_null())
        || value.get("type").and_then(Value::as_str) == Some("error")
    {
        return Some(StreamTerminalOutcome::ProviderFailure);
    }
    match transport {
        TransportKind::AnthropicMessagesNative
        | TransportKind::AnthropicMessagesBedrock
        | TransportKind::AnthropicMessagesVertex => match value.get("type").and_then(Value::as_str)
        {
            Some("message_stop") => Some(StreamTerminalOutcome::Complete),
            _ => None,
        },
        TransportKind::OpenaiResponsesHttp
        | TransportKind::OpenaiResponsesWebsocket
        | TransportKind::OpenaiCodexResponses
        | TransportKind::AzureOpenaiResponses => match value.get("type").and_then(Value::as_str) {
            Some("response.completed" | "response.incomplete") => {
                Some(StreamTerminalOutcome::Complete)
            }
            Some("response.failed") => Some(StreamTerminalOutcome::ProviderFailure),
            _ => None,
        },
        TransportKind::GoogleGeminiGenerateContent | TransportKind::GoogleVertexGenerateContent => {
            (value
                .get("candidates")
                .and_then(Value::as_array)
                .is_some_and(|candidates| {
                    candidates.iter().any(|candidate| {
                        candidate
                            .get("finishReason")
                            .and_then(Value::as_str)
                            .is_some_and(|reason| !reason.is_empty())
                    })
                })
                || value
                    .pointer("/promptFeedback/blockReason")
                    .and_then(Value::as_str)
                    .is_some_and(|reason| !reason.is_empty()))
            .then_some(StreamTerminalOutcome::Complete)
        }
        TransportKind::OpenaiChatCompletions | TransportKind::AzureOpenaiChatCompletions => None,
    }
}

#[derive(Debug, Default)]
pub struct DecodedEventStreamBatch {
    pub payloads: Vec<Vec<u8>>,
    pub error: Option<WireError>,
}

#[derive(Debug, Default)]
pub struct AwsEventStreamDecoder {
    pending: Vec<u8>,
}

impl AwsEventStreamDecoder {
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, WireError> {
        let batch = self.push_messages(bytes);
        match batch.error {
            Some(error) => Err(error),
            None => Ok(batch.payloads),
        }
    }

    pub fn push_messages(&mut self, mut bytes: &[u8]) -> DecodedEventStreamBatch {
        let mut batch = DecodedEventStreamBatch::default();
        while !bytes.is_empty() {
            // Buffer at most one bounded message, even when the caller supplies
            // many coalesced frames in a single network chunk.
            let needed = if self.pending.len() < 12 {
                12
            } else {
                u32::from_be_bytes(self.pending[0..4].try_into().expect("four bytes")) as usize
            };
            let take = needed.saturating_sub(self.pending.len()).min(bytes.len());
            self.pending.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.pending.len() < 12 {
                continue;
            }
            let total =
                u32::from_be_bytes(self.pending[0..4].try_into().expect("four bytes")) as usize;
            let headers =
                u32::from_be_bytes(self.pending[4..8].try_into().expect("four bytes")) as usize;
            if !(16..=MAX_EVENT_STREAM_MESSAGE_BYTES).contains(&total)
                || headers > MAX_EVENT_STREAM_HEADERS_BYTES
                || 16_usize.saturating_add(headers) > total
            {
                batch.error = Some(WireError::Bound);
                break;
            }
            if self.pending.len() < total {
                continue;
            }
            match decode_event_payload(&self.pending, headers) {
                Ok(payload) => batch.payloads.push(payload),
                Err(error) => {
                    batch.error = Some(error);
                    break;
                }
            }
            self.pending.clear();
        }
        batch
    }
}

fn decode_event_payload(message: &[u8], headers: usize) -> Result<Vec<u8>, WireError> {
    validate_crc(message)?;
    let header_end = 12 + headers;
    validate_event_headers(&message[12..header_end])?;
    let wrapper: Value = serde_json::from_slice(&message[header_end..message.len() - 4])
        .map_err(|_| WireError::Framing)?;
    let encoded = wrapper
        .get("bytes")
        .and_then(Value::as_str)
        .ok_or(WireError::Framing)?;
    let decoded = STANDARD.decode(encoded).map_err(|_| WireError::Framing)?;
    if decoded.len() > MAX_SSE_EVENT_BYTES {
        return Err(WireError::Bound);
    }
    Ok(decoded)
}

fn validate_crc(message: &[u8]) -> Result<(), WireError> {
    let expected_prelude = u32::from_be_bytes(message[8..12].try_into().expect("four bytes"));
    if crc32fast::hash(&message[..8]) != expected_prelude {
        return Err(WireError::Framing);
    }
    let expected_message =
        u32::from_be_bytes(message[message.len() - 4..].try_into().expect("four bytes"));
    if crc32fast::hash(&message[..message.len() - 4]) != expected_message {
        return Err(WireError::Framing);
    }
    Ok(())
}

fn validate_event_headers(mut bytes: &[u8]) -> Result<(), WireError> {
    let mut message_type = None;
    let mut event_type = None;
    while !bytes.is_empty() {
        let name_length = usize::from(*bytes.first().ok_or(WireError::Framing)?);
        bytes = bytes.get(1..).ok_or(WireError::Framing)?;
        let name = bytes.get(..name_length).ok_or(WireError::Framing)?;
        bytes = bytes.get(name_length..).ok_or(WireError::Framing)?;
        if bytes.first().copied() != Some(7) {
            return Err(WireError::Framing);
        }
        bytes = bytes.get(1..).ok_or(WireError::Framing)?;
        let length_bytes: [u8; 2] = bytes
            .get(..2)
            .ok_or(WireError::Framing)?
            .try_into()
            .map_err(|_| WireError::Framing)?;
        let length = usize::from(u16::from_be_bytes(length_bytes));
        bytes = bytes.get(2..).ok_or(WireError::Framing)?;
        let value = bytes.get(..length).ok_or(WireError::Framing)?;
        bytes = bytes.get(length..).ok_or(WireError::Framing)?;
        match name {
            b":message-type" => message_type = Some(value),
            b":event-type" => event_type = Some(value),
            _ => {}
        }
    }
    if message_type != Some(b"event".as_slice()) || event_type != Some(b"chunk".as_slice()) {
        return Err(WireError::Framing);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_all_supported_usage_shapes() {
        let anthropic = serde_json::json!({"usage":{"input_tokens":2,"output_tokens":3,"cache_read_input_tokens":1}});
        let usage = extract_json_usage(TransportKind::AnthropicMessagesNative, &anthropic);
        assert_eq!(usage.completeness, UsageCompleteness::Complete);
        assert_eq!(usage.dimensions["cached_input_tokens"], 1);

        let responses = serde_json::json!({"type":"response.completed","response":{"usage":{"input_tokens":5,"output_tokens":7,"input_tokens_details":{"cached_tokens":2},"output_tokens_details":{"reasoning_tokens":3}}}});
        let usage = extract_json_usage(TransportKind::OpenaiResponsesHttp, &responses);
        assert_eq!(usage.dimensions["reasoning_tokens"], 3);

        let gemini = serde_json::json!({"usageMetadata":{"promptTokenCount":11,"candidatesTokenCount":13,"thoughtsTokenCount":4}});
        let usage = extract_json_usage(TransportKind::GoogleVertexGenerateContent, &gemini);
        assert_eq!(usage.dimensions["output_tokens"], 13);
    }

    #[test]
    fn gemini_blocked_prompt_is_a_complete_native_response() {
        for transport in [
            TransportKind::GoogleGeminiGenerateContent,
            TransportKind::GoogleVertexGenerateContent,
        ] {
            let mut inspector = SseInspector::default();
            inspector
                .push(
                    transport,
                    b"data: {\"promptFeedback\":{\"blockReason\":\"SAFETY\"}}\n\n",
                )
                .unwrap();
            assert_eq!(inspector.commitment(), StreamCommitment::Ready);
            assert_eq!(
                inspector.terminal_outcome(),
                StreamTerminalOutcome::Complete
            );
        }
    }

    #[test]
    fn sse_inspector_handles_split_events_and_cumulative_usage() {
        let event = b"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_fixture\",\"usage\":null}}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_fixture\",\"usage\":{\"input_tokens\":2,\"output_tokens\":3}}}\n\n";
        let mut inspector = SseInspector::default();
        inspector
            .push(TransportKind::OpenaiResponsesHttp, &event[..37])
            .unwrap();
        inspector
            .push(TransportKind::OpenaiResponsesHttp, &event[37..])
            .unwrap();
        assert!(inspector.state_ids().contains("resp_fixture"));
        assert_eq!(inspector.latest_usage().dimensions["output_tokens"], 3);
        assert_eq!(
            inspector.terminal_outcome(),
            StreamTerminalOutcome::Complete
        );
    }

    #[test]
    fn sse_commitment_and_prefix_bounds_are_independent_of_chunking() {
        let prefix = b": keepalive\r\n\r\ndata: {\"type\":\"ping\"}\n\n";
        let ready = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_test\"}}\n\n";
        let tail = b"event: message_stop\r\ndata: {\"type\":\"message_stop\"}\r\n\r\n";
        let input = [prefix.as_slice(), ready.as_slice(), tail.as_slice()].concat();
        for chunk_size in 1..=input.len() {
            let mut inspector = SseInspector::default();
            let mut forwarded = Vec::new();
            for chunk in input.chunks(chunk_size) {
                let batch = inspector.push_frames(TransportKind::AnthropicMessagesNative, chunk);
                assert!(batch.error.is_none());
                forwarded.extend(batch.bytes);
            }
            assert_eq!(forwarded, input);
            assert_eq!(inspector.commitment(), StreamCommitment::Ready);
            assert_eq!(
                inspector.precommit_size(),
                ((prefix.len() + ready.len()) as u64, 3)
            );
            assert_eq!(
                inspector.terminal_outcome(),
                StreamTerminalOutcome::Complete
            );
        }
        let failure = b": keepalive\n\ndata: {\"type\":\"ping\"}\n\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\n";
        for chunk_size in 1..=failure.len() {
            let mut inspector = SseInspector::default();
            for chunk in failure.chunks(chunk_size) {
                inspector
                    .push(TransportKind::AnthropicMessagesNative, chunk)
                    .unwrap();
                assert_ne!(inspector.commitment(), StreamCommitment::Ready);
            }
            assert_eq!(inspector.commitment(), StreamCommitment::Rejected);
        }
    }

    #[test]
    fn sse_holds_partial_frames_and_does_not_retract_valid_prefix_on_error() {
        let mut inspector = SseInspector::default();
        let prefix = b"data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_test\"}}";
        assert!(
            inspector
                .push_frames(TransportKind::OpenaiResponsesHttp, prefix)
                .bytes
                .is_empty()
        );
        assert!(inspector.state_ids().is_empty());
        assert_eq!(inspector.commitment(), StreamCommitment::Pending);
        let batch =
            inspector.push_frames(TransportKind::OpenaiResponsesHttp, b"\n\ndata: invalid\n\n");
        assert!(batch.error.is_some());
        assert_eq!(batch.bytes, [prefix.as_slice(), b"\n\n"].concat());
        assert_eq!(inspector.commitment(), StreamCommitment::Ready);
        assert!(inspector.state_ids().contains("resp_test"));
    }

    #[test]
    fn sse_event_bound_does_not_limit_coalesced_network_chunks() {
        let input = b": pulse\n\n".repeat(MAX_SSE_EVENT_BYTES / 8 + 1);
        let mut inspector = SseInspector::default();
        let batch = inspector.push_frames(TransportKind::AnthropicMessagesNative, &input);
        assert!(batch.error.is_none());
        assert_eq!(batch.bytes, input);
        assert_eq!(inspector.commitment(), StreamCommitment::Pending);
        assert!(
            inspector
                .push(
                    TransportKind::AnthropicMessagesNative,
                    &vec![b'x'; MAX_SSE_EVENT_BYTES + 1]
                )
                .is_err()
        );
    }

    #[test]
    fn sse_clean_eof_requires_protocol_terminal_evidence() {
        let mut incomplete = SseInspector::default();
        incomplete
            .push(
                TransportKind::OpenaiResponsesHttp,
                b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n",
            )
            .unwrap();
        assert_eq!(
            incomplete.terminal_outcome(),
            StreamTerminalOutcome::Incomplete
        );

        let mut failed = SseInspector::default();
        failed
            .push(
                TransportKind::AnthropicMessagesNative,
                b"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\n",
            )
            .unwrap();
        assert_eq!(
            failed.terminal_outcome(),
            StreamTerminalOutcome::ProviderFailure
        );
    }
}
