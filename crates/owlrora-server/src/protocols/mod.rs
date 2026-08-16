use std::collections::BTreeSet;

use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Map, Value, json};

use crate::domain::{
    IngressProtocolFamily, LlmFeatureCapability, LlmScope, LlmScopeSet, TransportKind,
};

const MAX_JSON_DEPTH: usize = 128;
const MAX_JSON_NODES: usize = 100_000;
const ANTHROPIC_VERSION: &str = "2023-06-01";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseMode {
    Json,
    Sse,
    WebSocket,
}

#[derive(Clone, Debug)]
pub struct LlmIntent {
    pub model_key: String,
    pub response_mode: ResponseMode,
    pub required_scopes: LlmScopeSet,
    pub required_capabilities: BTreeSet<LlmFeatureCapability>,
    pub requested_output_bound: Option<u64>,
    pub continuation_reference: Option<String>,
    pub replay_safe: bool,
}

#[derive(Clone, Debug)]
pub struct NativeRequest {
    pub family: IngressProtocolFamily,
    pub original_body: Bytes,
    pub envelope: Value,
    pub intent: LlmIntent,
}

#[derive(Clone, Debug)]
pub enum ResponsesWebSocketClientEvent {
    Create(NativeRequest),
    Cancel {
        original_body: Bytes,
        response_id: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolErrorKind {
    Authentication,
    ConflictingAuthentication,
    Forbidden,
    InvalidRequest,
    RequestTooLarge,
    UnsupportedCapability,
    RouteUnavailable,
    StateOriginUnavailable,
    RateLimited,
    BudgetDenied,
    Overloaded,
    UpstreamUnavailable,
    DeadlineExceeded,
    Internal,
}

#[derive(Clone, Debug)]
pub struct ProtocolError {
    pub family: IngressProtocolFamily,
    pub kind: ProtocolErrorKind,
    pub request_id: String,
    pub message: &'static str,
}

impl ProtocolError {
    #[must_use]
    pub fn new(
        family: IngressProtocolFamily,
        kind: ProtocolErrorKind,
        request_id: impl Into<String>,
        message: &'static str,
    ) -> Self {
        Self {
            family,
            kind,
            request_id: request_id.into(),
            message,
        }
    }

    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self.kind {
            ProtocolErrorKind::Authentication | ProtocolErrorKind::ConflictingAuthentication => {
                StatusCode::UNAUTHORIZED
            }
            ProtocolErrorKind::Forbidden => StatusCode::FORBIDDEN,
            ProtocolErrorKind::InvalidRequest => StatusCode::BAD_REQUEST,
            ProtocolErrorKind::RequestTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ProtocolErrorKind::UnsupportedCapability => StatusCode::UNPROCESSABLE_ENTITY,
            ProtocolErrorKind::StateOriginUnavailable | ProtocolErrorKind::RouteUnavailable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            ProtocolErrorKind::RateLimited | ProtocolErrorKind::BudgetDenied => {
                StatusCode::TOO_MANY_REQUESTS
            }
            ProtocolErrorKind::Overloaded
            | ProtocolErrorKind::UpstreamUnavailable
            | ProtocolErrorKind::Internal => StatusCode::SERVICE_UNAVAILABLE,
            ProtocolErrorKind::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
        }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self.kind {
            ProtocolErrorKind::Authentication => "invalid_api_key",
            ProtocolErrorKind::ConflictingAuthentication => "conflicting_credentials",
            ProtocolErrorKind::Forbidden => "forbidden",
            ProtocolErrorKind::InvalidRequest => "invalid_request",
            ProtocolErrorKind::RequestTooLarge => "request_too_large",
            ProtocolErrorKind::UnsupportedCapability => "unsupported_capability",
            ProtocolErrorKind::RouteUnavailable => "route_unavailable",
            ProtocolErrorKind::StateOriginUnavailable => "state_origin_unavailable",
            ProtocolErrorKind::RateLimited => "rate_limit_exceeded",
            ProtocolErrorKind::BudgetDenied => "budget_exceeded",
            ProtocolErrorKind::Overloaded => "gateway_overloaded",
            ProtocolErrorKind::UpstreamUnavailable => "upstream_unavailable",
            ProtocolErrorKind::DeadlineExceeded => "deadline_exceeded",
            ProtocolErrorKind::Internal => "internal_error",
        }
    }
}

impl IntoResponse for ProtocolError {
    fn into_response(self) -> Response {
        let status = self.status();
        let code = self.code();
        let body = match self.family {
            IngressProtocolFamily::AnthropicMessages => json!({
                "type":"error",
                "error":{"type":code,"message":self.message},
                "request_id":self.request_id,
            }),
            IngressProtocolFamily::OpenaiChatCompletions
            | IngressProtocolFamily::OpenaiResponses => json!({
                "error":{
                    "message":self.message,
                    "type":code,
                    "param":null,
                    "code":code,
                },
                "request_id":self.request_id,
            }),
            IngressProtocolFamily::GoogleGemini => json!({
                "error":{
                    "code":status.as_u16(),
                    "message":self.message,
                    "status":gemini_status(status),
                    "details":[],
                },
                "request_id":self.request_id,
            }),
        };
        (status, axum::Json(body)).into_response()
    }
}

pub fn parse_anthropic(
    headers: &HeaderMap,
    body: Bytes,
    request_id: &str,
) -> Result<NativeRequest, ProtocolError> {
    let family = IngressProtocolFamily::AnthropicMessages;
    let versions = headers.get_all("anthropic-version");
    let mut versions = versions.iter();
    let version = versions
        .next()
        .and_then(|value| value.to_str().ok())
        .filter(|value| *value == ANTHROPIC_VERSION);
    if version.is_none() || versions.next().is_some() {
        return Err(invalid(
            family,
            request_id,
            "anthropic-version must be exactly 2023-06-01",
        ));
    }
    parse_json_request(family, body, request_id, None, None)
}

pub fn parse_openai_chat(body: Bytes, request_id: &str) -> Result<NativeRequest, ProtocolError> {
    parse_json_request(
        IngressProtocolFamily::OpenaiChatCompletions,
        body,
        request_id,
        None,
        None,
    )
}

pub fn parse_openai_responses(
    body: Bytes,
    request_id: &str,
) -> Result<NativeRequest, ProtocolError> {
    parse_json_request(
        IngressProtocolFamily::OpenaiResponses,
        body,
        request_id,
        None,
        None,
    )
}

pub fn parse_openai_responses_websocket_event(
    body: Bytes,
    request_id: &str,
) -> Result<ResponsesWebSocketClientEvent, ProtocolError> {
    let family = IngressProtocolFamily::OpenaiResponses;
    if body.is_empty() {
        return Err(invalid(
            family,
            request_id,
            "WebSocket event must not be empty",
        ));
    }
    let envelope: Value = serde_json::from_slice(&body)
        .map_err(|_| invalid(family, request_id, "WebSocket event must be valid JSON"))?;
    validate_json_complexity(&envelope).map_err(|message| invalid(family, request_id, message))?;
    let object = envelope
        .as_object()
        .ok_or_else(|| invalid(family, request_id, "WebSocket event must be a JSON object"))?;
    let event_type = required_bounded_string(object, "type", 128)
        .map_err(|_| invalid(family, request_id, "WebSocket event type is required"))?;
    match event_type {
        "response.create" => {
            if object.contains_key("response") {
                return Err(invalid(
                    family,
                    request_id,
                    "response.create fields must be top-level",
                ));
            }
            if object.contains_key("stream") || object.contains_key("background") {
                return Err(invalid(
                    family,
                    request_id,
                    "response.create does not accept stream or background",
                ));
            }
            let mut native = parse_json_request(family, body, request_id, None, Some(false))?;
            native.intent.response_mode = ResponseMode::WebSocket;
            native
                .intent
                .required_capabilities
                .insert(LlmFeatureCapability::Streaming);
            native.intent.required_scopes =
                required_scopes(true, &native.intent.required_capabilities);
            Ok(ResponsesWebSocketClientEvent::Create(native))
        }
        "response.cancel" => {
            let response_id = optional_bounded_string(object, "response_id", 1024)
                .map_err(|message| invalid(family, request_id, message))?
                .map(str::to_owned);
            Ok(ResponsesWebSocketClientEvent::Cancel {
                original_body: body,
                response_id,
            })
        }
        _ => Err(invalid(
            family,
            request_id,
            "unsupported Responses WebSocket client event",
        )),
    }
}

pub fn parse_gemini(
    model_key: &str,
    streaming: bool,
    body: Bytes,
    request_id: &str,
) -> Result<NativeRequest, ProtocolError> {
    validate_model_key(model_key)
        .map_err(|message| invalid(IngressProtocolFamily::GoogleGemini, request_id, message))?;
    parse_json_request(
        IngressProtocolFamily::GoogleGemini,
        body,
        request_id,
        Some(model_key),
        Some(streaming),
    )
}

fn parse_json_request(
    family: IngressProtocolFamily,
    body: Bytes,
    request_id: &str,
    path_model: Option<&str>,
    path_streaming: Option<bool>,
) -> Result<NativeRequest, ProtocolError> {
    if body.is_empty() {
        return Err(invalid(
            family,
            request_id,
            "request body must not be empty",
        ));
    }
    let envelope: Value = serde_json::from_slice(&body)
        .map_err(|_| invalid(family, request_id, "request body must be valid JSON"))?;
    let object = envelope
        .as_object()
        .ok_or_else(|| invalid(family, request_id, "request body must be a JSON object"))?;
    validate_json_complexity(&envelope).map_err(|message| invalid(family, request_id, message))?;

    let model_key = match path_model {
        Some(model) => model.to_owned(),
        None => required_bounded_string(object, "model", 512)
            .map_err(|message| invalid(family, request_id, message))?
            .to_owned(),
    };
    validate_model_key(&model_key).map_err(|message| invalid(family, request_id, message))?;

    let streaming = match path_streaming {
        Some(value) => value,
        None => optional_bool(object, "stream")
            .map_err(|message| invalid(family, request_id, message))?
            .unwrap_or(false),
    };
    let response_mode = if streaming {
        ResponseMode::Sse
    } else {
        ResponseMode::Json
    };

    let mut required_capabilities = collect_capabilities(family, object);
    if streaming {
        required_capabilities.insert(LlmFeatureCapability::Streaming);
    }
    let requested_output_bound =
        output_bound(family, object).map_err(|message| invalid(family, request_id, message))?;
    let continuation_reference = if family == IngressProtocolFamily::OpenaiResponses {
        optional_nullable_bounded_string(object, "previous_response_id", 4096)
            .map_err(|message| invalid(family, request_id, message))?
            .map(str::to_owned)
    } else {
        None
    };
    let required_scopes = required_scopes(streaming, &required_capabilities);
    let replay_safe = continuation_reference.is_none();

    Ok(NativeRequest {
        family,
        original_body: body,
        envelope,
        intent: LlmIntent {
            model_key,
            response_mode,
            required_scopes,
            required_capabilities,
            requested_output_bound,
            continuation_reference,
            replay_safe,
        },
    })
}

pub fn adapt_body(
    request: &NativeRequest,
    transport: TransportKind,
    upstream_model_id: &str,
    maximum_output_units: u64,
) -> Result<Vec<u8>, ProtocolError> {
    let mut body = request.envelope.clone();
    let object = body
        .as_object_mut()
        .expect("native request parsing always produces an object");
    match request.family {
        IngressProtocolFamily::AnthropicMessages
        | IngressProtocolFamily::OpenaiChatCompletions
        | IngressProtocolFamily::OpenaiResponses => {
            object.insert(
                "model".to_owned(),
                Value::String(upstream_model_id.to_owned()),
            );
        }
        IngressProtocolFamily::GoogleGemini => {}
    }
    enforce_output_bound(request.family, object, maximum_output_units);
    if transport == TransportKind::OpenaiCodexResponses {
        object.remove("max_output_tokens");
        match object.get("instructions") {
            None | Some(Value::Null) => {
                object.insert("instructions".to_owned(), Value::String(String::new()));
            }
            Some(Value::String(_)) => {}
            Some(_) => {
                return Err(ProtocolError::new(
                    request.family,
                    ProtocolErrorKind::InvalidRequest,
                    "unknown",
                    "instructions must be a string for the selected transport",
                ));
            }
        }
    }
    serde_json::to_vec(&body).map_err(|_| {
        ProtocolError::new(
            request.family,
            ProtocolErrorKind::Internal,
            "unknown",
            "request could not be prepared",
        )
    })
}

fn enforce_output_bound(
    family: IngressProtocolFamily,
    object: &mut Map<String, Value>,
    maximum: u64,
) {
    let field = match family {
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

fn output_bound(
    family: IngressProtocolFamily,
    object: &Map<String, Value>,
) -> Result<Option<u64>, &'static str> {
    let values: &[&str] = match family {
        IngressProtocolFamily::AnthropicMessages => &["max_tokens"],
        IngressProtocolFamily::OpenaiChatCompletions => &["max_completion_tokens", "max_tokens"],
        IngressProtocolFamily::OpenaiResponses => &["max_output_tokens"],
        IngressProtocolFamily::GoogleGemini => {
            return object
                .get("generationConfig")
                .map(|value| {
                    value
                        .as_object()
                        .ok_or("generationConfig must be an object")?
                        .get("maxOutputTokens")
                        .map(parse_positive_integer)
                        .transpose()
                })
                .transpose()
                .map(Option::flatten);
        }
    };
    let mut result = None;
    for name in values {
        if let Some(value) = object.get(*name) {
            let value = parse_positive_integer(value)?;
            result = Some(result.map_or(value, |current: u64| current.min(value)));
        }
    }
    Ok(result)
}

fn parse_positive_integer(value: &Value) -> Result<u64, &'static str> {
    value
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or("output token bound must be a positive integer")
}

fn required_scopes(streaming: bool, capabilities: &BTreeSet<LlmFeatureCapability>) -> LlmScopeSet {
    let mut scopes = BTreeSet::from([LlmScope::Invoke]);
    if streaming {
        scopes.insert(LlmScope::Stream);
    }
    if capabilities.contains(&LlmFeatureCapability::Tools)
        || capabilities.contains(&LlmFeatureCapability::ParallelTools)
    {
        scopes.insert(LlmScope::Tools);
    }
    if capabilities.iter().any(|capability| {
        matches!(
            capability,
            LlmFeatureCapability::ImageInput
                | LlmFeatureCapability::AudioInput
                | LlmFeatureCapability::DocumentInput
        )
    }) {
        scopes.insert(LlmScope::MultimodalInput);
    }
    if capabilities.contains(&LlmFeatureCapability::StructuredOutput)
        || capabilities.contains(&LlmFeatureCapability::JsonSchema)
    {
        scopes.insert(LlmScope::StructuredOutput);
    }
    LlmScopeSet::new(scopes).expect("llm:invoke is always included")
}

fn collect_capabilities(
    family: IngressProtocolFamily,
    object: &Map<String, Value>,
) -> BTreeSet<LlmFeatureCapability> {
    let mut capabilities = BTreeSet::new();
    match family {
        IngressProtocolFamily::AnthropicMessages => {
            insert_if_present(
                object,
                &["tools", "tool_choice"],
                &mut capabilities,
                LlmFeatureCapability::Tools,
            );
            insert_if_present(
                object,
                &["system"],
                &mut capabilities,
                LlmFeatureCapability::SystemInstructions,
            );
            insert_if_present(
                object,
                &["thinking"],
                &mut capabilities,
                LlmFeatureCapability::ReasoningControls,
            );
            scan_anthropic_content(object.get("system"), &mut capabilities);
            if array_objects(object.get("tools")).any(|tool| tool.contains_key("cache_control")) {
                capabilities.insert(LlmFeatureCapability::PromptCaching);
            }
            for message in array_objects(object.get("messages")) {
                scan_anthropic_content(message.get("content"), &mut capabilities);
            }
        }
        IngressProtocolFamily::OpenaiChatCompletions => {
            insert_if_present(
                object,
                &["tools", "tool_choice"],
                &mut capabilities,
                LlmFeatureCapability::Tools,
            );
            insert_if_present(
                object,
                &["parallel_tool_calls"],
                &mut capabilities,
                LlmFeatureCapability::ParallelTools,
            );
            insert_if_present(
                object,
                &["reasoning_effort"],
                &mut capabilities,
                LlmFeatureCapability::ReasoningControls,
            );
            insert_if_present(
                object,
                &["prompt_cache_key"],
                &mut capabilities,
                LlmFeatureCapability::PromptCaching,
            );
            scan_structured_output(object.get("response_format"), &mut capabilities);
            for message in array_objects(object.get("messages")) {
                match message.get("role").and_then(Value::as_str) {
                    Some("system") => {
                        capabilities.insert(LlmFeatureCapability::SystemInstructions);
                    }
                    Some("developer") => {
                        capabilities.insert(LlmFeatureCapability::DeveloperInstructions);
                    }
                    _ => {}
                }
                if message.contains_key("reasoning_content") {
                    capabilities.insert(LlmFeatureCapability::OpaqueReasoningState);
                }
                scan_openai_content(message.get("content"), &mut capabilities);
            }
        }
        IngressProtocolFamily::OpenaiResponses => {
            insert_if_present(
                object,
                &["tools", "tool_choice"],
                &mut capabilities,
                LlmFeatureCapability::Tools,
            );
            insert_if_present(
                object,
                &["parallel_tool_calls"],
                &mut capabilities,
                LlmFeatureCapability::ParallelTools,
            );
            insert_if_present(
                object,
                &["instructions"],
                &mut capabilities,
                LlmFeatureCapability::SystemInstructions,
            );
            insert_if_present(
                object,
                &["reasoning"],
                &mut capabilities,
                LlmFeatureCapability::ReasoningControls,
            );
            insert_if_present(
                object,
                &["prompt_cache_key"],
                &mut capabilities,
                LlmFeatureCapability::PromptCaching,
            );
            if let Some(format) = object
                .get("text")
                .and_then(Value::as_object)
                .and_then(|text| text.get("format"))
            {
                scan_structured_output(Some(format), &mut capabilities);
            }
            for item in array_objects(object.get("input")) {
                match item.get("role").and_then(Value::as_str) {
                    Some("system") => {
                        capabilities.insert(LlmFeatureCapability::SystemInstructions);
                    }
                    Some("developer") => {
                        capabilities.insert(LlmFeatureCapability::DeveloperInstructions);
                    }
                    _ => {}
                }
                if item.get("type").and_then(Value::as_str) == Some("reasoning")
                    && item.contains_key("encrypted_content")
                {
                    capabilities.insert(LlmFeatureCapability::OpaqueReasoningState);
                }
                scan_openai_content(item.get("content"), &mut capabilities);
            }
        }
        IngressProtocolFamily::GoogleGemini => {
            insert_if_present(
                object,
                &["tools", "toolConfig"],
                &mut capabilities,
                LlmFeatureCapability::Tools,
            );
            insert_if_present(
                object,
                &["systemInstruction"],
                &mut capabilities,
                LlmFeatureCapability::SystemInstructions,
            );
            insert_if_present(
                object,
                &["cachedContent"],
                &mut capabilities,
                LlmFeatureCapability::PromptCaching,
            );
            if let Some(generation) = object.get("generationConfig").and_then(Value::as_object) {
                if generation.contains_key("responseMimeType") {
                    capabilities.insert(LlmFeatureCapability::StructuredOutput);
                }
                if generation.contains_key("responseSchema") {
                    capabilities.insert(LlmFeatureCapability::StructuredOutput);
                    capabilities.insert(LlmFeatureCapability::JsonSchema);
                }
                if generation.contains_key("thinkingConfig") {
                    capabilities.insert(LlmFeatureCapability::ReasoningControls);
                }
            }
            for content in array_objects(object.get("contents")) {
                for part in array_objects(content.get("parts")) {
                    scan_gemini_part(part, &mut capabilities);
                }
            }
        }
    }
    capabilities
}

fn insert_if_present(
    object: &Map<String, Value>,
    fields: &[&str],
    capabilities: &mut BTreeSet<LlmFeatureCapability>,
    capability: LlmFeatureCapability,
) {
    if fields.iter().any(|field| object.contains_key(*field)) {
        capabilities.insert(capability);
    }
}

fn array_objects(value: Option<&Value>) -> impl Iterator<Item = &Map<String, Value>> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
}

fn scan_structured_output(
    value: Option<&Value>,
    capabilities: &mut BTreeSet<LlmFeatureCapability>,
) {
    let Some(object) = value.and_then(Value::as_object) else {
        return;
    };
    if let Some(kind) = object.get("type").and_then(Value::as_str)
        && matches!(kind, "json_object" | "json_schema")
    {
        capabilities.insert(LlmFeatureCapability::StructuredOutput);
        if kind == "json_schema" {
            capabilities.insert(LlmFeatureCapability::JsonSchema);
        }
    }
}

fn scan_anthropic_content(
    value: Option<&Value>,
    capabilities: &mut BTreeSet<LlmFeatureCapability>,
) {
    for block in array_objects(value) {
        if block.contains_key("cache_control") {
            capabilities.insert(LlmFeatureCapability::PromptCaching);
        }
        match block.get("type").and_then(Value::as_str) {
            Some("image") => {
                capabilities.insert(LlmFeatureCapability::ImageInput);
            }
            Some("document") => {
                capabilities.insert(LlmFeatureCapability::DocumentInput);
            }
            Some("thinking" | "redacted_thinking") => {
                capabilities.insert(LlmFeatureCapability::OpaqueReasoningState);
            }
            _ => {}
        }
    }
}

fn scan_openai_content(value: Option<&Value>, capabilities: &mut BTreeSet<LlmFeatureCapability>) {
    for block in array_objects(value) {
        match block.get("type").and_then(Value::as_str) {
            Some("image_url" | "input_image") => {
                capabilities.insert(LlmFeatureCapability::ImageInput);
            }
            Some("input_audio" | "audio") => {
                capabilities.insert(LlmFeatureCapability::AudioInput);
            }
            Some("input_file" | "file") => {
                capabilities.insert(LlmFeatureCapability::DocumentInput);
            }
            _ => {}
        }
    }
}

fn scan_gemini_part(part: &Map<String, Value>, capabilities: &mut BTreeSet<LlmFeatureCapability>) {
    if part.contains_key("thoughtSignature") {
        capabilities.insert(LlmFeatureCapability::OpaqueReasoningState);
    }
    let media = part
        .get("inlineData")
        .or_else(|| part.get("fileData"))
        .and_then(Value::as_object);
    let Some(media) = media else {
        return;
    };
    let mime = media
        .get("mimeType")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if mime.starts_with("image/") {
        capabilities.insert(LlmFeatureCapability::ImageInput);
    } else if mime.starts_with("audio/") {
        capabilities.insert(LlmFeatureCapability::AudioInput);
    } else {
        capabilities.insert(LlmFeatureCapability::DocumentInput);
    }
}

fn validate_json_complexity(value: &Value) -> Result<(), &'static str> {
    let mut stack = vec![(value, 0_usize)];
    let mut nodes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        nodes = nodes.saturating_add(1);
        if nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH {
            return Err("request JSON is too complex");
        }
        match value {
            Value::Array(values) => {
                stack.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(object) => {
                stack.extend(object.values().map(|value| (value, depth + 1)));
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_model_key(value: &str) -> Result<(), &'static str> {
    if value.is_empty()
        || value.len() > 512
        || value.chars().any(char::is_control)
        || value.starts_with('/')
        || value.contains("..")
    {
        return Err("model must be a bounded route key");
    }
    Ok(())
}

fn required_bounded_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    maximum: usize,
) -> Result<&'a str, &'static str> {
    optional_bounded_string(object, field, maximum)?.ok_or("required string field is missing")
}

fn optional_bounded_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    maximum: usize,
) -> Result<Option<&'a str>, &'static str> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .filter(|value| !value.is_empty() && value.len() <= maximum)
        .map(Some)
        .ok_or("string field is invalid")
}

fn optional_nullable_bounded_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    maximum: usize,
) -> Result<Option<&'a str>, &'static str> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .filter(|value| !value.is_empty() && value.len() <= maximum)
            .map(Some)
            .ok_or("string field is invalid"),
    }
}

fn optional_bool(object: &Map<String, Value>, field: &str) -> Result<Option<bool>, &'static str> {
    object
        .get(field)
        .map(|value| value.as_bool().ok_or("boolean field is invalid"))
        .transpose()
}

fn invalid(
    family: IngressProtocolFamily,
    request_id: &str,
    message: &'static str,
) -> ProtocolError {
    ProtocolError::new(
        family,
        ProtocolErrorKind::InvalidRequest,
        request_id,
        message,
    )
}

const fn gemini_status(status: StatusCode) -> &'static str {
    match status.as_u16() {
        400 => "INVALID_ARGUMENT",
        401 => "UNAUTHENTICATED",
        403 => "PERMISSION_DENIED",
        413 => "RESOURCE_EXHAUSTED",
        422 => "FAILED_PRECONDITION",
        429 => "RESOURCE_EXHAUSTED",
        504 => "DEADLINE_EXCEEDED",
        _ => "UNAVAILABLE",
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn extracts_protocol_capabilities_without_normalizing_payload() {
        let body = Bytes::from_static(
            br#"{"model":"route-a","stream":true,"max_tokens":20,"tools":[{"name":"x"}],"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.invalid/x"}}]}]}"#,
        );
        let request = parse_openai_chat(body.clone(), "r").unwrap();
        assert_eq!(request.original_body, body);
        assert_eq!(request.intent.model_key, "route-a");
        assert_eq!(request.intent.response_mode, ResponseMode::Sse);
        assert!(
            request
                .intent
                .required_capabilities
                .contains(&LlmFeatureCapability::Tools)
        );
        assert!(request.intent.required_scopes.contains(LlmScope::Stream));
        assert!(
            request
                .intent
                .required_scopes
                .contains(LlmScope::MultimodalInput)
        );
    }

    #[test]
    fn capability_extraction_never_scans_arbitrary_tool_or_prompt_payloads() {
        let chat = parse_openai_chat(
            Bytes::from_static(
                br#"{"model":"route","messages":[{"role":"tool","content":"ok","business":{"tools":true,"type":"image"}}]}"#,
            ),
            "r",
        )
        .unwrap();
        assert!(chat.intent.required_capabilities.is_empty());

        let responses = parse_openai_responses(
            Bytes::from_static(
                br#"{"model":"route","input":[{"type":"function_call_output","call_id":"c","output":{"system":"data","reasoning":true,"type":"input_file"}}]}"#,
            ),
            "r",
        )
        .unwrap();
        assert!(responses.intent.required_capabilities.is_empty());

        let gemini = parse_gemini(
            "route",
            false,
            Bytes::from_static(
                br#"{"contents":[{"parts":[{"functionResponse":{"name":"f","response":{"tools":true,"type":"image","systemInstruction":"data"}}}]}]}"#,
            ),
            "r",
        )
        .unwrap();
        assert!(gemini.intent.required_capabilities.is_empty());
    }

    #[test]
    fn capability_extraction_covers_exact_anthropic_and_gemini_semantic_markers() {
        let mut headers = HeaderMap::new();
        headers.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
        let anthropic = parse_anthropic(
            &headers,
            Bytes::from_static(
                br#"{"model":"route","max_tokens":1,"tools":[{"name":"lookup","description":"x","input_schema":{"type":"object","cache_control":"business-data"},"cache_control":{"type":"ephemeral"}}],"messages":[]}"#,
            ),
            "r",
        )
        .unwrap();
        assert!(
            anthropic
                .intent
                .required_capabilities
                .contains(&LlmFeatureCapability::PromptCaching)
        );

        let gemini = parse_gemini(
            "route",
            false,
            Bytes::from_static(
                br#"{"contents":[{"parts":[{"text":"answer","thoughtSignature":"opaque-state"}]}]}"#,
            ),
            "r",
        )
        .unwrap();
        assert!(
            gemini
                .intent
                .required_capabilities
                .contains(&LlmFeatureCapability::OpaqueReasoningState)
        );
    }

    #[test]
    fn anthropic_version_is_closed_and_exact() {
        let mut headers = HeaderMap::new();
        headers.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
        assert!(
            parse_anthropic(
                &headers,
                Bytes::from_static(br#"{"model":"x","max_tokens":1,"messages":[]}"#),
                "r"
            )
            .is_ok()
        );
        headers.append("anthropic-version", HeaderValue::from_static("2023-06-01"));
        assert!(
            parse_anthropic(
                &headers,
                Bytes::from_static(br#"{"model":"x","max_tokens":1,"messages":[]}"#),
                "r"
            )
            .is_err()
        );
    }

    #[test]
    fn responses_websocket_create_uses_top_level_fields() {
        let body = Bytes::from_static(
            br#"{"type":"response.create","model":"route-model","input":"hello","max_output_tokens":32}"#,
        );
        let ResponsesWebSocketClientEvent::Create(native) =
            parse_openai_responses_websocket_event(body, "request-test").unwrap()
        else {
            panic!("expected response.create");
        };
        assert_eq!(native.intent.model_key, "route-model");
        assert_eq!(native.intent.response_mode, ResponseMode::WebSocket);
        assert!(native.intent.required_scopes.contains(LlmScope::Stream));
        assert!(
            native
                .intent
                .required_capabilities
                .contains(&LlmFeatureCapability::Streaming)
        );
    }

    #[test]
    fn responses_websocket_rejects_nested_create_and_accepts_cancel() {
        let nested =
            Bytes::from_static(br#"{"type":"response.create","response":{"model":"route-model"}}"#);
        assert!(parse_openai_responses_websocket_event(nested, "request-test").is_err());
        let cancel =
            Bytes::from_static(br#"{"type":"response.cancel","response_id":"resp_fixture"}"#);
        let ResponsesWebSocketClientEvent::Cancel { response_id, .. } =
            parse_openai_responses_websocket_event(cancel, "request-test").unwrap()
        else {
            panic!("expected response.cancel");
        };
        assert_eq!(response_id.as_deref(), Some("resp_fixture"));
    }

    #[test]
    fn codex_patches_are_centralized_and_bounded() {
        let request = parse_openai_responses(
            Bytes::from_static(br#"{"model":"route","input":"hello","max_output_tokens":99}"#),
            "r",
        )
        .unwrap();
        let body = adapt_body(
            &request,
            TransportKind::OpenaiCodexResponses,
            "gpt-upstream",
            50,
        )
        .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["model"], "gpt-upstream");
        assert_eq!(value["instructions"], "");
        assert!(value.get("max_output_tokens").is_none());
    }
}
