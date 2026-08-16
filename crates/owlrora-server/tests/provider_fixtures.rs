use std::collections::HashMap;

use axum::body::Bytes;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use owlrora_server::{
    adapters::provider::wire::{
        AwsEventStreamDecoder, SseInspector, StreamTerminalOutcome, UsageCompleteness,
        adapt_provider_body, extract_json_usage, upstream_url,
    },
    domain::{
        EndpointAdapterKind, EndpointId, IngressProtocolFamily, LlmScope, LlmScopeSet,
        NetworkPolicyId, TransportKind,
    },
    protocols::{LlmIntent, NativeRequest, ResponseMode},
    runtime::EndpointSnapshot,
};
use serde::Deserialize;
use serde_json::{Value, json};

const FIXTURES: &str = include_str!("fixtures/provider/contracts-v1.json");

#[derive(Debug, Deserialize)]
struct FixtureDocument {
    version: u32,
    source: FixtureSource,
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
struct FixtureSource {
    commit: String,
}

#[derive(Debug, Deserialize)]
struct FixtureCase {
    name: String,
    transport: String,
    request: FixtureRequest,
    response: FixtureResponse,
    stream: FixtureStream,
}

#[derive(Debug, Deserialize)]
struct FixtureRequest {
    method: String,
    path_and_query: String,
    headers: HashMap<String, String>,
    json: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct FixtureResponse {
    status: u16,
    json: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct FixtureStream {
    framing: String,
    chunks: Vec<String>,
}

fn fixtures() -> FixtureDocument {
    serde_json::from_str(FIXTURES).expect("provider fixture document is valid")
}

fn transport(value: &str) -> TransportKind {
    match value {
        "anthropic_messages_native" => TransportKind::AnthropicMessagesNative,
        "anthropic_messages_bedrock" => TransportKind::AnthropicMessagesBedrock,
        "anthropic_messages_vertex" => TransportKind::AnthropicMessagesVertex,
        "openai_chat_completions" => TransportKind::OpenaiChatCompletions,
        "openai_responses_http" => TransportKind::OpenaiResponsesHttp,
        "openai_responses_websocket" => TransportKind::OpenaiResponsesWebsocket,
        "openai_codex_responses" => TransportKind::OpenaiCodexResponses,
        "azure_openai_chat_completions" => TransportKind::AzureOpenaiChatCompletions,
        "azure_openai_responses" => TransportKind::AzureOpenaiResponses,
        "google_gemini_generate_content" => TransportKind::GoogleGeminiGenerateContent,
        "google_vertex_generate_content" => TransportKind::GoogleVertexGenerateContent,
        other => panic!("unknown fixture transport {other}"),
    }
}

fn ingress_family(transport: TransportKind) -> IngressProtocolFamily {
    match transport {
        TransportKind::AnthropicMessagesNative
        | TransportKind::AnthropicMessagesBedrock
        | TransportKind::AnthropicMessagesVertex => IngressProtocolFamily::AnthropicMessages,
        TransportKind::OpenaiChatCompletions | TransportKind::AzureOpenaiChatCompletions => {
            IngressProtocolFamily::OpenaiChatCompletions
        }
        TransportKind::OpenaiResponsesHttp
        | TransportKind::OpenaiResponsesWebsocket
        | TransportKind::OpenaiCodexResponses
        | TransportKind::AzureOpenaiResponses => IngressProtocolFamily::OpenaiResponses,
        TransportKind::GoogleGeminiGenerateContent | TransportKind::GoogleVertexGenerateContent => {
            IngressProtocolFamily::GoogleGemini
        }
    }
}

fn ingress_body(transport: TransportKind, stream: bool) -> Value {
    match ingress_family(transport) {
        IngressProtocolFamily::AnthropicMessages => json!({
            "model":"route-model",
            "max_tokens":32,
            "messages":[{"role":"user","content":[{"type":"text","text":"Return the string fixture-ok."}]}],
            "stream":stream,
        }),
        IngressProtocolFamily::OpenaiChatCompletions => json!({
            "model":"route-model",
            "messages":[{"role":"user","content":"Return the string fixture-ok."}],
            "stream":stream,
            "max_tokens":32,
        }),
        IngressProtocolFamily::OpenaiResponses => json!({
            "model":"route-model",
            "input":"Return the string fixture-ok.",
            "max_output_tokens":32,
            "stream":stream,
        }),
        IngressProtocolFamily::GoogleGemini => json!({
            "contents":[{"role":"user","parts":[{"text":"Return the string fixture-ok."}]}],
            "generationConfig":{"maxOutputTokens":32},
        }),
    }
}

fn native(transport: TransportKind, stream: bool) -> NativeRequest {
    let envelope = ingress_body(transport, stream);
    NativeRequest {
        family: ingress_family(transport),
        original_body: Bytes::from(serde_json::to_vec(&envelope).unwrap()),
        envelope,
        intent: LlmIntent {
            model_key: "route-model".to_owned(),
            response_mode: if stream {
                ResponseMode::Sse
            } else {
                ResponseMode::Json
            },
            required_scopes: LlmScopeSet::new([LlmScope::Invoke]).unwrap(),
            required_capabilities: std::collections::BTreeSet::default(),
            requested_output_bound: Some(32),
            continuation_reference: None,
            replay_safe: true,
        },
    }
}

fn endpoint(transport: TransportKind) -> EndpointSnapshot {
    let (adapter, base_url, region, api_version) = match transport {
        TransportKind::AnthropicMessagesNative => (
            EndpointAdapterKind::AnthropicApi,
            "https://fixture.invalid",
            None,
            None,
        ),
        TransportKind::AnthropicMessagesBedrock => (
            EndpointAdapterKind::AwsBedrockRuntime,
            "https://fixture.invalid",
            Some("fixture-region".to_owned()),
            None,
        ),
        TransportKind::AnthropicMessagesVertex | TransportKind::GoogleVertexGenerateContent => (
            EndpointAdapterKind::GoogleVertex,
            "https://fixture.invalid/v1/projects/fixture-project/locations/fixture-region",
            Some("fixture-region".to_owned()),
            None,
        ),
        TransportKind::OpenaiChatCompletions
        | TransportKind::OpenaiResponsesHttp
        | TransportKind::OpenaiResponsesWebsocket => (
            EndpointAdapterKind::OpenaiApi,
            "https://fixture.invalid",
            None,
            None,
        ),
        TransportKind::OpenaiCodexResponses => (
            EndpointAdapterKind::OpenaiCodex,
            "https://fixture.invalid/backend-api/codex",
            None,
            None,
        ),
        TransportKind::AzureOpenaiChatCompletions | TransportKind::AzureOpenaiResponses => (
            EndpointAdapterKind::AzureOpenai,
            "https://fixture.invalid",
            None,
            Some("fixture-version".to_owned()),
        ),
        TransportKind::GoogleGeminiGenerateContent => (
            EndpointAdapterKind::GoogleGeminiApi,
            "https://fixture.invalid",
            None,
            None,
        ),
    };
    EndpointSnapshot {
        id: EndpointId::new(),
        adapter,
        base_url: base_url.parse().unwrap(),
        region,
        api_version,
        network_policy_id: NetworkPolicyId::new(),
        safe_headers: HashMap::new(),
        config_version: 1,
        active: true,
    }
}

#[test]
fn sanitized_fixture_covers_the_exact_v1_transport_registry() {
    let document = fixtures();
    assert_eq!(document.version, 1);
    assert_eq!(
        document.source.commit,
        "24b6a0bc9541ddb98d928a54303f85cfa1106d2f"
    );
    assert_eq!(document.cases.len(), 11);
    let names = document
        .cases
        .iter()
        .map(|case| case.transport.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(names.len(), 11);
    assert!(FIXTURES.contains("fixture-project"));
    for forbidden in [
        "claude-test-project",
        "youware-office",
        "fzw-ai",
        "gAAAAA",
        "eyJ0eXAi",
        "api.openai.com",
        "api.anthropic.com",
    ] {
        assert!(!FIXTURES.contains(forbidden), "found {forbidden}");
    }
}

#[test]
fn adapter_builds_recorded_json_contracts_without_path_duplication() {
    for case in fixtures()
        .cases
        .into_iter()
        .filter(|case| case.transport != "openai_responses_websocket")
    {
        let transport = transport(&case.transport);
        assert_eq!(case.request.method, "POST", "{}", case.name);
        let native = native(transport, false);
        let endpoint = endpoint(transport);
        let url = upstream_url(&native, transport, "fixture-model", &endpoint).unwrap();
        assert_eq!(
            url.path_and_query(),
            case.request.path_and_query,
            "{}",
            case.name
        );
        let body = adapt_provider_body(&native, transport, "fixture-model", 32).unwrap();
        let actual: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual, case.request.json.unwrap(), "{}", case.name);
        assert_eq!(case.response.status, 200);
        let usage = extract_json_usage(transport, case.response.json.as_ref().unwrap());
        assert_eq!(
            usage.completeness,
            UsageCompleteness::Complete,
            "{}",
            case.name
        );
        assert!(usage.dimensions.contains_key("input_tokens"));
        assert!(usage.dimensions.contains_key("output_tokens"));
        assert_eq!(case.request.headers["content-type"], "application/json");
    }
}

#[test]
fn streaming_fixtures_are_incrementally_parseable_and_report_usage() {
    for case in fixtures()
        .cases
        .into_iter()
        .filter(|case| case.stream.framing == "sse")
    {
        let transport = transport(&case.transport);
        let mut inspector = SseInspector::default();
        for chunk in case.stream.chunks {
            let bytes = chunk.as_bytes();
            let split = bytes.len() / 2;
            inspector.push(transport, &bytes[..split]).unwrap();
            inspector.push(transport, &bytes[split..]).unwrap();
        }
        assert_eq!(
            inspector.latest_usage().completeness,
            UsageCompleteness::Complete,
            "{}",
            case.name
        );
        assert_eq!(
            inspector.terminal_outcome(),
            StreamTerminalOutcome::Complete,
            "{} lacks protocol-native stream completion evidence",
            case.name
        );
    }
}

#[test]
fn bedrock_event_stream_fixture_decodes_across_arbitrary_chunks() {
    let case = fixtures()
        .cases
        .into_iter()
        .find(|case| case.transport == "anthropic_messages_bedrock")
        .unwrap();
    assert_eq!(case.stream.framing, "aws_event_stream_base64");
    let mut decoder = AwsEventStreamDecoder::default();
    let mut inspector = SseInspector::default();
    for encoded in case.stream.chunks {
        let frame = STANDARD.decode(encoded).unwrap();
        for byte in frame {
            for payload in decoder.push(&[byte]).unwrap() {
                let value: Value = serde_json::from_slice(&payload).unwrap();
                let event = value["type"].as_str().unwrap();
                let sse = format!(
                    "event: {event}\ndata: {}\n\n",
                    String::from_utf8(payload).unwrap()
                );
                inspector
                    .push(TransportKind::AnthropicMessagesBedrock, sse.as_bytes())
                    .unwrap();
            }
        }
    }
    assert_eq!(
        inspector.latest_usage().completeness,
        UsageCompleteness::Complete
    );
    assert_eq!(
        inspector.terminal_outcome(),
        StreamTerminalOutcome::Complete
    );
}

#[test]
fn websocket_fixture_uses_only_bounded_responses_text_frames() {
    let case = fixtures()
        .cases
        .into_iter()
        .find(|case| case.transport == "openai_responses_websocket")
        .unwrap();
    assert_eq!(case.request.method, "GET");
    assert_eq!(case.request.path_and_query, "/v1/responses");
    assert_eq!(case.stream.framing, "websocket_text");
    assert!(case.request.json.is_none());
    let frames = case
        .stream
        .chunks
        .iter()
        .map(|frame| serde_json::from_str::<Value>(frame).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(frames[0]["type"], "response.create");
    assert_eq!(frames[0]["model"], "fixture-model");
    assert!(frames[0].get("response").is_none());
    assert!(frames[0].get("stream").is_none());
    assert_eq!(frames.last().unwrap()["type"], "response.completed");
    let usage = extract_json_usage(
        TransportKind::OpenaiResponsesWebsocket,
        frames.last().unwrap(),
    );
    assert_eq!(usage.completeness, UsageCompleteness::Complete);
}

trait UrlPathAndQuery {
    fn path_and_query(&self) -> String;
}

impl UrlPathAndQuery for url::Url {
    fn path_and_query(&self) -> String {
        match self.query() {
            Some(query) => format!("{}?{query}", self.path()),
            None => self.path().to_owned(),
        }
    }
}
