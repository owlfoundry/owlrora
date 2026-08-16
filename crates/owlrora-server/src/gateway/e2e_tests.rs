use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    convert::Infallible,
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::body::Bytes;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use futures_util::{SinkExt as _, StreamExt as _};
use http_body_util::{BodyExt as _, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Request, Response, StatusCode,
    body::{Frame, Incoming},
    header,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use owlrora_key_provider::{
    ContextVersion, FieldPurpose, InstallationId, MaterialId, OwnerId, OwnerKind,
    ProtectionContext, ProtectionContextParts, ProviderFormatVersion, ProviderId, SecretPlaintext,
    SecretScope,
};
use rcgen::{
    BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256,
    PKCS_RSA_SHA256,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;
use tokio::{
    net::TcpListener,
    sync::oneshot,
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::{TlsAcceptor, rustls};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message, client::IntoClientRequest as _, handshake::derive_accept_key, protocol::Role,
    },
};
use uuid::Uuid;

use crate::{
    ServerBuilder,
    adapters::{
        coordinator::{
            PolicyCandidate, PolicyCoordinatorConfig, RedisCoordinator, TargetHealthCategory,
        },
        postgres::{
            AuditRecord, PgStore, RuntimeEvent,
            test_support::{
                connect_from_environment, shared_database_test_lock, valid_reliability_components,
            },
        },
    },
    application::{
        ApplicationError, CatalogGrantKind, CatalogStatus, CoordinatorRecoveryAllocation,
        CreateCoordinatorRecoveries, CreateGatewayApiKey, GatewayBudgetInput,
        GatewayRequestLimitsInput, KeyStatus, RecoveryPolicyKind, RotateGatewayApiKey,
        UpdateBudgetPolicy, UpdateCatalogGrantSet, UpdateField, UpdateGatewayApiKey,
        UpdateGatewayPolicyCeilings, UpdateGatewayRequestLimits, UpdateOrganizationApiKeyPolicy,
        UsageBreakdownDimension, UsageBreakdownOrder, UsageBreakdownQuery, UsageFactFamily,
        UsageGranularity, UsageQuery,
    },
    config::{SecretRoot, ServerConfig},
    domain::{
        BudgetMode, GatewayKeyId, IngressProtocolFamily, LlmFeatureCapability, LlmScope,
        LlmScopeSet, OrganizationId, PolicyKind, RouteGrantRequestPolicyCeilings, RouteId,
        SystemRouteGrantCeilings, gateway_key_digest, generate_gateway_key,
        generate_management_key,
    },
    protocols::{LlmIntent, ProtocolErrorKind, ResponseMode},
    secrets::{CustodyPair, CustodyRegistry, SecretService},
};

const CONTRACTS: &str = include_str!("../../tests/fixtures/provider/contracts-v1.json");
const UPSTREAM_MODEL: &str = "fixture-model";
const PROMPT: &str = "Return the string fixture-ok.";
const INTERRUPTED_STREAM_PROMPT: &str = "Return usage, then end without a terminal marker.";
const STREAM_LIMIT_PROMPT: &str = "stream-limit-fixture";
const SLOW_PHASE_PROMPT: &str = "slow-phase-fixture";

type ReplayBody = UnsyncBoxBody<Bytes, Infallible>;

#[derive(Clone, Debug, Deserialize)]
struct ContractDocument {
    cases: Vec<ContractCase>,
}

#[derive(Clone, Debug, Deserialize)]
struct ContractCase {
    transport: String,
    request: ContractRequest,
    response: ContractResponse,
    stream: ContractStream,
}

#[derive(Clone, Debug, Deserialize)]
struct ContractRequest {
    method: String,
    path_and_query: String,
    headers: HashMap<String, String>,
    json: Option<Value>,
}

#[derive(Clone, Debug, Deserialize)]
struct ContractResponse {
    status: u16,
    json: Option<Value>,
}

#[derive(Clone, Debug, Deserialize)]
struct ContractStream {
    framing: String,
    chunks: Vec<String>,
}

#[derive(Clone, Debug)]
struct RecordedRequest {
    connection_id: Uuid,
    method: String,
    path_and_query: String,
    headers: HashMap<String, String>,
    json: Option<Value>,
}

#[derive(Clone)]
struct ReplayState {
    contracts: Arc<ContractDocument>,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

struct ReplayServer {
    address: SocketAddr,
    ca_pem: String,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

struct StalledTlsServer {
    address: SocketAddr,
    accepted: Arc<AtomicUsize>,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl StalledTlsServer {
    async fn start() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_for_task = Arc::clone(&accepted);
        let (shutdown_sender, mut shutdown) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut shutdown => break,
                    accepted = listener.accept() => {
                        let Ok((socket, _)) = accepted else { break };
                        accepted_for_task.fetch_add(1, Ordering::Relaxed);
                        connections.spawn(async move {
                            let _socket = socket;
                            std::future::pending::<()>().await;
                        });
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Self {
            address,
            accepted,
            shutdown: Some(shutdown_sender),
            task,
        }
    }

    fn accepted_connections(&self) -> usize {
        self.accepted.load(Ordering::Relaxed)
    }

    async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.task.await;
    }
}

impl ReplayServer {
    async fn start() -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_certificate = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_certificate.pem();
        let issuer = Issuer::new(ca_params, ca_key);

        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let params = CertificateParams::new(vec![
            "127.0.0.1".to_owned(),
            "chatgpt.com".to_owned(),
            "oauth.owlrora.test".to_owned(),
        ])
        .unwrap();
        let certificate = params.signed_by(&key, &issuer).unwrap();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
        );
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.der().clone(), ca_certificate.der().clone()],
                key_der,
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let state = ReplayState {
            contracts: Arc::new(serde_json::from_str(CONTRACTS).unwrap()),
            requests: Arc::clone(&requests),
        };
        let (shutdown_sender, mut shutdown) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        let acceptor = acceptor.clone();
                        let state = state.clone();
                        let connection_id = Uuid::now_v7();
                        tokio::spawn(async move {
                            let Ok(stream) = acceptor.accept(stream).await else { return };
                            let service = service_fn(move |request| {
                                handle_replay_request(request, state.clone(), connection_id)
                            });
                            let connection = hyper::server::conn::http1::Builder::new()
                                .serve_connection(TokioIo::new(stream), service)
                                .with_upgrades();
                            let _ = connection.await;
                        });
                    }
                }
            }
        });
        Self {
            address,
            ca_pem,
            requests,
            shutdown: Some(shutdown_sender),
            task,
        }
    }

    async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.task.await;
    }
}

async fn handle_replay_request(
    mut request: Request<Incoming>,
    state: ReplayState,
    connection_id: Uuid,
) -> Result<Response<ReplayBody>, Infallible> {
    if request.method() == hyper::Method::HEAD && request.uri().path() == "/health" {
        record_request(&state, &request, None, connection_id);
        return Ok(bytes_response(
            StatusCode::NO_CONTENT,
            "application/octet-stream",
            Vec::new(),
        ));
    }
    if request.uri().path() == "/oauth/token" {
        let body = request.body_mut().collect().await.unwrap().to_bytes();
        record_request(
            &state,
            &request,
            Some(json!({"form": String::from_utf8_lossy(&body)})),
            connection_id,
        );
        return Ok(json_response(json!({
            "access_token": "fixture-token",
            "expires_in": 3600,
            "token_type": "Bearer"
        })));
    }
    if is_websocket_upgrade(&request) {
        let Some(key) = request
            .headers()
            .get(header::SEC_WEBSOCKET_KEY)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
        else {
            return Ok(status_response(
                StatusCode::BAD_REQUEST,
                "missing WebSocket key",
            ));
        };
        let path_and_query = path_and_query(request.uri());
        let headers = request_headers(request.headers());
        let failure_mode = headers.get("x-replay-mode").cloned();
        let upgrade = hyper::upgrade::on(&mut request);
        let ws_case = state
            .contracts
            .cases
            .iter()
            .find(|case| case.transport == "openai_responses_websocket")
            .unwrap()
            .clone();
        let requests = Arc::clone(&state.requests);
        tokio::spawn(async move {
            let Ok(upgraded) = upgrade.await else { return };
            let mut websocket =
                WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None).await;
            let mut turn = 0_u32;
            loop {
                let Some(Ok(Message::Text(create))) = websocket.next().await else {
                    return;
                };
                turn = turn.saturating_add(1);
                let create_json: Value = match serde_json::from_str(&create) {
                    Ok(value) => value,
                    Err(_) => return,
                };
                requests.lock().unwrap().push(RecordedRequest {
                    connection_id,
                    method: "GET".to_owned(),
                    path_and_query: path_and_query.clone(),
                    headers: headers.clone(),
                    json: Some(create_json.clone()),
                });
                match failure_mode.as_deref() {
                    Some("close-before-event") => {
                        let _ = websocket.close(None).await;
                        return;
                    }
                    Some("provider-overloaded-before-event") => {
                        let _ = websocket
                            .send(Message::Text(
                                json!({
                                    "type":"error",
                                    "error":{
                                        "type":"server_error",
                                        "code":"server_error",
                                        "message":"fixture provider overload"
                                    }
                                })
                                .to_string()
                                .into(),
                            ))
                            .await;
                        return;
                    }
                    _ => {}
                }
                let response_id = format!("resp_fixture_{}_turn_{turn}", ws_case.transport);
                let rewrite = |frame: &str| frame.replace("resp_fixture", &response_id);
                if create_json.get("input").and_then(Value::as_str) == Some("cancel-fixture") {
                    if websocket
                        .send(Message::Text(rewrite(&ws_case.stream.chunks[1]).into()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let Some(Ok(Message::Text(cancel))) = websocket.next().await else {
                        return;
                    };
                    let cancel_json = serde_json::from_str(&cancel).ok();
                    requests.lock().unwrap().push(RecordedRequest {
                        connection_id,
                        method: "FRAME".to_owned(),
                        path_and_query: path_and_query.clone(),
                        headers: HashMap::new(),
                        json: cancel_json,
                    });
                    let cancelled = json!({
                        "type":"response.cancelled",
                        "response":{
                            "id":response_id,
                            "object":"response",
                            "status":"cancelled",
                            "usage":{"input_tokens":12,"output_tokens":0,"total_tokens":12}
                        }
                    });
                    let _ = websocket
                        .send(Message::Text(cancelled.to_string().into()))
                        .await;
                    continue;
                }
                if create_json.get("input").and_then(Value::as_str) == Some(STREAM_LIMIT_PROMPT) {
                    if websocket
                        .send(Message::Text(rewrite(&ws_case.stream.chunks[1]).into()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    for frame in ws_case.stream.chunks.iter().skip(2) {
                        if websocket
                            .send(Message::Text(rewrite(frame).into()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    continue;
                }
                for frame in ws_case.stream.chunks.iter().skip(1) {
                    if websocket
                        .send(Message::Text(rewrite(frame).into()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        });
        let mut response = Response::new(Full::new(Bytes::new()).boxed_unsync());
        *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        response.headers_mut().insert(
            header::CONNECTION,
            header::HeaderValue::from_static("upgrade"),
        );
        response.headers_mut().insert(
            header::UPGRADE,
            header::HeaderValue::from_static("websocket"),
        );
        response.headers_mut().insert(
            header::SEC_WEBSOCKET_ACCEPT,
            header::HeaderValue::from_str(&derive_accept_key(key.as_bytes())).unwrap(),
        );
        return Ok(response);
    }

    let body = request.body_mut().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice::<Value>(&body).ok();
    record_request(&state, &request, json.clone(), connection_id);
    let transport = transport_for_upstream_path(request.uri().path());
    let contract = state
        .contracts
        .cases
        .iter()
        .find(|case| case.transport == transport)
        .unwrap();
    let streaming = request.uri().path().contains("stream")
        || json
            .as_ref()
            .and_then(|value| value.get("stream"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
    let slow_phase = transport == "openai_chat_completions"
        && json.as_ref().is_some_and(|value| {
            value["messages"][0]["content"].as_str() == Some(SLOW_PHASE_PROMPT)
        });
    if slow_phase {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    if streaming {
        let interrupted_after_usage = transport == "openai_chat_completions"
            && json.as_ref().is_some_and(|value| {
                value["messages"][0]["content"].as_str() == Some(INTERRUPTED_STREAM_PROMPT)
            });
        let (content_type, body) = match contract.stream.framing.as_str() {
            "sse" => {
                let mut stream = contract.stream.chunks.concat();
                if interrupted_after_usage {
                    stream = stream.replace("data: [DONE]\n\n", "");
                }
                (
                    "text/event-stream",
                    rewrite_state_id_text(&contract.transport, &stream).into_bytes(),
                )
            }
            "aws_event_stream_base64" => (
                "application/vnd.amazon.eventstream",
                contract
                    .stream
                    .chunks
                    .iter()
                    .flat_map(|chunk| STANDARD.decode(chunk).unwrap())
                    .collect(),
            ),
            framing => panic!("unexpected HTTP fixture framing {framing}"),
        };
        return Ok(bytes_response(StatusCode::OK, content_type, body));
    }
    let response =
        rewrite_state_id_json(&contract.transport, contract.response.json.clone().unwrap());
    if slow_phase {
        Ok(delayed_json_response(response, Duration::from_millis(250)))
    } else {
        Ok(json_response(response))
    }
}

fn rewrite_state_id_json(transport: &str, mut value: Value) -> Value {
    fn rewrite(value: &mut Value, replacement: &str) {
        match value {
            Value::String(text) if text == "resp_fixture" => *text = replacement.to_owned(),
            Value::Array(values) => {
                for value in values {
                    rewrite(value, replacement);
                }
            }
            Value::Object(fields) => {
                for value in fields.values_mut() {
                    rewrite(value, replacement);
                }
            }
            _ => {}
        }
    }
    let replacement = format!("resp_fixture_{transport}");
    rewrite(&mut value, &replacement);
    value
}

fn rewrite_state_id_text(transport: &str, value: &str) -> String {
    value.replace("resp_fixture", &format!("resp_fixture_{transport}"))
}

fn record_request(
    state: &ReplayState,
    request: &Request<Incoming>,
    json: Option<Value>,
    connection_id: Uuid,
) {
    state.requests.lock().unwrap().push(RecordedRequest {
        connection_id,
        method: request.method().to_string(),
        path_and_query: path_and_query(request.uri()),
        headers: request_headers(request.headers()),
        json,
    });
}

fn request_headers(headers: &hyper::HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect()
}

fn path_and_query(uri: &hyper::Uri) -> String {
    uri.path_and_query()
        .map_or_else(|| uri.path().to_owned(), ToString::to_string)
}

fn is_websocket_upgrade(request: &Request<Incoming>) -> bool {
    request.method() == hyper::Method::GET
        && request
            .headers()
            .get(header::UPGRADE)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"websocket"))
}

fn transport_for_upstream_path(path: &str) -> &'static str {
    if path == "/v1/messages" {
        "anthropic_messages_native"
    } else if path.starts_with("/model/") {
        "anthropic_messages_bedrock"
    } else if path.contains("publishers/anthropic/") {
        "anthropic_messages_vertex"
    } else if path.contains("publishers/google/") {
        "google_vertex_generate_content"
    } else if path.starts_with("/backend-api/codex/") {
        "openai_codex_responses"
    } else if path.starts_with("/openai/deployments/") {
        "azure_openai_chat_completions"
    } else if path == "/openai/responses" {
        "azure_openai_responses"
    } else if path.starts_with("/v1beta/models/") {
        "google_gemini_generate_content"
    } else if path == "/v1/chat/completions" {
        "openai_chat_completions"
    } else if path == "/v1/responses" {
        "openai_responses_http"
    } else {
        panic!("unexpected replay path {path}")
    }
}

fn json_response(value: Value) -> Response<ReplayBody> {
    bytes_response(
        StatusCode::OK,
        "application/json",
        serde_json::to_vec(&value).unwrap(),
    )
}

fn status_response(status: StatusCode, body: &str) -> Response<ReplayBody> {
    bytes_response(status, "text/plain", body.as_bytes().to_vec())
}

fn delayed_json_response(value: Value, delay: Duration) -> Response<ReplayBody> {
    let bytes = Bytes::from(serde_json::to_vec(&value).unwrap());
    let stream = async_stream::stream! {
        tokio::time::sleep(delay).await;
        yield Ok::<_, Infallible>(Frame::data(bytes));
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(StreamBody::new(stream).boxed_unsync())
        .unwrap()
}

fn bytes_response(status: StatusCode, content_type: &str, body: Vec<u8>) -> Response<ReplayBody> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(Full::new(Bytes::from(body)).boxed_unsync())
        .unwrap()
}

#[derive(Clone)]
struct TransportFixture {
    transport: &'static str,
    adapter: &'static str,
    credential: &'static str,
    ingress: &'static str,
    route_key: String,
    route_id: Uuid,
    deployment_id: Uuid,
    target_id: Uuid,
}

struct GatewayFixture {
    organization_id: Uuid,
    key_id: Uuid,
    key_wire: String,
    network_id: Uuid,
    openai_credential_id: Uuid,
    budget_candidates: Vec<PolicyCandidate>,
    rate_candidate: PolicyCandidate,
    routes: Vec<TransportFixture>,
    temp_dir: PathBuf,
}

impl GatewayFixture {
    fn route(&self, transport: &str) -> &TransportFixture {
        self.routes
            .iter()
            .find(|fixture| fixture.transport == transport)
            .unwrap()
    }
}

fn transports() -> Vec<TransportFixture> {
    [
        (
            "anthropic_messages_native",
            "anthropic_api",
            "anthropic",
            "anthropic_messages",
        ),
        (
            "anthropic_messages_bedrock",
            "aws_bedrock_runtime",
            "aws",
            "anthropic_messages",
        ),
        (
            "anthropic_messages_vertex",
            "google_vertex",
            "google",
            "anthropic_messages",
        ),
        (
            "openai_chat_completions",
            "openai_api",
            "openai",
            "openai_chat_completions",
        ),
        (
            "openai_responses_http",
            "openai_api",
            "openai",
            "openai_responses",
        ),
        (
            "openai_responses_websocket",
            "openai_api",
            "openai",
            "openai_responses",
        ),
        (
            "openai_codex_responses",
            "openai_codex",
            "codex",
            "openai_responses",
        ),
        (
            "azure_openai_chat_completions",
            "azure_openai",
            "azure",
            "openai_chat_completions",
        ),
        (
            "azure_openai_responses",
            "azure_openai",
            "azure",
            "openai_responses",
        ),
        (
            "google_gemini_generate_content",
            "google_gemini_api",
            "gemini",
            "google_gemini",
        ),
        (
            "google_vertex_generate_content",
            "google_vertex",
            "google",
            "google_gemini",
        ),
    ]
    .into_iter()
    .map(
        |(transport, adapter, credential, ingress)| TransportFixture {
            transport,
            adapter,
            credential,
            ingress,
            route_key: format!("e2e-{transport}-{}", Uuid::now_v7()),
            route_id: Uuid::now_v7(),
            deployment_id: Uuid::now_v7(),
            target_id: Uuid::now_v7(),
        },
    )
    .collect()
}

async fn insert_gateway_fixture(
    store: &PgStore,
    secrets: &SecretService,
    replay: &ReplayServer,
) -> GatewayFixture {
    let organization_id = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    let membership_id = Uuid::now_v7();
    let network_id = Uuid::now_v7();
    let ca_secret_id = Uuid::now_v7();
    let reliability_id = Uuid::now_v7();
    let key_id = Uuid::now_v7();
    let key_budget_id = Uuid::now_v7();
    let key_rate_policy_id = Uuid::now_v7();
    let key_rate_version_id = Uuid::now_v7();
    let routes = transports();
    let temp_dir = std::env::temp_dir().join(format!("owlrora-gateway-e2e-{organization_id}"));
    fs::create_dir_all(&temp_dir).unwrap();

    let google_key = KeyPair::generate_for(&PKCS_RSA_SHA256).unwrap();
    let credential_files = write_credential_files(&temp_dir, replay.address, &google_key);
    let endpoint_ids = [
        "anthropic_api",
        "aws_bedrock_runtime",
        "google_vertex",
        "openai_api",
        "openai_codex",
        "azure_openai",
        "google_gemini_api",
    ]
    .into_iter()
    .map(|adapter| (adapter, Uuid::now_v7()))
    .collect::<HashMap<_, _>>();
    let credential_ids = [
        "anthropic",
        "aws",
        "google",
        "openai",
        "codex",
        "azure",
        "gemini",
    ]
    .into_iter()
    .map(|name| (name, Uuid::now_v7()))
    .collect::<HashMap<_, _>>();

    let context = custom_ca_context(store.installation_id(), ca_secret_id, network_id);
    let envelope = secrets
        .seal(
            &context,
            &SecretPlaintext::new(replay.ca_pem.as_bytes().to_vec()).unwrap(),
        )
        .await
        .unwrap()
        .expose(<[u8]>::to_vec);

    let gateway_key = generate_gateway_key();
    let key_wire = gateway_key.expose_once();
    let lookup = gateway_key.lookup_text();
    let digest = gateway_key_digest(&gateway_key);
    let route_ids = routes
        .iter()
        .map(|route| route.route_id)
        .collect::<Vec<_>>();

    let mut transaction = store.begin().await.unwrap();
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO protected_secret_versions(id,scope_kind,owner_kind,owner_id,
            owner_generation,secret_version,field_purpose,custody_provider_id,
            provider_format_version,context_version,opaque_envelope)
         VALUES ($1,'system','egress_network_policy',$2,1,1,'custom_ca_bundle',
            'software-xchacha20-poly1305',1,1,$3)",
    )
    .bind(ca_secret_id)
    .bind(network_id)
    .bind(envelope)
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO egress_network_policies(id,name,dns_policy,address_policy,tls_policy,
            custom_ca_secret_id,custom_ca_generation,redirect_policy,connection_policy,
            body_policy,status,created_by_principal,etag_token)
         VALUES ($1,$2,'{}','{\"allow_loopback\":true}','{}',$3,1,'{}','{}','{}',
            'active','{}',$4)",
    )
    .bind(network_id)
    .bind(format!("e2e-network-{network_id}"))
    .bind(ca_secret_id)
    .bind(Uuid::now_v7())
    .execute(&mut *transaction)
    .await
    .unwrap();

    for (adapter, endpoint_id) in &endpoint_ids {
        let (base_url, region, api_version) = endpoint_configuration(adapter, replay.address);
        sqlx::query(
            "INSERT INTO upstream_endpoints(id,name,adapter_kind,base_url,region,api_version,
                network_policy_id,safe_headers,status,created_by_principal,etag_token)
             VALUES ($1,$2,$3,$4,$5,$6,$7,'{}','active','{}',$8)",
        )
        .bind(endpoint_id)
        .bind(format!("e2e-endpoint-{adapter}-{endpoint_id}"))
        .bind(adapter)
        .bind(base_url)
        .bind(region)
        .bind(api_version)
        .bind(network_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
    }

    for (name, credential_id) in &credential_ids {
        let (kind, injection) = credential_configuration(name);
        let (source_kind, source_configuration, fingerprint): (&str, Value, [u8; 32]) =
            if *name == "aws" {
                (
                    "workload_identity",
                    json!({}),
                    Sha256::digest(b"aws-default-chain-e2e").into(),
                )
            } else {
                let path = credential_files.get(name).unwrap();
                let bytes = fs::read(path).unwrap();
                (
                    "mounted_file_reference",
                    json!({"path": path.to_str().unwrap()}),
                    Sha256::digest(&bytes).into(),
                )
            };
        sqlx::query(
            "INSERT INTO upstream_credentials(id,resource_scope_kind,name,credential_kind,
                secret_source_kind,injection_kind,sharing_policy,administrative_status,
                authentication_status,current_secret_version,created_by_principal,etag_token)
             VALUES ($1,'deployment',$2,$3,$4,$5,'same_scope_reusable',
                'active','ready',1,'{}',$6)",
        )
        .bind(credential_id)
        .bind(format!("e2e-credential-{name}-{credential_id}"))
        .bind(kind)
        .bind(source_kind)
        .bind(injection)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO upstream_credential_secret_versions(id,credential_id,version,
                credential_state_identity_version,source_configuration,safe_fingerprint,state)
             VALUES ($1,$2,1,1,$3,$4,'current')",
        )
        .bind(Uuid::now_v7())
        .bind(credential_id)
        .bind(source_configuration)
        .bind(fingerprint.to_vec())
        .execute(&mut *transaction)
        .await
        .unwrap();
    }

    let mut reliability = valid_reliability_components();
    reliability[7] = json!({
        "enabled": true,
        "interval_ms": 1_000,
        "timeout_ms": 750,
        "path": "/health"
    });
    sqlx::query(
        "INSERT INTO reliability_policies(id,name,attempt_policy,deadline_policy,retry_policy,
            failover_policy,commitment_policy,health_policy,circuit_policy,probe_policy,
            status,created_by_principal,etag_token)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'active','{}',$11)",
    )
    .bind(reliability_id)
    .bind(format!("e2e-reliability-{reliability_id}"))
    .bind(&reliability[0])
    .bind(&reliability[1])
    .bind(&reliability[2])
    .bind(&reliability[3])
    .bind(&reliability[4])
    .bind(&reliability[5])
    .bind(&reliability[6])
    .bind(&reliability[7])
    .bind(Uuid::now_v7())
    .execute(&mut *transaction)
    .await
    .unwrap();

    for route in &routes {
        let has_base_document_capability = matches!(
            route.transport,
            "openai_chat_completions" | "openai_responses_websocket"
        );
        let deployment_capabilities = if has_base_document_capability {
            json!(["streaming", "document_input"])
        } else {
            json!(["streaming"])
        };
        let required_base_capabilities = if has_base_document_capability {
            json!(["document_input"])
        } else {
            json!([])
        };
        sqlx::query(
            "INSERT INTO model_deployments(id,resource_scope_kind,name,endpoint_id,credential_id,
                transport_kind,upstream_model_id,capability_set,context_limits,
                state_isolation_profile,unpriced,status,created_by_principal,etag_token)
             VALUES ($1,'deployment',$2,$3,$4,$5,$6,$7,'{}','{}',true,
                'active','{}',$8)",
        )
        .bind(route.deployment_id)
        .bind(format!(
            "e2e-deployment-{}-{}",
            route.transport, route.deployment_id
        ))
        .bind(endpoint_ids[route.adapter])
        .bind(credential_ids[route.credential])
        .bind(route.transport)
        .bind(UPSTREAM_MODEL)
        .bind(deployment_capabilities)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO model_routes(id,resource_scope_kind,model_key,ingress_protocol_family,
                required_base_capabilities,selection_policy,reliability_policy_id,request_policy,
                status,created_by_principal,etag_token)
             VALUES ($1,'deployment',$2,$3,$4,'{}',$5,'{}','active','{}',$6)",
        )
        .bind(route.route_id)
        .bind(&route.route_key)
        .bind(route.ingress)
        .bind(required_base_capabilities)
        .bind(reliability_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO route_targets(id,route_id,deployment_id,affinity_identity,priority,
                weight,enabled,etag_token) VALUES ($1,$2,$3,$4,0,256,true,$5)",
        )
        .bind(route.target_id)
        .bind(route.route_id)
        .bind(route.deployment_id)
        .bind(Uuid::new_v4().as_bytes().to_vec())
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
    }

    // A disabled route-local timeout must not tighten the endpoint-owned client shared by the
    // active route. Before client construction was isolated, this 10 ms override reduced the
    // shared client below the endpoint policy's supported 100 ms minimum and poisoned capture.
    let shared_client_route = routes
        .iter()
        .find(|route| route.transport == "openai_chat_completions")
        .unwrap();
    let isolated_route_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO model_routes(id,resource_scope_kind,model_key,ingress_protocol_family,
            required_base_capabilities,selection_policy,reliability_policy_id,request_policy,
            status,created_by_principal,etag_token)
         VALUES ($1,'deployment',$2,$3,'[\"document_input\"]','{}',$4,'{}',
            'disabled','{}',$5)",
    )
    .bind(isolated_route_id)
    .bind(format!("client-timeout-isolation-{isolated_route_id}"))
    .bind(shared_client_route.ingress)
    .bind(reliability_id)
    .bind(Uuid::now_v7())
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO route_targets(id,route_id,deployment_id,affinity_identity,priority,
            weight,enabled,timeout_overrides,etag_token)
         VALUES ($1,$2,$3,$4,0,256,true,'{\"connect_timeout_ms\":10}',$5)",
    )
    .bind(Uuid::now_v7())
    .bind(isolated_route_id)
    .bind(shared_client_route.deployment_id)
    .bind(Uuid::new_v4().as_bytes().to_vec())
    .bind(Uuid::now_v7())
    .execute(&mut *transaction)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO organizations(id,kind,status,name,created_by_principal,etag_token)
         VALUES ($1,'ordinary','active',$2,'{}',$3)",
    )
    .bind(organization_id)
    .bind(format!("e2e-organization-{organization_id}"))
    .bind(Uuid::now_v7())
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO users(id,kind,status,display_name,created_by_principal,etag_token)
         VALUES ($1,'human','active','Gateway E2E owner','{}',$2)",
    )
    .bind(user_id)
    .bind(Uuid::now_v7())
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO memberships(id,organization_id,user_id,role,status,llm_scope_ceiling,
            llm_capability_ceiling,llm_route_ceiling,created_by_principal,etag_token)
         VALUES ($1,$2,$3,'owner','active','[\"llm:invoke\",\"llm:stream\"]',
            '[\"streaming\"]',$4,'{}',$5)",
    )
    .bind(membership_id)
    .bind(organization_id)
    .bind(user_id)
    .bind(json!({"kind":"routes","route_ids":route_ids}))
    .bind(Uuid::now_v7())
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO organization_api_key_policies(organization_id,policy,etag_token)
         VALUES ($1,$2,$3)",
    )
    .bind(organization_id)
    .bind(organization_gateway_policy(&route_ids))
    .bind(Uuid::now_v7())
    .execute(&mut *transaction)
    .await
    .unwrap();
    for route_id in &route_ids {
        sqlx::query(
            "INSERT INTO organization_route_grant_identities(
                id,organization_id,route_id,created_by_principal
             ) VALUES ($1,$2,$3,'{}')",
        )
        .bind(Uuid::now_v7())
        .bind(organization_id)
        .bind(route_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO organization_route_grants(organization_id,route_id,ceilings,status,
                created_by_principal,etag_token) VALUES ($1,$2,'{}','active','{}',$3)",
        )
        .bind(organization_id)
        .bind(route_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
    }

    let key_budget_version = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO gateway_api_keys(id,organization_id,issuance_policy_class,
            created_by_principal,name,key_prefix,lookup_id,scopes,budget_policy_id,
            rate_policy_id,status,etag_token)
         VALUES ($1,$2,'standard','{}',$3,'owlrora_llm_v1',$4,
            '[\"llm:invoke\",\"llm:stream\"]',$5,$6,'active',$7)",
    )
    .bind(key_id)
    .bind(organization_id)
    .bind(format!("e2e-key-{key_id}"))
    .bind(&lookup)
    .bind(key_budget_id)
    .bind(key_rate_policy_id)
    .bind(Uuid::now_v7())
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO gateway_key_budget_policies(id,organization_id,gateway_api_key_id,
            active_version_id,status,etag_token) VALUES ($1,$2,$3,$4,'active',$5)",
    )
    .bind(key_budget_id)
    .bind(organization_id)
    .bind(key_id)
    .bind(key_budget_version)
    .bind(Uuid::now_v7())
    .execute(&mut *transaction)
    .await
    .unwrap();
    let key_budget_epoch = format!("e2e-key-{key_id}");
    insert_budget_version(
        &mut transaction,
        key_budget_version,
        "gateway_key_budget",
        Some(key_budget_id),
        None,
        key_budget_epoch.clone(),
    )
    .await;
    sqlx::query(
        "INSERT INTO gateway_key_rate_policies(
            id,organization_id,gateway_api_key_id,desired_version_id,active_version_id,
            status,etag_token)
         VALUES ($1,$2,$3,$4,$4,'active',$5)",
    )
    .bind(key_rate_policy_id)
    .bind(organization_id)
    .bind(key_id)
    .bind(key_rate_version_id)
    .bind(Uuid::now_v7())
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO gateway_key_rate_policy_versions(
            id,rate_policy_id,generation,epoch,requests_per_minute,input_units_per_minute,
            grant_mode,grant_policy,max_stream_seconds,created_by_principal)
         VALUES ($1,$2,1,'fixture-rate-epoch',1000,1000000,'local_grants',
            '{\"max_request_tokens\":10,\"grant_seconds\":1}',1,'{}')",
    )
    .bind(key_rate_version_id)
    .bind(key_rate_policy_id)
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO gateway_api_key_secret_versions(id,gateway_api_key_id,lookup_id,
            secret_digest,state) VALUES ($1,$2,$3,$4,'current')",
    )
    .bind(Uuid::now_v7())
    .bind(key_id)
    .bind(&lookup)
    .bind(digest.to_vec())
    .execute(&mut *transaction)
    .await
    .unwrap();
    for route_id in &route_ids {
        sqlx::query(
            "INSERT INTO gateway_api_key_routes(organization_id,gateway_api_key_id,route_id)
             VALUES ($1,$2,$3)",
        )
        .bind(organization_id)
        .bind(key_id)
        .bind(route_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
    }

    let system_origin_id = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM organization_origin_budget_policies
         WHERE organization_id=$1 AND origin='system_provided'",
    )
    .bind(organization_id)
    .fetch_one(&mut *transaction)
    .await
    .unwrap();
    let origin_version = Uuid::now_v7();
    let origin_epoch = format!("e2e-origin-{organization_id}");
    insert_budget_version(
        &mut transaction,
        origin_version,
        "organization_origin_budget",
        None,
        Some(system_origin_id),
        origin_epoch.clone(),
    )
    .await;
    sqlx::query(
        "UPDATE organization_origin_budget_policies
         SET status='active',active_version_id=$2 WHERE id=$1",
    )
    .bind(system_origin_id)
    .bind(origin_version)
    .execute(&mut *transaction)
    .await
    .unwrap();

    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    allocate_runtime_revision(store).await;

    let budget_config = |version_id| PolicyCoordinatorConfig::Budget {
        version_id,
        mode: "enforce".to_owned(),
        limit_cost_nanos: "1000000000".to_owned(),
        max_slice_nanos: "100000000".to_owned(),
        grant_seconds: 30,
    };
    GatewayFixture {
        organization_id,
        key_id,
        key_wire,
        network_id,
        openai_credential_id: credential_ids["openai"],
        budget_candidates: vec![
            PolicyCandidate {
                organization_id: OrganizationId::from_uuid(organization_id),
                kind: PolicyKind::GatewayKeyBudget,
                policy_id: key_budget_id,
                desired_epoch: key_budget_epoch,
                desired_version_id: key_budget_version,
                desired_generation: 1,
                desired_recovery_generation: 0,
                fence: Uuid::now_v7(),
                config: budget_config(key_budget_version),
            },
            PolicyCandidate {
                organization_id: OrganizationId::from_uuid(organization_id),
                kind: PolicyKind::OrganizationOriginBudget,
                policy_id: system_origin_id,
                desired_epoch: origin_epoch,
                desired_version_id: origin_version,
                desired_generation: 1,
                desired_recovery_generation: 0,
                fence: Uuid::now_v7(),
                config: budget_config(origin_version),
            },
        ],
        rate_candidate: PolicyCandidate {
            organization_id: OrganizationId::from_uuid(organization_id),
            kind: PolicyKind::GatewayKeyRequestLimits,
            policy_id: key_rate_policy_id,
            desired_epoch: "fixture-rate-epoch".to_owned(),
            desired_version_id: key_rate_version_id,
            desired_generation: 1,
            desired_recovery_generation: 0,
            fence: Uuid::now_v7(),
            config: PolicyCoordinatorConfig::RequestLimits {
                version_id: key_rate_version_id,
                requests_per_minute: 1000,
                input_units_per_minute: Some(1_000_000),
                grant_mode: "local_grants".to_owned(),
                max_request_tokens: 10,
                grant_seconds: 1,
                concurrency_mode: None,
                concurrency_limit: None,
                lease_seconds: None,
                max_stream_seconds: 1,
            },
        },
        routes,
        temp_dir,
    }
}

async fn insert_websocket_pre_exposure_failover_target(
    store: &PgStore,
    fixture: &GatewayFixture,
    replay_address: SocketAddr,
) -> Uuid {
    let endpoint_id = Uuid::now_v7();
    let deployment_id = Uuid::now_v7();
    let target_id = Uuid::now_v7();
    let route = fixture.route("openai_responses_websocket");
    let mut transaction = store.begin().await.unwrap();
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO upstream_endpoints(id,name,adapter_kind,base_url,network_policy_id,
            safe_headers,status,created_by_principal,etag_token)
         VALUES ($1,$2,'openai_api',$3,$4,$5,'active','{}',$6)",
    )
    .bind(endpoint_id)
    .bind(format!("e2e-ws-pre-exposure-failure-{endpoint_id}"))
    .bind(format!("https://{replay_address}"))
    .bind(fixture.network_id)
    .bind(json!({"x-replay-mode":"provider-overloaded-before-event"}))
    .bind(Uuid::now_v7())
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO model_deployments(id,resource_scope_kind,name,endpoint_id,credential_id,
            transport_kind,upstream_model_id,capability_set,context_limits,
            state_isolation_profile,unpriced,status,created_by_principal,etag_token)
         VALUES ($1,'deployment',$2,$3,$4,'openai_responses_websocket',$5,
            '[\"streaming\",\"document_input\"]','{}','{}',true,'active','{}',$6)",
    )
    .bind(deployment_id)
    .bind(format!("e2e-ws-pre-exposure-failure-{deployment_id}"))
    .bind(endpoint_id)
    .bind(fixture.openai_credential_id)
    .bind(UPSTREAM_MODEL)
    .bind(Uuid::now_v7())
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query("UPDATE route_targets SET priority=1 WHERE id=$1")
        .bind(route.target_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO route_targets(id,route_id,deployment_id,affinity_identity,priority,
            weight,enabled,etag_token) VALUES ($1,$2,$3,$4,0,256,true,$5)",
    )
    .bind(target_id)
    .bind(route.route_id)
    .bind(deployment_id)
    .bind(Uuid::new_v4().as_bytes().to_vec())
    .bind(Uuid::now_v7())
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    allocate_runtime_revision(store).await;
    target_id
}

async fn narrow_target_connect_timeout(store: &PgStore, target_id: Uuid, timeout_ms: u64) {
    sqlx::query(
        "UPDATE route_targets
         SET timeout_overrides=jsonb_build_object('connect_timeout_ms',$2::bigint),
             etag_token=$3
         WHERE id=$1",
    )
    .bind(target_id)
    .bind(i64::try_from(timeout_ms).unwrap())
    .bind(Uuid::now_v7())
    .execute(store.pool())
    .await
    .unwrap();
    allocate_runtime_revision(store).await;
}

struct StalledConnectTargets {
    target_ids: [Uuid; 2],
    healthy_http_target_id: Uuid,
    failed_websocket_target_id: Uuid,
}

async fn insert_stalled_connect_targets(
    store: &PgStore,
    fixture: &GatewayFixture,
    failed_websocket_target_id: Uuid,
) -> StalledConnectTargets {
    let endpoint_id = Uuid::now_v7();
    let http_deployment_id = Uuid::now_v7();
    let websocket_deployment_id = Uuid::now_v7();
    let http_target_id = Uuid::now_v7();
    let websocket_target_id = Uuid::now_v7();
    let http_route = fixture.route("openai_chat_completions");
    let websocket_route = fixture.route("openai_responses_websocket");
    let mut transaction = store.begin().await.unwrap();
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO upstream_endpoints(id,name,adapter_kind,base_url,network_policy_id,
            safe_headers,status,created_by_principal,etag_token)
         VALUES ($1,$2,'openai_api','https://connect-stall.owlrora.test',$3,'{}',
            'active','{}',$4)",
    )
    .bind(endpoint_id)
    .bind(format!("e2e-connect-stall-{endpoint_id}"))
    .bind(fixture.network_id)
    .bind(Uuid::now_v7())
    .execute(&mut *transaction)
    .await
    .unwrap();
    for (deployment_id, transport) in [
        (http_deployment_id, "openai_chat_completions"),
        (websocket_deployment_id, "openai_responses_websocket"),
    ] {
        sqlx::query(
            "INSERT INTO model_deployments(id,resource_scope_kind,name,endpoint_id,credential_id,
                transport_kind,upstream_model_id,capability_set,context_limits,
                state_isolation_profile,unpriced,status,created_by_principal,etag_token)
             VALUES ($1,'deployment',$2,$3,$4,$5,$6,
                '[\"streaming\",\"document_input\"]','{}','{}',true,'active','{}',$7)",
        )
        .bind(deployment_id)
        .bind(format!("e2e-connect-stall-{transport}-{deployment_id}"))
        .bind(endpoint_id)
        .bind(fixture.openai_credential_id)
        .bind(transport)
        .bind(UPSTREAM_MODEL)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
    }
    sqlx::query("UPDATE route_targets SET priority=1 WHERE id=$1")
        .bind(http_route.target_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query("UPDATE route_targets SET enabled=false, priority=2 WHERE id=$1")
        .bind(failed_websocket_target_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
    for (target_id, route_id, deployment_id) in [
        (http_target_id, http_route.route_id, http_deployment_id),
        (
            websocket_target_id,
            websocket_route.route_id,
            websocket_deployment_id,
        ),
    ] {
        sqlx::query(
            "INSERT INTO route_targets(id,route_id,deployment_id,affinity_identity,priority,
                weight,enabled,timeout_overrides,etag_token)
             VALUES ($1,$2,$3,$4,0,256,true,'{\"connect_timeout_ms\":100}',$5)",
        )
        .bind(target_id)
        .bind(route_id)
        .bind(deployment_id)
        .bind(Uuid::new_v4().as_bytes().to_vec())
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
    }
    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    allocate_runtime_revision(store).await;
    StalledConnectTargets {
        target_ids: [http_target_id, websocket_target_id],
        healthy_http_target_id: http_route.target_id,
        failed_websocket_target_id,
    }
}

async fn remove_stalled_connect_targets(store: &PgStore, targets: &StalledConnectTargets) {
    let mut transaction = store.begin().await.unwrap();
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query("UPDATE route_targets SET enabled=false, priority=255 WHERE id=ANY($1)")
        .bind(targets.target_ids.to_vec())
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query("UPDATE route_targets SET priority=0 WHERE id=$1")
        .bind(targets.healthy_http_target_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query("UPDATE route_targets SET enabled=true, priority=0 WHERE id=$1")
        .bind(targets.failed_websocket_target_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    allocate_runtime_revision(store).await;
}

fn custom_ca_context(
    installation_id: Uuid,
    material_id: Uuid,
    network_id: Uuid,
) -> ProtectionContext {
    ProtectionContext::new(ProtectionContextParts {
        version: ContextVersion::V1,
        installation_id: InstallationId::new(installation_id.to_string()).unwrap(),
        scope: SecretScope::System,
        material_id: MaterialId::new(material_id.to_string()).unwrap(),
        owner_kind: OwnerKind::new("egress_network_policy").unwrap(),
        owner_id: OwnerId::new(network_id.to_string()).unwrap(),
        owner_generation: 1,
        secret_version: 1,
        field_purpose: FieldPurpose::new("custom_ca_bundle").unwrap(),
        provider_id: ProviderId::new("software-xchacha20-poly1305").unwrap(),
        provider_format_version: ProviderFormatVersion::new(1).unwrap(),
    })
    .unwrap()
}

fn write_credential_files(
    directory: &Path,
    token_address: SocketAddr,
    google_key: &KeyPair,
) -> HashMap<&'static str, PathBuf> {
    let codex_payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "https://api.openai.com/auth":{"chatgpt_account_id":"fixture-account"}
        }))
        .unwrap(),
    );
    let materials = [
        ("anthropic", b"fixture-secret".to_vec()),
        (
            "aws",
            serde_json::to_vec(&json!({
                "access_key_id":"AKIDFIXTURE",
                "secret_access_key":"fixture-secret",
                "session_token":"fixture-session"
            }))
            .unwrap(),
        ),
        (
            "google",
            serde_json::to_vec(&json!({
                "project_id":"fixture-project",
                "client_email":"fixture@fixture-project.iam.gserviceaccount.com",
                "private_key":google_key.serialize_pem(),
                "token_uri":format!(
                    "https://oauth.owlrora.test:{}/oauth/token",
                    token_address.port()
                )
            }))
            .unwrap(),
        ),
        ("openai", b"fixture-secret".to_vec()),
        (
            "codex",
            serde_json::to_vec(&json!({
                "id_token":format!("e30.{codex_payload}.fixture"),
                "access_token":"fixture-token",
                "refresh_token":"fixture-refresh"
            }))
            .unwrap(),
        ),
        ("azure", b"fixture-secret".to_vec()),
        ("gemini", b"fixture-secret".to_vec()),
    ];
    materials
        .into_iter()
        .map(|(name, material)| {
            let path = directory.join(format!("{name}.secret"));
            fs::write(&path, material).unwrap();
            (name, path)
        })
        .collect()
}

fn endpoint_configuration(
    adapter: &str,
    replay_address: SocketAddr,
) -> (String, Option<&'static str>, Option<&'static str>) {
    let base = format!("https://{replay_address}");
    match adapter {
        "aws_bedrock_runtime" => (base, Some("us-east-1"), None),
        "google_vertex" => (
            format!("{base}/v1/projects/fixture-project/locations/fixture-region"),
            Some("fixture-region"),
            None,
        ),
        "openai_codex" => (
            "https://chatgpt.com/backend-api/codex".to_owned(),
            None,
            None,
        ),
        "azure_openai" => (base, None, Some("fixture-version")),
        _ => (base, None, None),
    }
}

fn credential_configuration(name: &str) -> (&'static str, &'static str) {
    match name {
        "anthropic" => ("static_api_key", "x_api_key"),
        "aws" => ("aws_default_chain", "aws_sigv4"),
        "google" => ("google_service_account", "google_oauth"),
        "openai" => ("static_api_key", "bearer"),
        "codex" => ("oauth_openai_codex", "bearer"),
        "azure" => ("azure_api_key", "api_key_header"),
        "gemini" => ("static_api_key", "api_key_header"),
        _ => unreachable!(),
    }
}

fn organization_gateway_policy(route_ids: &[Uuid]) -> Value {
    json!({
        "management": {
            "allowed_scopes":["management:read"], "allowed_capabilities":["read_organization"],
            "max_active_keys":100, "max_expiry_days":365, "max_overlap_seconds":3600
        },
        "member_self_service": {
            "management_key_creation":false, "allowed_scopes":[], "allowed_capabilities":[],
            "max_active_keys":0, "max_expiry_days":0, "max_overlap_seconds":0
        },
        "gateway": {
            "enabled":true, "allowed_scopes":["llm:invoke","llm:stream"],
            "allowed_capabilities":["streaming"], "allowed_route_ids":route_ids,
            "max_active_keys":10, "max_expiry_days":365, "max_overlap_seconds":3600,
            "budget":{"max_limit_cost_nanos":"1000000000","allowed_modes":["enforce"]},
            "rate":{"max_requests_per_minute":1000,"max_input_units_per_minute":1_000_000},
            "concurrency":{"max_limit":100,"allowed_modes":["approximate"]}
        },
        "gateway_member_self_service": {
            "enabled":false, "allowed_scopes":[], "allowed_capabilities":[],
            "allowed_route_ids":[], "max_active_keys":0, "max_expiry_days":0,
            "max_overlap_seconds":0, "budget":{"max_limit_cost_nanos":"0","allowed_modes":[]},
            "rate":{"max_requests_per_minute":0,"max_input_units_per_minute":0},
            "concurrency":{"max_limit":0,"allowed_modes":[]}
        }
    })
}

async fn insert_budget_version(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    kind: &str,
    key_policy_id: Option<Uuid>,
    origin_policy_id: Option<Uuid>,
    epoch: String,
) {
    sqlx::query(
        r#"INSERT INTO budget_policy_versions(id,policy_kind,gateway_key_budget_policy_id,
            organization_origin_budget_policy_id,generation,limit_cost_nanos,
            recovery_incident_cap_nanos,recovery_epoch_cap_nanos,epoch,mode,
            estimate_policy,allowance_policy,failure_policy,recovery_policy,created_by_principal)
         VALUES ($1,$2,$3,$4,1,1000000000,0,0,$5,'enforce',
            '{"unknown_mode":"fixed_unknown_reservation","fixed_unknown_reservation_nanos":1000000}',
            '{}','{}','{}','{}')"#,
    )
    .bind(id)
    .bind(kind)
    .bind(key_policy_id)
    .bind(origin_policy_id)
    .bind(epoch)
    .execute(&mut **transaction)
    .await
    .unwrap();
}

async fn allocate_runtime_revision(store: &PgStore) {
    let transaction = store.begin().await.unwrap();
    store
        .commit_command(
            transaction,
            &AuditRecord {
                actor: None,
                authentication_evidence: json!({"kind":"gateway_e2e"}),
                organization_id: None,
                target_resource_kind: "gateway_e2e_fixture".to_owned(),
                target_resource_id: None,
                operation_id: "gateway_e2e_fixture.created".to_owned(),
                outcome: "accepted",
                request_id: Uuid::now_v7().to_string(),
                changed_fields: vec!["gateway_e2e_fixture".to_owned()],
                safe_details: json!({}),
            },
            Some(&RuntimeEvent {
                event_kind: "gateway_e2e_fixture.created".to_owned(),
                affected_scope: json!({"kind":"gateway_e2e_fixture"}),
                security_tightening: false,
            }),
        )
        .await
        .unwrap();
}

fn server_config(
    database_url: String,
    redis_url: String,
    seed_admin_key: &str,
) -> Arc<ServerConfig> {
    let mut values = BTreeMap::new();
    values.insert("OWLRORA_PROFILE".to_owned(), "full".to_owned());
    values.insert("OWLRORA_DATABASE_URL".to_owned(), database_url);
    values.insert("OWLRORA_REDIS_URL".to_owned(), redis_url);
    values.insert(
        "OWLRORA_PUBLIC_ORIGIN".to_owned(),
        "https://console.owlrora.test".to_owned(),
    );
    values.insert(
        "OWLRORA_NODE_INSTANCE_ID".to_owned(),
        format!("gateway-e2e-{}", Uuid::now_v7()),
    );
    values.insert(
        "OWLRORA_SECRET_ROOT".to_owned(),
        URL_SAFE_NO_PAD.encode([117_u8; 32]),
    );
    values.insert(
        "OWLRORA_SEED_ADMIN_API_KEY".to_owned(),
        seed_admin_key.to_owned(),
    );
    values.insert(
        "OWLRORA_USAGE_FLUSH_INTERVAL_SECONDS".to_owned(),
        "1".to_owned(),
    );
    values.insert(
        "OWLRORA_GEMINI_QUERY_KEY_COMPATIBILITY".to_owned(),
        "true".to_owned(),
    );
    Arc::new(ServerConfig::from_values(&values).unwrap())
}

fn ingress_body(route: &TransportFixture, stream: bool) -> Value {
    match route.ingress {
        "anthropic_messages" => json!({
            "model":route.route_key, "max_tokens":32,
            "messages":[{"role":"user","content":[{"type":"text","text":PROMPT}]}],
            "stream":stream
        }),
        "openai_chat_completions" => json!({
            "model":route.route_key,
            "messages":[{"role":"user","content":PROMPT}],
            "stream":stream, "max_tokens":32
        }),
        "openai_responses" => json!({
            "model":route.route_key, "input":PROMPT,
            "max_output_tokens":32, "stream":stream
        }),
        "google_gemini" => json!({
            "contents":[{"role":"user","parts":[{"text":PROMPT}]}],
            "generationConfig":{"maxOutputTokens":32}
        }),
        _ => unreachable!(),
    }
}

fn ingress_url(address: SocketAddr, route: &TransportFixture, stream: bool) -> String {
    let base = format!("http://{address}");
    match route.ingress {
        "anthropic_messages" => format!("{base}/v1/messages"),
        "openai_chat_completions" => format!("{base}/v1/chat/completions"),
        "openai_responses" => format!("{base}/v1/responses"),
        "google_gemini" if stream => format!(
            "{base}/v1beta/models/{}:streamGenerateContent?alt=sse",
            route.route_key
        ),
        "google_gemini" => format!("{base}/v1beta/models/{}:generateContent", route.route_key),
        _ => unreachable!(),
    }
}

async fn send_gateway_request(
    client: &reqwest::Client,
    address: SocketAddr,
    fixture: &GatewayFixture,
    route: &TransportFixture,
    stream: bool,
) -> reqwest::Response {
    let mut request = client
        .post(ingress_url(address, route, stream))
        .header("x-request-id", "request-fixture")
        .json(&ingress_body(route, stream));
    request = match route.ingress {
        "anthropic_messages" => request
            .header("x-api-key", &fixture.key_wire)
            .header("anthropic-version", "2023-06-01"),
        "google_gemini" => request.header("x-goog-api-key", &fixture.key_wire),
        _ => request.bearer_auth(&fixture.key_wire),
    };
    request.send().await.unwrap()
}

fn assert_recorded_contracts(contracts: &ContractDocument, requests: &[RecordedRequest]) {
    for contract in contracts
        .cases
        .iter()
        .filter(|case| case.transport != "openai_responses_websocket")
    {
        let actual = requests
            .iter()
            .find(|request| {
                request.path_and_query == contract.request.path_and_query
                    && request.method == contract.request.method
                    && request.json == contract.request.json
            })
            .unwrap_or_else(|| panic!("missing replay request for {}", contract.transport));
        assert_eq!(
            actual.method, contract.request.method,
            "{}",
            contract.transport
        );
        assert_eq!(actual.json, contract.request.json, "{}", contract.transport);
        for (name, expected) in &contract.request.headers {
            let actual_value = actual
                .headers
                .get(name)
                .unwrap_or_else(|| panic!("missing {name} for {}", contract.transport));
            if contract.transport == "anthropic_messages_bedrock"
                && matches!(
                    name.as_str(),
                    "authorization" | "x-amz-date" | "x-amz-content-sha256"
                )
            {
                assert!(!actual_value.is_empty());
                if name == "authorization" {
                    assert!(
                        actual_value.starts_with("AWS4-HMAC-SHA256 Credential=AKIDRECORDEDE2E/")
                    );
                }
            } else {
                assert_eq!(
                    actual_value, expected,
                    "{} header {name}",
                    contract.transport
                );
            }
        }
    }
    let websocket_contract = contracts
        .cases
        .iter()
        .find(|case| case.transport == "openai_responses_websocket")
        .unwrap();
    let websocket = requests
        .iter()
        .find(|request| {
            request.method == "GET"
                && request.path_and_query == websocket_contract.request.path_and_query
        })
        .expect("WebSocket replay request was recorded");
    assert_eq!(
        websocket.json,
        Some(serde_json::from_str(&websocket_contract.stream.chunks[0]).unwrap())
    );
    assert_eq!(
        websocket.headers.get("authorization").map(String::as_str),
        Some("Bearer fixture-secret")
    );
}

async fn budget_ledger_snapshot(
    coordinator: &RedisCoordinator,
    candidates: &[PolicyCandidate],
) -> Vec<(Uuid, (u128, u128))> {
    let mut snapshot = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        snapshot.push((
            candidate.policy_id,
            coordinator
                .budget_ledger_totals(candidate)
                .await
                .expect("read test budget ledger"),
        ));
    }
    snapshot.sort_by_key(|(policy_id, _)| *policy_id);
    snapshot
}

async fn usage_totals(store: &PgStore, key_id: Uuid) -> (i64, i64) {
    let logical = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(SUM(request_count), 0)::bigint
         FROM logical_usage_hourly WHERE gateway_api_key_id=$1",
    )
    .bind(key_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let attempts = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(SUM(attempt_count), 0)::bigint
         FROM attempt_usage_hourly WHERE gateway_api_key_id=$1",
    )
    .bind(key_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    (logical, attempts)
}

fn probe_uses_expected_credential(request: &RecordedRequest, credential: &str) -> bool {
    let header = |name: &str| request.headers.get(name).map(String::as_str);
    match credential {
        "anthropic" => header("x-api-key") == Some("fixture-secret"),
        "aws" => {
            header("authorization").is_some_and(|value| value.starts_with("AWS4-HMAC-SHA256 "))
                && header("x-amz-security-token") == Some("recorded-e2e-session")
        }
        "google" => header("authorization") == Some("Bearer fixture-token"),
        "openai" => header("authorization") == Some("Bearer fixture-secret"),
        "codex" => {
            header("authorization") == Some("Bearer fixture-token")
                && header("chatgpt-account-id") == Some("fixture-account")
        }
        "azure" => header("api-key") == Some("fixture-secret"),
        "gemini" => header("x-goog-api-key") == Some("fixture-secret"),
        _ => false,
    }
}

#[tokio::test]
async fn recorded_transports_run_through_postgres_redis_and_gateway_network_e2e() {
    let _database_guard = shared_database_test_lock().await;
    const CHILD_MARKER: &str = "OWLRORA_RECORDED_GATEWAY_E2E_CHILD";
    const TEST_NAME: &str = "gateway::e2e_tests::recorded_transports_run_through_postgres_redis_and_gateway_network_e2e";
    if std::env::var_os(CHILD_MARKER).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(TEST_NAME)
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .env("AWS_ACCESS_KEY_ID", "AKIDRECORDEDE2E")
            .env("AWS_SECRET_ACCESS_KEY", "recorded-e2e-secret")
            .env("AWS_SESSION_TOKEN", "recorded-e2e-session")
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env_remove("AWS_PROFILE")
            .env_remove("AWS_CONFIG_FILE")
            .env_remove("AWS_SHARED_CREDENTIALS_FILE")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "recorded E2E child failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let store = connect_from_environment()
        .await
        .expect("OWLRORA_TEST_DATABASE_URL is required for the provider network E2E test");
    let redis_url = std::env::var("OWLRORA_TEST_REDIS_URL")
        .expect("OWLRORA_TEST_REDIS_URL is required for the provider network E2E test");
    let database_url = std::env::var("OWLRORA_TEST_DATABASE_URL").unwrap();
    let replay = ReplayServer::start().await;
    let stalled_tls = StalledTlsServer::start().await;
    let secret_root = Arc::new(SecretRoot::from_bytes([117_u8; 32]));
    let secrets = SecretService::new(
        Some(secret_root),
        CustodyRegistry::default(),
        CustodyPair::software(),
    )
    .unwrap();
    let fixture = insert_gateway_fixture(&store, &secrets, &replay).await;
    let failed_websocket_target =
        insert_websocket_pre_exposure_failover_target(&store, &fixture, replay.address).await;
    let coordinator = RedisCoordinator::connect(
        &redis_url.parse().unwrap(),
        4,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    for candidate in fixture
        .budget_candidates
        .iter()
        .chain(std::iter::once(&fixture.rate_candidate))
    {
        coordinator.stage_policy(candidate).await.unwrap();
        coordinator.arm_policy(candidate).await.unwrap();
        coordinator.activate_policy(candidate).await.unwrap();
    }
    let probe_budget_baseline =
        budget_ledger_snapshot(&coordinator, &fixture.budget_candidates).await;
    let probe_usage_baseline = usage_totals(&store, fixture.key_id).await;
    let seed_admin_key = generate_management_key().expose_once();
    let config = server_config(database_url.clone(), redis_url.clone(), &seed_admin_key);
    let built = ServerBuilder::new(config)
        .with_test_egress_dns_override("chatgpt.com", replay.address)
        .with_test_egress_dns_override("oauth.owlrora.test", replay.address)
        .with_test_egress_dns_override("connect-stall.owlrora.test", stalled_tls.address)
        .build()
        .await
        .unwrap();
    let application = built.application().unwrap();
    let management_identity = application
        .authenticate_management_key(&seed_admin_key, "gateway-e2e-management".to_owned())
        .unwrap();
    let organization_id = OrganizationId::from_uuid(fixture.organization_id);
    let (original_grants, original_grants_etag) = application
        .get_catalog_grant_set(
            &management_identity,
            organization_id,
            CatalogGrantKind::SystemRoute,
        )
        .await
        .unwrap();
    assert_eq!(original_grants.resource_ids.len(), fixture.routes.len());
    assert_eq!(
        original_grants.system_route_ceilings.len(),
        fixture.routes.len()
    );
    let restricted_route = fixture.route("openai_chat_completions");
    let mut restricted_ceilings = original_grants.system_route_ceilings.clone();
    restricted_ceilings.insert(
        restricted_route.route_id.to_string(),
        SystemRouteGrantCeilings {
            allowed_capabilities: Some(BTreeSet::from([LlmFeatureCapability::Streaming])),
            max_context_bytes: Some(4096),
            max_output_units: Some(16),
            request_policy: RouteGrantRequestPolicyCeilings {
                max_header_bytes: Some(8192),
                max_request_body_bytes: Some(2048),
                max_response_body_bytes: Some(4096),
                max_stream_seconds: Some(30),
                state_origin_ttl_seconds: Some(60),
            },
        },
    );
    let (restricted_grants, restricted_grants_etag) = application
        .update_catalog_grant_set(
            &management_identity,
            organization_id,
            CatalogGrantKind::SystemRoute,
            Some(original_grants_etag.as_str()),
            UpdateCatalogGrantSet {
                resource_ids: original_grants.resource_ids.clone(),
                system_route_ceilings: restricted_ceilings,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        restricted_grants.system_route_ceilings[&restricted_route.route_id.to_string()]
            .max_output_units,
        Some(16)
    );
    application.runtime().refresh_now().await.unwrap();
    let mut gateway_headers = http::HeaderMap::new();
    gateway_headers.insert(
        "authorization",
        http::HeaderValue::from_str(&format!("Bearer {}", fixture.key_wire)).unwrap(),
    );
    let restricted_admission = super::authenticate_and_admit(
        &application,
        IngressProtocolFamily::OpenaiChatCompletions,
        &gateway_headers,
        &LlmIntent {
            model_key: restricted_route.route_key.clone(),
            response_mode: ResponseMode::Sse,
            required_scopes: LlmScopeSet::new([LlmScope::Invoke, LlmScope::Stream]).unwrap(),
            required_capabilities: BTreeSet::from([LlmFeatureCapability::Streaming]),
            requested_output_bound: Some(16),
            continuation_reference: None,
            replay_safe: true,
        },
        "gateway-e2e-route-grant-narrowing".to_owned(),
    )
    .unwrap();
    assert_eq!(
        restricted_admission
            .effective_request_policy
            .max_header_bytes,
        8192
    );
    assert_eq!(
        restricted_admission
            .effective_request_policy
            .max_request_body_bytes,
        2048
    );
    assert_eq!(
        restricted_admission
            .effective_request_policy
            .max_output_units,
        16
    );
    assert_eq!(
        restricted_admission.route.required_base_capabilities,
        BTreeSet::from([LlmFeatureCapability::DocumentInput])
    );
    assert_eq!(restricted_admission.candidates.len(), 1);
    assert!(restricted_admission.candidates.iter().all(|candidate| {
        candidate
            .deployment
            .capabilities
            .contains(&LlmFeatureCapability::DocumentInput)
    }));
    let principal_capability_denied = super::authenticate_and_admit(
        &application,
        IngressProtocolFamily::OpenaiChatCompletions,
        &gateway_headers,
        &LlmIntent {
            model_key: restricted_route.route_key.clone(),
            response_mode: ResponseMode::Json,
            required_scopes: LlmScopeSet::new([LlmScope::Invoke]).unwrap(),
            required_capabilities: BTreeSet::from([LlmFeatureCapability::Tools]),
            requested_output_bound: Some(16),
            continuation_reference: None,
            replay_safe: true,
        },
        "gateway-e2e-principal-capability-deny".to_owned(),
    )
    .unwrap_err();
    assert_eq!(
        principal_capability_denied.kind,
        ProtocolErrorKind::Forbidden
    );

    let mut denied_ceilings = restricted_grants.system_route_ceilings.clone();
    denied_ceilings
        .get_mut(&restricted_route.route_id.to_string())
        .unwrap()
        .allowed_capabilities = Some(BTreeSet::new());
    let (_, denied_grants_etag) = application
        .update_catalog_grant_set(
            &management_identity,
            organization_id,
            CatalogGrantKind::SystemRoute,
            Some(restricted_grants_etag.as_str()),
            UpdateCatalogGrantSet {
                resource_ids: restricted_grants.resource_ids.clone(),
                system_route_ceilings: denied_ceilings,
            },
        )
        .await
        .unwrap();
    let denied = super::authenticate_and_admit(
        &application,
        IngressProtocolFamily::OpenaiChatCompletions,
        &gateway_headers,
        &LlmIntent {
            model_key: restricted_route.route_key.clone(),
            response_mode: ResponseMode::Sse,
            required_scopes: LlmScopeSet::new([LlmScope::Invoke, LlmScope::Stream]).unwrap(),
            required_capabilities: BTreeSet::from([LlmFeatureCapability::Streaming]),
            requested_output_bound: Some(16),
            continuation_reference: None,
            replay_safe: true,
        },
        "gateway-e2e-route-grant-capability-deny".to_owned(),
    )
    .unwrap_err();
    assert_eq!(denied.kind, ProtocolErrorKind::Forbidden);
    application
        .update_catalog_grant_set(
            &management_identity,
            organization_id,
            CatalogGrantKind::SystemRoute,
            Some(denied_grants_etag.as_str()),
            UpdateCatalogGrantSet {
                resource_ids: original_grants.resource_ids,
                system_route_ceilings: original_grants.system_route_ceilings,
            },
        )
        .await
        .unwrap();

    let (mut organization_policy, organization_policy_etag) = application
        .get_organization_api_key_policy(&management_identity, organization_id)
        .await
        .unwrap();
    organization_policy.policy["gateway"]["budget"]["max_limit_cost_nanos"] = json!("1");
    assert!(matches!(
        application
            .update_organization_api_key_policy(
                &management_identity,
                organization_id,
                Some(&organization_policy_etag.to_string()),
                UpdateOrganizationApiKeyPolicy {
                    policy: UpdateField::Value(organization_policy.policy),
                },
            )
            .await,
        Err(ApplicationError::Conflict(_))
    ));
    let (_, ceilings_etag) = application
        .get_gateway_policy_ceilings(&management_identity)
        .await
        .unwrap();
    let ceiling_tightening = application
        .update_gateway_policy_ceilings(
            &management_identity,
            Some(&ceilings_etag.to_string()),
            UpdateGatewayPolicyCeilings {
                key_budget_max_limit_cost_nanos: UpdateField::Value("1".to_owned()),
                ..UpdateGatewayPolicyCeilings::default()
            },
        )
        .await;
    assert!(
        matches!(ceiling_tightening, Err(ApplicationError::Conflict(_))),
        "deployment ceiling tightening should reject incompatible policies: {ceiling_tightening:?}"
    );
    let key_id = GatewayKeyId::from_uuid(fixture.key_id);
    let (_, budget_etag) = application
        .get_gateway_key_budget(&management_identity, organization_id, key_id)
        .await
        .unwrap();
    let budget_update = || UpdateBudgetPolicy {
        limit_cost_nanos: UpdateField::Value("1000000001".to_owned()),
        ..UpdateBudgetPolicy::default()
    };
    let budget_expansion = application
        .update_gateway_key_budget(
            &management_identity,
            organization_id,
            key_id,
            Some(&budget_etag.to_string()),
            budget_update(),
        )
        .await;
    let budget_expansion = match budget_expansion {
        Err(ApplicationError::Stale {
            current_etag: Some(current_etag),
        }) => {
            application
                .update_gateway_key_budget(
                    &management_identity,
                    organization_id,
                    key_id,
                    Some(&current_etag),
                    budget_update(),
                )
                .await
        }
        result => result,
    };
    assert!(
        matches!(budget_expansion, Err(ApplicationError::Validation(_))),
        "organization budget ceiling should reject key expansion: {budget_expansion:?}"
    );
    let (_, limits_etag) = application
        .get_gateway_key_limits(&management_identity, organization_id, key_id)
        .await
        .unwrap();
    assert!(matches!(
        application
            .update_gateway_key_limits(
                &management_identity,
                organization_id,
                key_id,
                Some(&limits_etag.to_string()),
                UpdateGatewayRequestLimits {
                    limits: UpdateField::Value(GatewayRequestLimitsInput {
                        epoch: "fixture-rate-epoch-invalid".to_owned(),
                        requests_per_minute: 1001,
                        input_units_per_minute: Some(1_000_000),
                        grant_mode: "local_grants".to_owned(),
                        grant_policy: json!({
                            "max_request_tokens": 10,
                            "grant_seconds": 1
                        }),
                        concurrency_mode: None,
                        concurrency_limit: None,
                        lease_seconds: None,
                        max_stream_seconds: 3600,
                    }),
                    status: UpdateField::Value(CatalogStatus::Active),
                },
            )
            .await,
        Err(ApplicationError::Validation(_))
    ));
    let generation = built.runtime().unwrap().capture();
    let verifier = generation
        .snapshot
        .gateway_keys
        .values()
        .find(|verifier| verifier.key_id.as_uuid() == fixture.key_id)
        .expect("fixture Gateway key verifier");
    assert_eq!(
        verifier.capabilities,
        BTreeSet::from([crate::domain::LlmFeatureCapability::Streaming]),
        "Gateway key verifier must carry the effective organization capability ceiling"
    );
    for route in &fixture.routes {
        assert!(
            generation
                .snapshot
                .catalog
                .deployments
                .get(&crate::domain::DeploymentId::from_uuid(route.deployment_id))
                .is_some_and(|deployment| deployment.operational),
            "deployment is not operational: {}",
            route.transport
        );
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let gateway_address = listener.local_addr().unwrap();
    let (shutdown_sender, shutdown) = oneshot::channel();
    let gateway = tokio::spawn(async move {
        built
            .serve_with_shutdown(listener, async move {
                let _ = shutdown.await;
            })
            .await
            .unwrap();
    });
    let client = reqwest::Client::new();
    let mut expected_probe_credentials = fixture
        .routes
        .iter()
        .map(|route| (route.target_id, route.credential))
        .collect::<HashMap<_, _>>();
    expected_probe_credentials.insert(failed_websocket_target, "openai");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let observed = replay
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|request| request.method == "HEAD" && request.path_and_query == "/health")
                .filter_map(|request| {
                    request
                        .headers
                        .get("x-owlrora-test-probe-target")
                        .and_then(|value| Uuid::parse_str(value).ok())
                })
                .collect::<HashSet<_>>();
            if expected_probe_credentials
                .keys()
                .all(|target_id| observed.contains(target_id))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("every distinct recorded target binding should receive an active HEAD probe");
    let probe_requests = replay
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|request| request.method == "HEAD" && request.path_and_query == "/health")
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        probe_requests.iter().all(|request| request.json.is_none()),
        "active probes must never carry a billable model request body"
    );
    for (target_id, credential) in &expected_probe_credentials {
        let target_id = target_id.to_string();
        let request = probe_requests
            .iter()
            .find(|request| request.headers.get("x-owlrora-test-probe-target") == Some(&target_id))
            .expect("distinct target probe request");
        assert!(
            probe_uses_expected_credential(request, credential),
            "target {target_id} did not use its exact generation-bound {credential} credential"
        );
    }
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert_eq!(
        budget_ledger_snapshot(&coordinator, &fixture.budget_candidates).await,
        probe_budget_baseline,
        "active probes must not charge or return Gateway budget allowance"
    );
    assert_eq!(
        usage_totals(&store, fixture.key_id).await,
        probe_usage_baseline,
        "active probes must not enter logical or attempt usage aggregates"
    );

    let slow_route = fixture.route("openai_chat_completions");
    let prior_generation = application.runtime().capture();
    let prior_deployment = prior_generation
        .snapshot
        .catalog
        .deployments
        .get(&crate::domain::DeploymentId::from_uuid(
            slow_route.deployment_id,
        ))
        .unwrap();
    let prior_client = prior_generation
        .credential_clients
        .clients
        .get(&prior_deployment.client_key())
        .unwrap()
        .clone();
    narrow_target_connect_timeout(&store, slow_route.target_id, 100).await;
    application.runtime().refresh_now().await.unwrap();
    let narrowed_generation = application.runtime().capture();
    let narrowed_deployment = narrowed_generation
        .snapshot
        .catalog
        .deployments
        .get(&crate::domain::DeploymentId::from_uuid(
            slow_route.deployment_id,
        ))
        .unwrap();
    let narrowed_client = narrowed_generation
        .credential_clients
        .clients
        .get(&narrowed_deployment.client_key())
        .unwrap();
    assert!(
        Arc::ptr_eq(&prior_client, narrowed_client),
        "route-local connect timeouts must not split or rebuild the shared endpoint client pool"
    );
    let slow_body = json!({
        "model":slow_route.route_key,
        "messages":[{"role":"user","content":SLOW_PHASE_PROMPT}],
        "stream":false,
        "max_tokens":32
    });
    for request_number in 1..=2 {
        let started = tokio::time::Instant::now();
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            client
                .post(ingress_url(gateway_address, slow_route, false))
                .bearer_auth(&fixture.key_wire)
                .json(&slow_body)
                .send(),
        )
        .await
        .expect("route connect timeout must not cap a slow provider response header")
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = tokio::time::timeout(Duration::from_secs(2), response.bytes())
            .await
            .expect("route connect timeout must not cap a slow provider response body")
            .unwrap();
        assert!(
            body.windows(b"fixture-ok".len())
                .any(|value| value == b"fixture-ok")
        );
        assert!(
            started.elapsed() >= Duration::from_millis(450),
            "slow response {request_number} did not exercise both delayed header and body phases"
        );
    }
    let slow_requests = replay
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|request| {
            request.json.as_ref().is_some_and(|value| {
                value["messages"][0]["content"].as_str() == Some(SLOW_PHASE_PROMPT)
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(slow_requests.len(), 2);
    assert_eq!(
        slow_requests
            .iter()
            .map(|request| request.connection_id)
            .collect::<BTreeSet<_>>()
            .len(),
        1,
        "narrow connect-timeout variants must preserve healthy connection pooling"
    );

    let stalled_targets =
        insert_stalled_connect_targets(&store, &fixture, failed_websocket_target).await;
    application.runtime().refresh_now().await.unwrap();
    let http_connections_before = stalled_tls.accepted_connections();
    let connect_timeout_started = tokio::time::Instant::now();
    let connect_timeout_response = tokio::time::timeout(
        Duration::from_secs(2),
        send_gateway_request(
            &client,
            gateway_address,
            &fixture,
            fixture.route("openai_chat_completions"),
            false,
        ),
    )
    .await
    .expect("HTTP route connect timeout must preempt the 10 second endpoint connect timeout");
    assert_eq!(connect_timeout_response.status(), StatusCode::OK);
    assert!(
        connect_timeout_started.elapsed() < Duration::from_secs(2),
        "HTTP failover exceeded the route-local connect timeout bound"
    );
    assert!(
        stalled_tls.accepted_connections() > http_connections_before,
        "HTTP route did not exercise the stalled TLS connection"
    );

    let websocket_connections_before = stalled_tls.accepted_connections();
    let mut request = format!("ws://{gateway_address}/v1/responses")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "authorization",
        http::HeaderValue::from_str(&format!("Bearer {}", fixture.key_wire)).unwrap(),
    );
    let (mut connect_timeout_websocket, _) =
        tokio_tungstenite::connect_async(request).await.unwrap();
    let websocket_connect_started = tokio::time::Instant::now();
    connect_timeout_websocket
        .send(Message::Text(
            json!({
                "type":"response.create",
                "model":fixture.route("openai_responses_websocket").route_key,
                "input":PROMPT,
                "max_output_tokens":32
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let first_frame =
        tokio::time::timeout(Duration::from_secs(2), connect_timeout_websocket.next())
            .await
            .expect(
                "Responses WebSocket connect timeout must fail over before the endpoint timeout",
            )
            .expect("Responses WebSocket closed before failover")
            .unwrap();
    let Message::Text(first_frame) = first_frame else {
        panic!("expected a Responses WebSocket text frame after connect-timeout failover");
    };
    assert_eq!(
        serde_json::from_str::<Value>(&first_frame).unwrap()["type"],
        "response.created"
    );
    assert!(
        websocket_connect_started.elapsed() < Duration::from_secs(2),
        "Responses WebSocket failover exceeded the route-local connect timeout bound"
    );
    assert!(
        stalled_tls.accepted_connections() > websocket_connections_before,
        "Responses WebSocket route did not exercise the stalled TLS connection"
    );
    drop(connect_timeout_websocket);
    remove_stalled_connect_targets(&store, &stalled_targets).await;
    application.runtime().refresh_now().await.unwrap();

    let contracts: ContractDocument = serde_json::from_str(CONTRACTS).unwrap();
    for contract in contracts
        .cases
        .iter()
        .filter(|case| case.transport != "openai_responses_websocket")
    {
        assert_eq!(contract.response.status, 200);
        let route = fixture.route(&contract.transport);
        let response = send_gateway_request(&client, gateway_address, &fixture, route, false).await;
        let status = response.status();
        let body = response.bytes().await.unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "{}: {}; replay requests: {:?}",
            contract.transport,
            String::from_utf8_lossy(&body),
            replay.requests.lock().unwrap()
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            rewrite_state_id_json(&contract.transport, contract.response.json.clone().unwrap()),
            "{}",
            contract.transport
        );
    }

    let gemini_route = fixture.route("google_gemini_generate_content");
    let mut gemini_query_url =
        url::Url::parse(&ingress_url(gateway_address, gemini_route, false)).unwrap();
    gemini_query_url
        .query_pairs_mut()
        .append_pair("key", &fixture.key_wire);
    let query_authenticated = client
        .post(gemini_query_url.clone())
        .json(&ingress_body(gemini_route, false))
        .send()
        .await
        .unwrap();
    assert_eq!(query_authenticated.status(), StatusCode::OK);
    let conflicting = client
        .post(gemini_query_url)
        .header("authorization", format!("Bearer {}", fixture.key_wire))
        .json(&ingress_body(gemini_route, false))
        .send()
        .await
        .unwrap();
    assert_eq!(conflicting.status(), StatusCode::UNAUTHORIZED);
    let conflicting_body: Value = conflicting.json().await.unwrap();
    assert_eq!(conflicting_body["error"]["status"], "UNAUTHENTICATED");

    for transport in [
        "anthropic_messages_native",
        "anthropic_messages_bedrock",
        "openai_chat_completions",
        "openai_responses_http",
        "google_gemini_generate_content",
    ] {
        let response = send_gateway_request(
            &client,
            gateway_address,
            &fixture,
            fixture.route(transport),
            true,
        )
        .await;
        let status = response.status();
        let body = response.bytes().await.unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "{transport}: {}",
            String::from_utf8_lossy(&body)
        );
        assert!(
            body.windows(b"fixture-ok".len())
                .any(|window| window == b"fixture-ok")
        );
    }

    let websocket_route = fixture.route("openai_responses_websocket");
    let mut request = format!("ws://{gateway_address}/v1/responses")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "authorization",
        http::HeaderValue::from_str(&format!("Bearer {}", fixture.key_wire)).unwrap(),
    );
    let (mut websocket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    websocket
        .send(Message::Text(
            json!({
                "type":"response.create",
                "model":websocket_route.route_key,
                "input":PROMPT,
                "max_output_tokens":32
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let mut websocket_frames = Vec::new();
    while let Some(frame) = websocket.next().await {
        let frame = frame.unwrap();
        if let Message::Text(text) = frame {
            let value: Value = serde_json::from_str(&text).unwrap();
            let terminal = value["type"] == "response.completed";
            websocket_frames.push(value);
            if terminal {
                break;
            }
        }
    }
    assert_eq!(
        websocket_frames.len(),
        3,
        "unexpected first-turn WebSocket frames: {websocket_frames:#?}"
    );
    assert_eq!(websocket_frames[0]["type"], "response.created");
    assert_eq!(websocket_frames[2]["response"]["usage"]["output_tokens"], 5);
    let first_response_id = websocket_frames[0]["response"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    websocket
        .send(Message::Text(
            json!({
                "type":"response.create",
                "model":websocket_route.route_key,
                "input":PROMPT,
                "previous_response_id":first_response_id,
                "max_output_tokens":32
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let mut second_turn = Vec::new();
    while let Some(frame) = websocket.next().await {
        let frame = frame.unwrap();
        if let Message::Text(text) = frame {
            let value: Value = serde_json::from_str(&text).unwrap();
            let terminal = value["type"] == "response.completed";
            second_turn.push(value);
            if terminal {
                break;
            }
        }
    }
    assert_eq!(second_turn.len(), 3);
    let second_response_id = second_turn[0]["response"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(first_response_id, second_response_id);

    websocket
        .send(Message::Text(
            json!({
                "type":"response.create",
                "model":websocket_route.route_key,
                "input":"cancel-fixture",
                "previous_response_id":second_response_id,
                "max_output_tokens":32
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let created = loop {
        let frame = websocket.next().await.unwrap().unwrap();
        if let Message::Text(text) = frame {
            let value: Value = serde_json::from_str(&text).unwrap();
            if value["type"] == "response.created" {
                break value;
            }
        }
    };
    let active_response_id = created["response"]["id"].as_str().unwrap().to_owned();
    websocket
        .send(Message::Text(
            json!({
                "type":"response.cancel",
                "response_id":active_response_id
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let cancelled = loop {
        let frame = websocket.next().await.unwrap().unwrap();
        if let Message::Text(text) = frame {
            let value: Value = serde_json::from_str(&text).unwrap();
            if value["type"] == "response.cancelled" {
                break value;
            }
        }
    };
    assert_eq!(cancelled["response"]["id"], active_response_id);

    websocket
        .send(Message::Text(
            json!({
                "type":"response.create",
                "model":websocket_route.route_key,
                "input":STREAM_LIMIT_PROMPT,
                "previous_response_id":second_response_id,
                "max_output_tokens":32
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let limited_created = tokio::time::timeout(Duration::from_millis(500), websocket.next())
        .await
        .expect("the key-limited turn should expose its first frame")
        .unwrap()
        .unwrap();
    assert!(matches!(limited_created, Message::Text(_)));
    let limited_terminal = tokio::time::timeout(Duration::from_millis(1_500), websocket.next())
        .await
        .expect("Responses WebSocket must enforce the Gateway-key stream limit");
    if let Some(Ok(Message::Text(text))) = limited_terminal {
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_ne!(value["type"], "response.completed");
    }
    drop(websocket);

    let interrupted_route = fixture.route("openai_chat_completions");
    let (_, before_interrupted_flush) = application.usage.flush_now().await;
    assert!(before_interrupted_flush.last_flush_error.is_none());
    let ambiguous_before = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(sum(attempt_count),0)::bigint
         FROM attempt_usage_hourly
         WHERE gateway_api_key_id=$1 AND target_id=$2
           AND terminal_class='unknown_or_ambiguous'",
    )
    .bind(fixture.key_id)
    .bind(interrupted_route.target_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let mut interrupted_body = ingress_body(interrupted_route, true);
    interrupted_body["messages"][0]["content"] = json!(INTERRUPTED_STREAM_PROMPT);
    let interrupted = client
        .post(ingress_url(gateway_address, interrupted_route, true))
        .bearer_auth(&fixture.key_wire)
        .json(&interrupted_body)
        .send()
        .await;
    if let Ok(interrupted) = interrupted {
        assert_eq!(interrupted.status(), StatusCode::OK);
        assert!(
            interrupted.bytes().await.is_err(),
            "a nonterminal upstream SSE EOF must terminate the downstream body with an error"
        );
    }
    assert!(replay.requests.lock().unwrap().iter().any(|request| {
        request.json.as_ref().is_some_and(|value| {
            value["messages"][0]["content"].as_str() == Some(INTERRUPTED_STREAM_PROMPT)
        })
    }));
    let interrupted_admission = super::authenticate_and_admit(
        &application,
        IngressProtocolFamily::OpenaiChatCompletions,
        &gateway_headers,
        &LlmIntent {
            model_key: interrupted_route.route_key.clone(),
            response_mode: ResponseMode::Sse,
            required_scopes: LlmScopeSet::new([LlmScope::Invoke, LlmScope::Stream]).unwrap(),
            required_capabilities: BTreeSet::from([LlmFeatureCapability::Streaming]),
            requested_output_bound: Some(16),
            continuation_reference: None,
            replay_safe: true,
        },
        "gateway-e2e-interrupted-stream-health".to_owned(),
    )
    .unwrap();
    assert!(matches!(
        application
            .target_protection
            .local_health(&interrupted_admission.candidates[0])
            .category,
        TargetHealthCategory::Degraded | TargetHealthCategory::Open
    ));
    let (_, after_interrupted_flush) = application.usage.flush_now().await;
    assert!(after_interrupted_flush.last_flush_error.is_none());
    let ambiguous_after = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(sum(attempt_count),0)::bigint
         FROM attempt_usage_hourly
         WHERE gateway_api_key_id=$1 AND target_id=$2
           AND terminal_class='unknown_or_ambiguous'",
    )
    .bind(fixture.key_id)
    .bind(interrupted_route.target_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(ambiguous_after, ambiguous_before + 1);

    let later_response =
        send_gateway_request(&client, gateway_address, &fixture, interrupted_route, false).await;
    assert_eq!(later_response.status(), StatusCode::OK);
    assert_eq!(
        later_response.json::<Value>().await.unwrap()["choices"][0]["message"]["content"],
        "fixture-ok"
    );

    let organization_id = OrganizationId::from_uuid(fixture.organization_id);
    let gateway_key_id = GatewayKeyId::from_uuid(fixture.key_id);
    let (_, initial_etag) = application
        .get_gateway_api_key(&management_identity, organization_id, gateway_key_id)
        .await
        .unwrap();
    let (first_rotation, first_etag) = application
        .rotate_gateway_api_key(
            &management_identity,
            organization_id,
            gateway_key_id,
            Some(initial_etag.as_str()),
            RotateGatewayApiKey {
                overlap_seconds: 60,
            },
        )
        .await
        .unwrap();
    let (second_rotation, _) = application
        .rotate_gateway_api_key(
            &management_identity,
            organization_id,
            gateway_key_id,
            Some(first_etag.as_str()),
            RotateGatewayApiKey {
                overlap_seconds: 60,
            },
        )
        .await
        .unwrap();
    assert_ne!(first_rotation.key, second_rotation.key);
    let version_counts = sqlx::query(
        "SELECT count(*) FILTER (WHERE state='current') AS current_count,
                count(*) FILTER (WHERE state='overlap') AS overlap_count,
                count(*) FILTER (WHERE state='retired') AS retired_count
         FROM gateway_api_key_secret_versions WHERE gateway_api_key_id=$1",
    )
    .bind(fixture.key_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        version_counts.try_get::<i64, _>("current_count").unwrap(),
        1
    );
    assert_eq!(
        version_counts.try_get::<i64, _>("overlap_count").unwrap(),
        1
    );
    assert_eq!(
        version_counts.try_get::<i64, _>("retired_count").unwrap(),
        1
    );

    let recovery = application
        .create_coordinator_recoveries(
            &management_identity,
            &CreateCoordinatorRecoveries {
                incident_reference: format!("recorded-e2e-{}", Uuid::now_v7()),
                reason: "Recorded coordinator state-loss recovery E2E".to_owned(),
                safe_evidence: json!({
                    "verified_state_loss":false,
                    "source":"recorded_gateway_e2e"
                }),
                allocations: fixture
                    .budget_candidates
                    .iter()
                    .map(|candidate| CoordinatorRecoveryAllocation {
                        organization_id: candidate.organization_id,
                        policy_kind: match candidate.kind {
                            PolicyKind::GatewayKeyBudget => RecoveryPolicyKind::GatewayKeyBudget,
                            PolicyKind::OrganizationOriginBudget => {
                                RecoveryPolicyKind::OrganizationOriginBudget
                            }
                            PolicyKind::GatewayKeyRequestLimits => unreachable!(),
                        },
                        policy_id: candidate.policy_id,
                        authorized_allowance_nanos: "0".to_owned(),
                    })
                    .collect(),
            },
        )
        .await
        .unwrap();
    assert!(recovery["items"].as_array().is_some_and(|items| {
        items.len() == 2
            && items
                .iter()
                .all(|item| item["installation_status"] == "installed")
    }));
    let installed_recoveries = sqlx::query_scalar::<_, i64>(
        "SELECT count(*)
         FROM coordinator_recovery_installations installation
         JOIN coordinator_recoveries recovery ON recovery.id=installation.recovery_id
         WHERE recovery.organization_id=$1 AND installation.status='installed'",
    )
    .bind(fixture.organization_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(installed_recoveries, 2);
    let recovered_generation = application.runtime().capture();
    for candidate in &fixture.budget_candidates {
        let policy = recovered_generation
            .snapshot
            .catalog
            .key_budget_policies
            .get(&crate::domain::BudgetPolicyId::from_uuid(
                candidate.policy_id,
            ))
            .map_or_else(
                || {
                    recovered_generation
                        .snapshot
                        .organizations
                        .get(&candidate.organization_id)
                        .and_then(|organization| {
                            organization
                                .origin_budgets
                                .values()
                                .find(|policy| policy.id.as_uuid() == candidate.policy_id)
                        })
                },
                Some,
            )
            .unwrap();
        assert_eq!(
            policy.active_version.as_ref().unwrap().recovery_generation,
            1
        );
    }

    let _ = shutdown_sender.send(());
    gateway.await.unwrap();

    let current_day = chrono::Utc::now()
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .and_utc();
    let usage_query = UsageQuery {
        start: current_day - chrono::Duration::days(1),
        end: current_day + chrono::Duration::days(2),
        granularity: UsageGranularity::Hour,
        organization_id: Some(fixture.organization_id),
        principal_kind: None,
        user_id: None,
        gateway_api_key_id: Some(fixture.key_id),
        route_id: None,
        target_id: None,
        origin: None,
        deployment_id: None,
        endpoint_id: None,
        credential_id: None,
        outcome: None,
    };
    let usage = application
        .get_system_usage(&management_identity, &usage_query)
        .await
        .unwrap();
    let queried_logical_count = usage
        .logical_requests
        .items
        .iter()
        .map(|bucket| bucket.request_count.parse::<u64>().unwrap())
        .sum::<u64>();
    let queried_attempt_count = usage
        .attempts
        .items
        .iter()
        .map(|bucket| bucket.attempt_count.parse::<u64>().unwrap())
        .sum::<u64>();
    assert_eq!(queried_logical_count, 26);
    assert_eq!(queried_attempt_count, 32);
    assert!(!usage.completeness.includes_unflushed_process_facts);
    let origin_breakdown = application
        .get_system_usage_breakdown(
            &management_identity,
            &UsageBreakdownQuery {
                usage: usage_query,
                fact_family: UsageFactFamily::Attempts,
                dimension: UsageBreakdownDimension::Origin,
                order: UsageBreakdownOrder::CountDesc,
                limit: Some(10),
            },
        )
        .await
        .unwrap();
    assert_eq!(origin_breakdown.items.len(), 1);
    assert_eq!(
        origin_breakdown.items[0].dimension_value.as_deref(),
        Some("system_provided")
    );
    assert_eq!(origin_breakdown.items[0].measures.count, "32");

    let logical_request_count = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(sum(request_count),0)::bigint
         FROM logical_usage_hourly WHERE gateway_api_key_id=$1",
    )
    .bind(fixture.key_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let attempt_count = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(sum(attempt_count),0)::bigint
         FROM attempt_usage_hourly WHERE gateway_api_key_id=$1",
    )
    .bind(fixture.key_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(logical_request_count, 26);
    assert_eq!(attempt_count, 32);
    let stalled_connect_attempts = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(sum(attempt_count),0)::bigint
         FROM attempt_usage_hourly
         WHERE gateway_api_key_id=$1 AND target_id=ANY($2)
           AND terminal_class='definitely_not_dispatched'",
    )
    .bind(fixture.key_id)
    .bind(stalled_targets.target_ids.to_vec())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        stalled_connect_attempts, 4,
        "HTTP and Responses WebSocket must each classify and retry one route-local connect timeout"
    );
    let failed_websocket_attempts = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(sum(attempt_count),0)::bigint
         FROM attempt_usage_hourly
         WHERE gateway_api_key_id=$1 AND target_id=$2
           AND terminal_class='unknown_or_ambiguous'",
    )
    .bind(fixture.key_id)
    .bind(failed_websocket_target)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(failed_websocket_attempts, 2);

    let (created_key, created_key_etag) = application
        .create_gateway_api_key(
            &management_identity,
            OrganizationId::from_uuid(fixture.organization_id),
            CreateGatewayApiKey {
                name: "Recorded E2E created key".to_owned(),
                scopes: LlmScopeSet::new([LlmScope::Invoke]).unwrap(),
                route_ids: BTreeSet::from([RouteId::from_uuid(fixture.routes[0].route_id)]),
                budget: GatewayBudgetInput {
                    limit_cost_nanos: "100000000".to_owned(),
                    mode: BudgetMode::Enforce,
                    epoch: format!("created-e2e-{}", Uuid::now_v7()),
                    estimate_policy: json!({}),
                    allowance_policy: json!({}),
                    failure_policy: json!({}),
                    recovery_policy: json!({}),
                },
                expires_at: None,
            },
        )
        .await
        .unwrap();
    crate::domain::GatewayKeyMaterial::parse(&created_key.key).unwrap();
    let created_limit = sqlx::query_scalar::<_, String>(
        "SELECT version.limit_cost_nanos::text
         FROM gateway_key_budget_policies policy
         JOIN budget_policy_versions version ON version.id=policy.desired_version_id
         WHERE policy.gateway_api_key_id=$1",
    )
    .bind(created_key.gateway_api_key.id.as_uuid())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(created_limit, "100000000");

    let key_id = created_key.gateway_api_key.id;
    let renamed = application
        .update_gateway_api_key(
            &management_identity,
            OrganizationId::from_uuid(fixture.organization_id),
            key_id,
            Some(&created_key_etag.to_string()),
            UpdateGatewayApiKey {
                name: UpdateField::Value("Renamed before activation".to_owned()),
                ..UpdateGatewayApiKey::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(renamed.0.name, "Renamed before activation");
    let disabled = application
        .update_gateway_api_key(
            &management_identity,
            OrganizationId::from_uuid(fixture.organization_id),
            key_id,
            Some(&renamed.1.to_string()),
            UpdateGatewayApiKey {
                status: UpdateField::Value(KeyStatus::Disabled),
                ..UpdateGatewayApiKey::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(disabled.0.status, KeyStatus::Disabled);
    let revoked = application
        .update_gateway_api_key(
            &management_identity,
            OrganizationId::from_uuid(fixture.organization_id),
            key_id,
            Some(&disabled.1.to_string()),
            UpdateGatewayApiKey {
                status: UpdateField::Value(KeyStatus::Revoked),
                ..UpdateGatewayApiKey::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(revoked.0.status, KeyStatus::Revoked);

    let rebuilt = ServerBuilder::new(server_config(database_url, redis_url, &seed_admin_key))
        .with_test_egress_dns_override("chatgpt.com", replay.address)
        .with_test_egress_dns_override("oauth.owlrora.test", replay.address)
        .with_test_egress_dns_override("connect-stall.owlrora.test", stalled_tls.address)
        .build()
        .await
        .unwrap();
    let restarted_generation = rebuilt.runtime().unwrap().capture();
    let created_policy_id = crate::domain::BudgetPolicyId::from_uuid(
        Uuid::parse_str(&created_key.gateway_api_key.budget_policy_id).unwrap(),
    );
    let created_policy = restarted_generation
        .snapshot
        .catalog
        .key_budget_policies
        .get(&created_policy_id)
        .unwrap();
    assert!(created_policy.active);
    assert!(
        restarted_generation
            .snapshot
            .gateway_keys
            .values()
            .filter(|verifier| verifier.key_id == key_id)
            .all(|verifier| !verifier.active),
        "a revoked key may retain constant-time verifier material but must never be active after restart"
    );

    let requests = replay.requests.lock().unwrap().clone();
    assert_recorded_contracts(&contracts, &requests);
    let websocket_path = &contracts
        .cases
        .iter()
        .find(|case| case.transport == "openai_responses_websocket")
        .unwrap()
        .request
        .path_and_query;
    let healthy_websocket_requests = requests
        .iter()
        .filter(|request| {
            request.path_and_query == *websocket_path
                && request.method != "POST"
                && !request.headers.contains_key("x-replay-mode")
        })
        .collect::<Vec<_>>();
    let main_websocket_connection_id = healthy_websocket_requests
        .iter()
        .find(|request| {
            request.json.as_ref().is_some_and(|value| {
                value.get("previous_response_id").and_then(Value::as_str)
                    == Some(first_response_id.as_str())
                    && value.get("input").and_then(Value::as_str) == Some(PROMPT)
            })
        })
        .expect("the main Responses WebSocket continuation was recorded")
        .connection_id;
    let main_websocket_requests = healthy_websocket_requests
        .iter()
        .filter(|request| request.connection_id == main_websocket_connection_id)
        .collect::<Vec<_>>();
    assert!(
        main_websocket_requests.len() >= 5,
        "all successful Responses turns and cancel must use one physical upstream socket: {main_websocket_requests:?}"
    );
    assert_eq!(
        main_websocket_requests
            .iter()
            .map(|request| request.connection_id)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([main_websocket_connection_id])
    );
    assert!(
        requests.iter().any(|request| {
            request.path_and_query == "/oauth/token" && request.method == "POST"
        }),
        "Google service-account OAuth exchange was not replayed"
    );

    stalled_tls.shutdown().await;
    replay.shutdown().await;
    fs::remove_dir_all(fixture.temp_dir).unwrap();
}
