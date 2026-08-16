use std::{sync::Arc, time::Duration};

use axum::{
    body::Bytes,
    extract::ws::{CloseFrame, Message as DownstreamMessage, WebSocket, WebSocketUpgrade},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{Value, json};
use tokio::time::{Instant, timeout};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message as UpstreamMessage,
        handshake::{client::generate_key, derive_accept_key},
        protocol::{Role, WebSocketConfig},
    },
};
use uuid::Uuid;

use crate::{
    adapters::provider::wire::{
        adapt_provider_body, extract_json_usage, response_state_id, upstream_url,
    },
    application::Application,
    domain::{IngressProtocolFamily, RouteId, TransportKind},
    protocols::{
        NativeRequest, ProtocolError, ProtocolErrorKind, ResponsesWebSocketClientEvent,
        parse_openai_responses_websocket_event,
    },
    runtime::{CredentialClient, CredentialInjection, ReliabilityPolicySnapshot, RetryCondition},
};

use super::{
    AdmissionContext, Candidate, GatewayPrincipal, LogicalRequestPermit, TargetAttemptPermit,
    authenticate_and_admit, authenticate_websocket_connection,
    dispatch::{
        AttemptTelemetry, LogicalTelemetry, UpstreamStatusFailure, candidate_policy_ready,
        candidates_for_request, classify_pre_header_transport_error, classify_upstream_status,
        effective_stream_duration_limit, gateway_error, logical_admission_error,
        maximum_output_units, persist_state_origin, prefixed_header, retry_backoff,
        settle_from_usage, validate_request_bounds,
    },
    usage::AttemptTerminalClass,
};

const CONNECTION_FIRST_EVENT_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CONNECTION_LIFETIME: Duration = Duration::from_secs(60 * 60);
const MAX_CONNECTION_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
const MAX_CONTROL_PAYLOAD_BYTES: usize = 125;
const CONTROL_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

pub async fn upgrade(
    application: Arc<Application>,
    headers: HeaderMap,
    websocket: WebSocketUpgrade,
    request_id: String,
) -> Result<Response, ProtocolError> {
    reject_subprotocols(&headers, &request_id)?;
    authenticate_websocket_connection(&application, &headers, &request_id)?;
    let connection_permit = Arc::clone(&application.websocket_connections)
        .try_acquire_owned()
        .map_err(|_| {
            ProtocolError::new(
                IngressProtocolFamily::OpenaiResponses,
                ProtocolErrorKind::Overloaded,
                &request_id,
                "Responses WebSocket connection capacity is exhausted",
            )
        })?;
    Ok(websocket
        .max_message_size(MAX_CONNECTION_MESSAGE_BYTES)
        .max_frame_size(MAX_CONNECTION_MESSAGE_BYTES)
        .on_upgrade(move |socket| {
            Box::pin(async move {
                let _connection_permit = connection_permit;
                Box::pin(run_connection(socket, application, headers, request_id)).await;
            })
        }))
}

fn reject_subprotocols(headers: &HeaderMap, request_id: &str) -> Result<(), ProtocolError> {
    if headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .next()
        .is_some()
    {
        return Err(ProtocolError::new(
            IngressProtocolFamily::OpenaiResponses,
            ProtocolErrorKind::UnsupportedCapability,
            request_id,
            "Responses WebSocket does not accept a requested subprotocol",
        ));
    }
    Ok(())
}

async fn run_connection(
    mut downstream: WebSocket,
    application: Arc<Application>,
    headers: HeaderMap,
    connection_request_id: String,
) {
    let mut pinned: Option<PinnedUpstream> = None;
    let mut turn_number = 0_u64;
    let connection_deadline = Instant::now() + MAX_CONNECTION_LIFETIME;
    loop {
        if Instant::now() >= connection_deadline {
            close_normally(&mut downstream, "connection lifetime exceeded").await;
            close_upstream(&mut pinned).await;
            return;
        }
        let wait = if turn_number == 0 {
            CONNECTION_FIRST_EVENT_TIMEOUT
        } else {
            CONNECTION_IDLE_TIMEOUT
        }
        .min(connection_deadline.saturating_duration_since(Instant::now()));
        let request_id = if turn_number == 0 {
            connection_request_id.clone()
        } else {
            Uuid::now_v7().to_string()
        };
        let event = match receive_idle_event(&mut downstream, wait, &request_id).await {
            Ok(Some(event)) => event,
            Ok(None) => {
                close_normally(&mut downstream, "connection idle timeout").await;
                close_upstream(&mut pinned).await;
                return;
            }
            Err(error) => {
                close_with_error(&mut downstream, &error).await;
                close_upstream(&mut pinned).await;
                return;
            }
        };
        let native = match event {
            ResponsesWebSocketClientEvent::Create(native) => native,
            ResponsesWebSocketClientEvent::Cancel { .. } => {
                close_with_error(
                    &mut downstream,
                    &ProtocolError::new(
                        IngressProtocolFamily::OpenaiResponses,
                        ProtocolErrorKind::InvalidRequest,
                        request_id,
                        "response.cancel is valid only while a response is active",
                    ),
                )
                .await;
                close_upstream(&mut pinned).await;
                return;
            }
        };
        turn_number = turn_number.saturating_add(1);
        let admission = match authenticate_and_admit(
            &application,
            IngressProtocolFamily::OpenaiResponses,
            &headers,
            &native.intent,
            request_id,
        ) {
            Ok(admission) => admission,
            Err(error) => {
                close_with_error(&mut downstream, &error).await;
                close_upstream(&mut pinned).await;
                return;
            }
        };
        let mut logical = LogicalTelemetry::new(&admission, Instant::now());
        let _global_permit = match admission.protection.try_acquire_global() {
            Ok(permit) => permit,
            Err(_) => {
                logical.finish("admission_denied", None, None);
                close_with_error(
                    &mut downstream,
                    &gateway_error(&admission, ProtocolErrorKind::Overloaded),
                )
                .await;
                close_upstream(&mut pinned).await;
                return;
            }
        };
        if let Err(error) = validate_turn_bounds(&headers, &admission, &native) {
            logical.finish("invalid_request", None, None);
            close_with_error(&mut downstream, &error).await;
            close_upstream(&mut pinned).await;
            return;
        }
        let permit = match admit_turn(&admission, &native).await {
            Ok(permit) => permit,
            Err(error) => {
                logical.finish("admission_denied", None, None);
                close_with_error(&mut downstream, &error).await;
                close_upstream(&mut pinned).await;
                return;
            }
        };
        let outcome = Box::pin(dispatch_active_turn(
            &mut downstream,
            &mut pinned,
            &admission,
            &native,
            &mut logical,
        ))
        .await;
        drop(permit);
        match outcome {
            TurnOutcome::Completed | TurnOutcome::CompletedFailure => {}
            TurnOutcome::Closed
            | TurnOutcome::ClosedFailure
            | TurnOutcome::PreExposureFailure { .. } => {
                close_upstream(&mut pinned).await;
                return;
            }
        }
    }
}

async fn receive_idle_event(
    downstream: &mut WebSocket,
    wait: Duration,
    request_id: &str,
) -> Result<Option<ResponsesWebSocketClientEvent>, ProtocolError> {
    let deadline = Instant::now() + wait;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let message = match timeout(remaining, downstream.recv()).await {
            Ok(Some(Ok(message))) => message,
            Ok(Some(Err(_))) | Ok(None) | Err(_) => return Ok(None),
        };
        match message {
            DownstreamMessage::Text(text) => {
                return parse_openai_responses_websocket_event(
                    Bytes::copy_from_slice(text.as_bytes()),
                    request_id,
                )
                .map(Some);
            }
            DownstreamMessage::Ping(payload) | DownstreamMessage::Pong(payload)
                if payload.len() <= MAX_CONTROL_PAYLOAD_BYTES => {}
            DownstreamMessage::Close(_) => return Ok(None),
            DownstreamMessage::Binary(_)
            | DownstreamMessage::Ping(_)
            | DownstreamMessage::Pong(_) => {
                return Err(ProtocolError::new(
                    IngressProtocolFamily::OpenaiResponses,
                    ProtocolErrorKind::InvalidRequest,
                    request_id,
                    "Responses WebSocket accepts bounded text events only",
                ));
            }
        }
    }
}

fn validate_turn_bounds(
    headers: &HeaderMap,
    admission: &AdmissionContext,
    native: &NativeRequest,
) -> Result<(), ProtocolError> {
    validate_request_bounds(admission, native)?;
    let header_bytes = crate::http::request_header_bytes(headers);
    if header_bytes > admission.effective_request_policy.max_header_bytes {
        return Err(ProtocolError::new(
            IngressProtocolFamily::OpenaiResponses,
            ProtocolErrorKind::RequestTooLarge,
            admission.request_id.clone(),
            "request headers exceed the route limit",
        ));
    }
    Ok(())
}

async fn admit_turn(
    admission: &AdmissionContext,
    native: &NativeRequest,
) -> Result<LogicalRequestPermit, ProtocolError> {
    match &admission.principal {
        GatewayPrincipal::GatewayKey { verifier, .. } => admission
            .admission_state
            .admit_gateway_key(
                admission.coordinator.as_ref(),
                &admission.generation,
                verifier,
                u64::try_from(native.original_body.len()).unwrap_or(u64::MAX),
            )
            .await
            .map_err(|error| logical_admission_error(admission, error)),
        GatewayPrincipal::LocalUser { .. } => Ok(LogicalRequestPermit::unconstrained()),
    }
}

async fn reserve_turn(
    admission: &AdmissionContext,
    candidate: &Candidate,
    native: &NativeRequest,
) -> Result<super::AttemptReservation, ProtocolError> {
    match &admission.principal {
        GatewayPrincipal::GatewayKey { verifier, .. } => admission
            .admission_state
            .reserve_attempt(
                admission.coordinator.as_ref(),
                &admission.generation,
                verifier,
                candidate,
                native,
                maximum_output_units(admission, candidate),
            )
            .await
            .map_err(|error| logical_admission_error(admission, error)),
        GatewayPrincipal::LocalUser { .. } => Ok(super::AttemptReservation::unconstrained()),
    }
}

async fn dispatch_active_turn(
    downstream: &mut WebSocket,
    pinned: &mut Option<PinnedUpstream>,
    admission: &AdmissionContext,
    native: &NativeRequest,
    logical: &mut LogicalTelemetry,
) -> TurnOutcome {
    let reliability = admission
        .generation
        .snapshot
        .catalog
        .reliability_policies
        .get(&admission.route.reliability_policy_id)
        .filter(|policy| policy.active)
        .cloned();
    let Some(reliability) = reliability else {
        close_with_error(
            downstream,
            &gateway_error(admission, ProtocolErrorKind::RouteUnavailable),
        )
        .await;
        return TurnOutcome::Closed;
    };
    let deadline = logical.deadline_after(Duration::from_millis(
        reliability.deadline_policy.overall_timeout_ms,
    ));
    if pinned.is_some() {
        return Box::pin(dispatch_pinned_turn(
            downstream,
            pinned,
            admission,
            native,
            logical,
            &reliability,
            deadline,
        ))
        .await;
    }
    Box::pin(dispatch_initial_turn(
        downstream,
        pinned,
        admission,
        native,
        logical,
        &reliability,
        deadline,
    ))
    .await
}

async fn dispatch_pinned_turn(
    downstream: &mut WebSocket,
    pinned: &mut Option<PinnedUpstream>,
    admission: &AdmissionContext,
    native: &NativeRequest,
    logical: &mut LogicalTelemetry,
    reliability: &ReliabilityPolicySnapshot,
    deadline: Instant,
) -> TurnOutcome {
    let selection = pinned.as_ref().map(PinnedUpstream::selection);
    let candidate = match select_candidate(admission, native, selection.as_ref()).await {
        Ok(candidate) => candidate,
        Err(error) => {
            close_with_error(downstream, &error).await;
            return TurnOutcome::Closed;
        }
    };
    let body = match prepare_turn_body(admission, &candidate, native) {
        Ok(body) => body,
        Err(error) => {
            close_with_error(downstream, &error).await;
            return TurnOutcome::Closed;
        }
    };
    let mut reservation = match reserve_turn(admission, &candidate, native).await {
        Ok(reservation) => reservation,
        Err(error) => {
            close_with_error(downstream, &error).await;
            return TurnOutcome::Closed;
        }
    };
    let target_permit = match admission
        .protection
        .try_acquire_target(&candidate, &reliability.circuit_policy)
    {
        Ok(permit) => permit,
        Err(_) => {
            reservation.definitely_not_dispatched();
            close_with_error(
                downstream,
                &gateway_error(admission, ProtocolErrorKind::Overloaded),
            )
            .await;
            return TurnOutcome::Closed;
        }
    };
    let telemetry = AttemptTelemetry::new(admission, &candidate, &reservation);
    let Some(upstream) = pinned.as_mut() else {
        return TurnOutcome::Closed;
    };
    if !send_upstream_until(
        &mut upstream.socket,
        UpstreamMessage::Text(String::from_utf8_lossy(&body).into_owned().into()),
        deadline,
    )
    .await
    {
        target_permit.failure();
        close_with_error(
            downstream,
            &gateway_error(admission, ProtocolErrorKind::UpstreamUnavailable),
        )
        .await;
        return TurnOutcome::Closed;
    }
    match proxy_active_turn(
        downstream,
        upstream,
        admission,
        &candidate,
        reservation,
        target_permit,
        telemetry,
        logical,
        deadline,
    )
    .await
    {
        TurnOutcome::PreExposureFailure { kind, .. } => {
            close_with_error(downstream, &gateway_error(admission, kind)).await;
            TurnOutcome::Closed
        }
        outcome => outcome,
    }
}

async fn dispatch_initial_turn(
    downstream: &mut WebSocket,
    pinned: &mut Option<PinnedUpstream>,
    admission: &AdmissionContext,
    native: &NativeRequest,
    logical: &mut LogicalTelemetry,
    reliability: &ReliabilityPolicySnapshot,
    deadline: Instant,
) -> TurnOutcome {
    let candidates = match candidates_for_request(admission, native).await {
        Ok(candidates) => candidates,
        Err(error) => {
            close_with_error(downstream, &error).await;
            return TurnOutcome::Closed;
        }
    };
    let can_fail_over = reliability.failover_policy.enabled
        && native.intent.replay_safe
        && native.intent.continuation_reference.is_none();
    let mut attempts = 0_u8;
    let mut distinct = 0_u8;
    let mut last_kind = ProtocolErrorKind::RouteUnavailable;

    'candidates: for candidate in candidates {
        if distinct > reliability.attempt_policy.max_distinct_failover_targets {
            break;
        }
        if !candidate_policy_ready(admission, candidate) {
            last_kind = ProtocolErrorKind::BudgetDenied;
            continue;
        }
        let body = match prepare_turn_body(admission, candidate, native) {
            Ok(body) => body,
            Err(error) => {
                logical.finish("failed", None, None);
                close_with_error(downstream, &error).await;
                return TurnOutcome::Closed;
            }
        };
        distinct = distinct.saturating_add(1);
        let mut same_target = 0_u8;
        loop {
            if attempts >= reliability.attempt_policy.max_total_attempts
                || same_target > reliability.attempt_policy.max_same_target_retries
                || Instant::now() >= deadline
            {
                break;
            }
            let mut reservation = match reserve_turn(admission, candidate, native).await {
                Ok(reservation) => reservation,
                Err(error) => {
                    last_kind = error.kind;
                    continue 'candidates;
                }
            };
            let target_permit = match admission
                .protection
                .try_acquire_target(candidate, &reliability.circuit_policy)
            {
                Ok(permit) => permit,
                Err(_) => {
                    reservation.definitely_not_dispatched();
                    last_kind = ProtocolErrorKind::Overloaded;
                    continue 'candidates;
                }
            };
            attempts = attempts.saturating_add(1);
            same_target = same_target.saturating_add(1);
            let telemetry = AttemptTelemetry::new(admission, candidate, &reservation);
            let socket = match connect_candidate(admission, candidate, deadline).await {
                Ok(socket) => socket,
                Err(failure) => {
                    if failure.terminal_class == AttemptTerminalClass::DefinitelyNotDispatched {
                        reservation.definitely_not_dispatched();
                    }
                    target_permit.failure();
                    telemetry.finish(failure.terminal_class, None);
                    last_kind = failure.kind;
                    let Some(condition) = failure.condition else {
                        if failure.kind == ProtocolErrorKind::InvalidRequest {
                            logical.finish("failed", None, None);
                            close_with_error(downstream, &gateway_error(admission, failure.kind))
                                .await;
                            return TurnOutcome::Closed;
                        }
                        break;
                    };
                    let retry_same = native.intent.replay_safe
                        && reliability.retry_policy.conditions.contains(&condition)
                        && same_target <= reliability.attempt_policy.max_same_target_retries
                        && attempts < reliability.attempt_policy.max_total_attempts;
                    if retry_same && retry_backoff(reliability, same_target, deadline, None).await {
                        continue;
                    }
                    break;
                }
            };
            let mut trial = PinnedUpstream {
                organization_id: admission.organization.id.as_uuid(),
                principal_affinity_id: admission.principal.affinity_uuid(),
                route_id: admission.route.id,
                identity: CandidateIdentity::new(candidate),
                socket,
            };
            let outcome = if send_upstream_until(
                &mut trial.socket,
                UpstreamMessage::Text(String::from_utf8_lossy(&body).into_owned().into()),
                deadline,
            )
            .await
            {
                proxy_active_turn(
                    downstream,
                    &mut trial,
                    admission,
                    candidate,
                    reservation,
                    target_permit,
                    telemetry,
                    logical,
                    deadline,
                )
                .await
            } else {
                target_permit.failure();
                TurnOutcome::PreExposureFailure {
                    condition: RetryCondition::ConnectFailure,
                    kind: ProtocolErrorKind::UpstreamUnavailable,
                }
            };
            match outcome {
                TurnOutcome::Completed | TurnOutcome::CompletedFailure => {
                    *pinned = Some(trial);
                    return outcome;
                }
                TurnOutcome::Closed | TurnOutcome::ClosedFailure => {
                    close_trial(&mut trial).await;
                    return outcome;
                }
                TurnOutcome::PreExposureFailure { condition, kind } => {
                    close_trial(&mut trial).await;
                    last_kind = kind;
                    let retry_same = native.intent.replay_safe
                        && reliability.retry_policy.conditions.contains(&condition)
                        && same_target <= reliability.attempt_policy.max_same_target_retries
                        && attempts < reliability.attempt_policy.max_total_attempts;
                    if retry_same && retry_backoff(reliability, same_target, deadline, None).await {
                        continue;
                    }
                    break;
                }
            }
        }
        if !can_fail_over {
            break;
        }
    }

    let kind = if Instant::now() >= deadline {
        ProtocolErrorKind::DeadlineExceeded
    } else {
        last_kind
    };
    logical.finish("failed", None, None);
    close_with_error(downstream, &gateway_error(admission, kind)).await;
    TurnOutcome::Closed
}

fn prepare_turn_body(
    admission: &AdmissionContext,
    candidate: &Candidate,
    native: &NativeRequest,
) -> Result<Vec<u8>, ProtocolError> {
    let body = adapt_provider_body(
        native,
        candidate.deployment.transport_kind,
        &candidate.deployment.upstream_model_id,
        maximum_output_units(admission, candidate),
    )
    .map_err(|_| {
        ProtocolError::new(
            IngressProtocolFamily::OpenaiResponses,
            ProtocolErrorKind::InvalidRequest,
            admission.request_id.clone(),
            "response.create could not be prepared for the selected transport",
        )
    })?;
    let client = admission
        .generation
        .credential_clients
        .clients
        .get(&candidate.deployment.client_key())
        .ok_or_else(|| gateway_error(admission, ProtocolErrorKind::RouteUnavailable))?;
    if !client.request_body_allowed(u64::try_from(body.len()).unwrap_or(u64::MAX)) {
        return Err(gateway_error(admission, ProtocolErrorKind::RequestTooLarge));
    }
    Ok(body)
}

async fn close_trial(upstream: &mut PinnedUpstream) {
    let _ = timeout(CONTROL_WRITE_TIMEOUT, upstream.socket.close(None)).await;
}

async fn select_candidate(
    admission: &AdmissionContext,
    native: &NativeRequest,
    pinned: Option<&PinnedSelection>,
) -> Result<Candidate, ProtocolError> {
    let candidates = candidates_for_request(admission, native).await?;
    if let Some(pinned) = pinned {
        if pinned.organization_id != admission.organization.id.as_uuid()
            || pinned.principal_affinity_id != admission.principal.affinity_uuid()
            || pinned.route_id != admission.route.id
        {
            return Err(gateway_error(
                admission,
                ProtocolErrorKind::StateOriginUnavailable,
            ));
        }
        return candidates
            .into_iter()
            .find(|candidate| pinned.identity.matches(candidate))
            .cloned()
            .ok_or_else(|| gateway_error(admission, ProtocolErrorKind::StateOriginUnavailable));
    }
    candidates
        .into_iter()
        .find(|candidate| candidate_policy_ready(admission, candidate))
        .cloned()
        .ok_or_else(|| gateway_error(admission, ProtocolErrorKind::RouteUnavailable))
}

struct PinnedUpstream {
    organization_id: Uuid,
    principal_affinity_id: Uuid,
    route_id: RouteId,
    identity: CandidateIdentity,
    socket: WebSocketStream<reqwest::Upgraded>,
}

impl PinnedUpstream {
    fn selection(&self) -> PinnedSelection {
        PinnedSelection {
            organization_id: self.organization_id,
            principal_affinity_id: self.principal_affinity_id,
            route_id: self.route_id,
            identity: self.identity.clone(),
        }
    }
}

struct PinnedSelection {
    organization_id: Uuid,
    principal_affinity_id: Uuid,
    route_id: RouteId,
    identity: CandidateIdentity,
}

#[derive(Clone)]
struct CandidateIdentity {
    target_id: Uuid,
    deployment_id: Uuid,
    deployment_config_version: u64,
    endpoint_id: Uuid,
    endpoint_config_version: i64,
    credential_id: Uuid,
    credential_state_identity_version: u64,
    transport: TransportKind,
}

impl CandidateIdentity {
    fn new(candidate: &Candidate) -> Self {
        let key = candidate.deployment.client_key();
        Self {
            target_id: candidate.target.id.as_uuid(),
            deployment_id: candidate.deployment.id.as_uuid(),
            deployment_config_version: candidate.deployment.config_version,
            endpoint_id: candidate.deployment.endpoint_id.as_uuid(),
            endpoint_config_version: key.endpoint_config_version,
            credential_id: key.credential_id.as_uuid(),
            credential_state_identity_version: candidate
                .deployment
                .credential_state_identity_version,
            transport: candidate.deployment.transport_kind,
        }
    }

    fn matches(&self, candidate: &Candidate) -> bool {
        let key = candidate.deployment.client_key();
        self.target_id == candidate.target.id.as_uuid()
            && self.deployment_id == candidate.deployment.id.as_uuid()
            && self.deployment_config_version == candidate.deployment.config_version
            && self.endpoint_id == candidate.deployment.endpoint_id.as_uuid()
            && self.endpoint_config_version == key.endpoint_config_version
            && self.credential_id == key.credential_id.as_uuid()
            && self.credential_state_identity_version
                == candidate.deployment.credential_state_identity_version
            && self.transport == candidate.deployment.transport_kind
    }
}

#[derive(Clone, Copy, Debug)]
struct CandidateConnectFailure {
    condition: Option<RetryCondition>,
    kind: ProtocolErrorKind,
    terminal_class: AttemptTerminalClass,
}

impl CandidateConnectFailure {
    const fn after_dispatch(condition: Option<RetryCondition>, kind: ProtocolErrorKind) -> Self {
        Self {
            condition,
            kind,
            terminal_class: AttemptTerminalClass::Actual,
        }
    }

    const fn ambiguous(condition: RetryCondition) -> Self {
        Self {
            condition: Some(condition),
            kind: ProtocolErrorKind::UpstreamUnavailable,
            terminal_class: AttemptTerminalClass::UnknownOrAmbiguous,
        }
    }
}

impl From<RetryCondition> for CandidateConnectFailure {
    fn from(condition: RetryCondition) -> Self {
        Self {
            condition: Some(condition),
            kind: ProtocolErrorKind::UpstreamUnavailable,
            terminal_class: AttemptTerminalClass::DefinitelyNotDispatched,
        }
    }
}

async fn connect_candidate(
    admission: &AdmissionContext,
    candidate: &Candidate,
    deadline: Instant,
) -> Result<WebSocketStream<reqwest::Upgraded>, CandidateConnectFailure> {
    let unavailable = RetryCondition::ConnectFailure;
    let client = admission
        .generation
        .credential_clients
        .clients
        .get(&candidate.deployment.client_key())
        .ok_or(unavailable)?;
    let endpoint = admission
        .generation
        .snapshot
        .catalog
        .endpoints
        .get(&candidate.deployment.endpoint_id)
        .ok_or(unavailable)?;
    let placeholder = NativeRequest {
        family: IngressProtocolFamily::OpenaiResponses,
        original_body: Bytes::new(),
        envelope: json!({"model": admission.route.model_key}),
        intent: crate::protocols::LlmIntent {
            model_key: admission.route.model_key.clone(),
            response_mode: crate::protocols::ResponseMode::WebSocket,
            required_scopes: crate::domain::LlmScopeSet::new([
                crate::domain::LlmScope::Invoke,
                crate::domain::LlmScope::Stream,
            ])
            .map_err(|_| unavailable)?,
            required_capabilities: Default::default(),
            requested_output_bound: None,
            continuation_reference: None,
            replay_safe: true,
        },
    };
    let url = upstream_url(
        &placeholder,
        candidate.deployment.transport_kind,
        &candidate.deployment.upstream_model_id,
        endpoint,
    )
    .map_err(|_| unavailable)?;
    let reliability = admission
        .generation
        .snapshot
        .catalog
        .reliability_policies
        .get(&admission.route.reliability_policy_id)
        .ok_or(unavailable)?;
    let connect_timeout_ms = candidate
        .target
        .timeout_overrides
        .connect_timeout_ms
        .unwrap_or(reliability.deadline_policy.connect_timeout_ms);
    let websocket_key = generate_key();
    let mut builder = client
        .http
        .get(url)
        .version(http::Version::HTTP_11)
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, "websocket")
        .header(header::SEC_WEBSOCKET_VERSION, "13")
        .header(header::SEC_WEBSOCKET_KEY, websocket_key.clone())
        .header(
            "x-request-id",
            HeaderValue::from_str(&admission.request_id).map_err(|_| unavailable)?,
        );
    builder = apply_static_injection(builder, client, candidate.deployment.transport_kind)
        .map_err(|_| unavailable)?;
    let mut request = builder.build().map_err(|_| unavailable)?;
    if let CredentialInjection::Dynamic(authenticator) = &client.injection {
        let authentication_timeout = Duration::from_millis(connect_timeout_ms)
            .min(deadline.saturating_duration_since(Instant::now()));
        match timeout(
            authentication_timeout,
            authenticator.apply(&mut request, &[]),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                return Err(CandidateConnectFailure {
                    condition: None,
                    kind: ProtocolErrorKind::UpstreamUnavailable,
                    terminal_class: AttemptTerminalClass::DefinitelyNotDispatched,
                });
            }
            Err(_) => return Err(RetryCondition::ConnectTimeout.into()),
        }
    }
    let response_timeout = Duration::from_millis(
        candidate
            .target
            .timeout_overrides
            .response_header_timeout_ms
            .unwrap_or(reliability.deadline_policy.response_header_timeout_ms),
    )
    .min(deadline.saturating_duration_since(Instant::now()));
    let response = match timeout(
        response_timeout,
        client.execute_attempt(request, connect_timeout_ms),
    )
    .await
    {
        Err(_) => {
            return Err(CandidateConnectFailure::ambiguous(
                RetryCondition::ResponseHeaderTimeout,
            ));
        }
        Ok(Err(error)) => {
            let condition = classify_pre_header_transport_error(&error);
            if error.is_connect() {
                return Err(condition.into());
            }
            return Err(CandidateConnectFailure::ambiguous(condition));
        }
        Ok(Ok(response)) => response,
    };
    match classify_upstream_status(response.status()) {
        Some(UpstreamStatusFailure::Retryable(condition)) => {
            return Err(CandidateConnectFailure::after_dispatch(
                Some(condition),
                ProtocolErrorKind::UpstreamUnavailable,
            ));
        }
        Some(UpstreamStatusFailure::AuthOrConfiguration) => {
            return Err(CandidateConnectFailure::after_dispatch(
                None,
                ProtocolErrorKind::UpstreamUnavailable,
            ));
        }
        Some(UpstreamStatusFailure::ClientInvalid) => {
            return Err(CandidateConnectFailure::after_dispatch(
                None,
                ProtocolErrorKind::InvalidRequest,
            ));
        }
        None => {}
    }
    validate_upgrade_response(&response, &websocket_key).map_err(|_| {
        CandidateConnectFailure::after_dispatch(
            Some(RetryCondition::Provider5xx),
            ProtocolErrorKind::UpstreamUnavailable,
        )
    })?;
    let upgraded = match timeout(
        deadline.saturating_duration_since(Instant::now()),
        response.upgrade(),
    )
    .await
    {
        Err(_) => {
            return Err(CandidateConnectFailure::after_dispatch(
                Some(RetryCondition::ResponseHeaderTimeout),
                ProtocolErrorKind::UpstreamUnavailable,
            ));
        }
        Ok(Err(_)) => {
            return Err(CandidateConnectFailure::after_dispatch(
                Some(RetryCondition::ConnectFailure),
                ProtocolErrorKind::UpstreamUnavailable,
            ));
        }
        Ok(Ok(upgraded)) => upgraded,
    };
    let maximum = client
        .max_response_body_bytes
        .min(admission.effective_request_policy.max_response_body_bytes);
    let maximum = usize::try_from(maximum).unwrap_or(usize::MAX);
    let config = WebSocketConfig::default()
        .write_buffer_size(0)
        .max_write_buffer_size(maximum.max(1))
        .max_message_size(Some(maximum))
        .max_frame_size(Some(maximum));
    Ok(WebSocketStream::from_raw_socket(upgraded, Role::Client, Some(config)).await)
}

fn apply_static_injection(
    mut builder: reqwest::RequestBuilder,
    client: &CredentialClient,
    transport: TransportKind,
) -> Result<reqwest::RequestBuilder, ()> {
    builder = match &client.injection {
        CredentialInjection::Bearer(value) => builder.header(
            header::AUTHORIZATION,
            prefixed_header("Bearer ", value).map_err(|_| ())?,
        ),
        CredentialInjection::Codex {
            authorization,
            account_id,
        } => builder
            .header(header::AUTHORIZATION, authorization.clone())
            .header("chatgpt-account-id", account_id.clone()),
        CredentialInjection::XApiKey(value) => builder.header("x-api-key", value.clone()),
        CredentialInjection::ApiKeyHeader(value) => {
            let name = if transport == TransportKind::GoogleGeminiGenerateContent {
                "x-goog-api-key"
            } else {
                "api-key"
            };
            builder.header(name, value.clone())
        }
        CredentialInjection::Dynamic(_) => builder,
    };
    Ok(builder)
}

fn validate_upgrade_response(response: &reqwest::Response, request_key: &str) -> Result<(), ()> {
    if response.status() != StatusCode::SWITCHING_PROTOCOLS
        || !header_has_token(response.headers(), header::CONNECTION, "upgrade")
        || !header_has_token(response.headers(), header::UPGRADE, "websocket")
        || response
            .headers()
            .contains_key(header::SEC_WEBSOCKET_PROTOCOL)
        || response
            .headers()
            .contains_key(header::SEC_WEBSOCKET_EXTENSIONS)
    {
        return Err(());
    }
    let expected = derive_accept_key(request_key.as_bytes());
    let mut accept_values = response
        .headers()
        .get_all(header::SEC_WEBSOCKET_ACCEPT)
        .iter();
    let actual = accept_values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(())?;
    if accept_values.next().is_some() {
        return Err(());
    }
    bool::from(subtle::ConstantTimeEq::ct_eq(
        actual.as_bytes(),
        expected.as_bytes(),
    ))
    .then_some(())
    .ok_or(())
}

fn header_has_token(headers: &HeaderMap, name: header::HeaderName, expected: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().ok().is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
        })
    })
}

enum TurnEvent {
    Upstream(Option<Result<UpstreamMessage, tokio_tungstenite::tungstenite::Error>>),
    Downstream(Option<Result<DownstreamMessage, axum::Error>>),
}

enum TurnOutcome {
    Completed,
    CompletedFailure,
    PreExposureFailure {
        condition: RetryCondition,
        kind: ProtocolErrorKind,
    },
    Closed,
    ClosedFailure,
}

async fn proxy_active_turn(
    downstream: &mut WebSocket,
    upstream: &mut PinnedUpstream,
    admission: &AdmissionContext,
    candidate: &Candidate,
    reservation: super::AttemptReservation,
    target_permit: TargetAttemptPermit,
    telemetry: AttemptTelemetry,
    logical: &mut LogicalTelemetry,
    turn_deadline: Instant,
) -> TurnOutcome {
    let outcome = proxy_active_turn_inner(
        downstream,
        upstream,
        admission,
        candidate,
        reservation,
        telemetry,
        logical,
        turn_deadline,
    )
    .await;
    match outcome {
        TurnOutcome::Completed => target_permit.success(),
        TurnOutcome::CompletedFailure
        | TurnOutcome::PreExposureFailure { .. }
        | TurnOutcome::ClosedFailure => target_permit.failure(),
        TurnOutcome::Closed => drop(target_permit),
    }
    outcome
}

async fn proxy_active_turn_inner(
    downstream: &mut WebSocket,
    upstream: &mut PinnedUpstream,
    admission: &AdmissionContext,
    candidate: &Candidate,
    mut reservation: super::AttemptReservation,
    telemetry: AttemptTelemetry,
    logical: &mut LogicalTelemetry,
    turn_deadline: Instant,
) -> TurnOutcome {
    let reliability = match admission
        .generation
        .snapshot
        .catalog
        .reliability_policies
        .get(&admission.route.reliability_policy_id)
        .filter(|policy| policy.active)
    {
        Some(policy) => policy,
        None => return TurnOutcome::Closed,
    };
    let maximum = admission
        .effective_request_policy
        .max_response_body_bytes
        .min(
            admission
                .generation
                .credential_clients
                .clients
                .get(&candidate.deployment.client_key())
                .map_or(0, |client| client.max_response_body_bytes),
        );
    let idle = Duration::from_millis(
        candidate
            .target
            .timeout_overrides
            .stream_idle_timeout_ms
            .unwrap_or(reliability.deadline_policy.stream_idle_timeout_ms),
    );
    let stream_deadline =
        Instant::now() + Duration::from_secs(u64::from(effective_stream_duration_limit(admission)));
    let turn_deadline = turn_deadline.min(stream_deadline);
    let classification_deadline = Instant::now()
        + Duration::from_millis(
            reliability
                .deadline_policy
                .pre_commit_classification_timeout_ms,
        );
    let mut committed = false;
    let mut state_id: Option<String> = None;
    let mut precommit = Vec::<String>::new();
    let mut precommit_bytes = 0_u64;
    let mut response_bytes = 0_u64;
    loop {
        if Instant::now() >= turn_deadline {
            if let Some(outcome) = pre_exposure_failure(
                committed,
                state_id.as_ref(),
                RetryCondition::ResponseHeaderTimeout,
                ProtocolErrorKind::DeadlineExceeded,
            ) {
                return outcome;
            }
            close_with_error(
                downstream,
                &gateway_error(admission, ProtocolErrorKind::DeadlineExceeded),
            )
            .await;
            return TurnOutcome::ClosedFailure;
        }
        let wait = if committed {
            idle.min(turn_deadline.saturating_duration_since(Instant::now()))
        } else {
            classification_deadline
                .saturating_duration_since(Instant::now())
                .min(turn_deadline.saturating_duration_since(Instant::now()))
        };
        let event = timeout(wait, async {
            tokio::select! {
                message = upstream.socket.next() => TurnEvent::Upstream(message),
                message = downstream.recv() => TurnEvent::Downstream(message),
            }
        })
        .await;
        let Ok(event) = event else {
            if let Some(outcome) = pre_exposure_failure(
                committed,
                state_id.as_ref(),
                RetryCondition::ResponseHeaderTimeout,
                ProtocolErrorKind::DeadlineExceeded,
            ) {
                return outcome;
            }
            close_with_error(
                downstream,
                &gateway_error(admission, ProtocolErrorKind::DeadlineExceeded),
            )
            .await;
            return TurnOutcome::ClosedFailure;
        };
        match event {
            TurnEvent::Downstream(Some(Ok(DownstreamMessage::Text(text)))) => {
                let parsed = parse_openai_responses_websocket_event(
                    Bytes::copy_from_slice(text.as_bytes()),
                    &admission.request_id,
                );
                let ResponsesWebSocketClientEvent::Cancel {
                    original_body,
                    response_id: cancelled,
                } = (match parsed {
                    Ok(event) => event,
                    Err(error) => {
                        close_with_error(downstream, &error).await;
                        return TurnOutcome::Closed;
                    }
                })
                else {
                    close_with_error(
                        downstream,
                        &ProtocolError::new(
                            IngressProtocolFamily::OpenaiResponses,
                            ProtocolErrorKind::InvalidRequest,
                            admission.request_id.clone(),
                            "only response.cancel is accepted while a response is active",
                        ),
                    )
                    .await;
                    return TurnOutcome::Closed;
                };
                if cancelled.is_some() && cancelled.as_deref() != state_id.as_deref() {
                    close_with_error(
                        downstream,
                        &ProtocolError::new(
                            IngressProtocolFamily::OpenaiResponses,
                            ProtocolErrorKind::InvalidRequest,
                            admission.request_id.clone(),
                            "response.cancel does not match the active response",
                        ),
                    )
                    .await;
                    return TurnOutcome::Closed;
                }
                if !send_upstream_until(
                    &mut upstream.socket,
                    UpstreamMessage::Text(
                        String::from_utf8_lossy(&original_body).into_owned().into(),
                    ),
                    turn_deadline,
                )
                .await
                {
                    return TurnOutcome::Closed;
                }
            }
            TurnEvent::Downstream(Some(Ok(DownstreamMessage::Ping(payload))))
            | TurnEvent::Downstream(Some(Ok(DownstreamMessage::Pong(payload))))
                if payload.len() <= MAX_CONTROL_PAYLOAD_BYTES => {}
            TurnEvent::Downstream(Some(Ok(DownstreamMessage::Close(_))))
            | TurnEvent::Downstream(None)
            | TurnEvent::Downstream(Some(Err(_))) => return TurnOutcome::Closed,
            TurnEvent::Downstream(Some(Ok(DownstreamMessage::Binary(_))))
            | TurnEvent::Downstream(Some(Ok(DownstreamMessage::Ping(_))))
            | TurnEvent::Downstream(Some(Ok(DownstreamMessage::Pong(_)))) => {
                close_with_error(
                    downstream,
                    &ProtocolError::new(
                        IngressProtocolFamily::OpenaiResponses,
                        ProtocolErrorKind::InvalidRequest,
                        admission.request_id.clone(),
                        "Responses WebSocket accepts bounded text events only",
                    ),
                )
                .await;
                return TurnOutcome::Closed;
            }
            TurnEvent::Upstream(Some(Ok(UpstreamMessage::Ping(payload)))) => {
                if payload.len() > MAX_CONTROL_PAYLOAD_BYTES
                    || !send_upstream_until(
                        &mut upstream.socket,
                        UpstreamMessage::Pong(payload),
                        turn_deadline,
                    )
                    .await
                {
                    return TurnOutcome::ClosedFailure;
                }
            }
            TurnEvent::Upstream(Some(Ok(UpstreamMessage::Pong(payload)))) => {
                if payload.len() > MAX_CONTROL_PAYLOAD_BYTES {
                    return TurnOutcome::ClosedFailure;
                }
            }
            TurnEvent::Upstream(Some(Ok(UpstreamMessage::Text(text)))) => {
                let length = u64::try_from(text.len()).unwrap_or(u64::MAX);
                response_bytes = response_bytes.saturating_add(length);
                if response_bytes > maximum {
                    if let Some(outcome) = pre_exposure_failure(
                        committed,
                        state_id.as_ref(),
                        RetryCondition::ProviderOverloaded,
                        ProtocolErrorKind::UpstreamUnavailable,
                    ) {
                        return outcome;
                    }
                    close_with_error(
                        downstream,
                        &gateway_error(admission, ProtocolErrorKind::UpstreamUnavailable),
                    )
                    .await;
                    return TurnOutcome::ClosedFailure;
                }
                let value: Value = match serde_json::from_str(&text) {
                    Ok(value) => value,
                    Err(_) => {
                        if let Some(outcome) = pre_exposure_failure(
                            committed,
                            state_id.as_ref(),
                            RetryCondition::Provider5xx,
                            ProtocolErrorKind::UpstreamUnavailable,
                        ) {
                            return outcome;
                        }
                        close_with_error(
                            downstream,
                            &gateway_error(admission, ProtocolErrorKind::UpstreamUnavailable),
                        )
                        .await;
                        return TurnOutcome::ClosedFailure;
                    }
                };
                let event_type = value.get("type").and_then(Value::as_str).unwrap_or("");
                if event_type.len() > 128
                    || !(event_type.starts_with("response.") || event_type == "error")
                {
                    if let Some(outcome) = pre_exposure_failure(
                        committed,
                        state_id.as_ref(),
                        RetryCondition::Provider5xx,
                        ProtocolErrorKind::UpstreamUnavailable,
                    ) {
                        return outcome;
                    }
                    close_with_error(
                        downstream,
                        &gateway_error(admission, ProtocolErrorKind::UpstreamUnavailable),
                    )
                    .await;
                    return TurnOutcome::ClosedFailure;
                }
                if event_type == "error"
                    && let Some(condition) = websocket_provider_error_condition(&value)
                    && let Some(outcome) = pre_exposure_failure(
                        committed,
                        state_id.as_ref(),
                        condition,
                        ProtocolErrorKind::UpstreamUnavailable,
                    )
                {
                    return outcome;
                }
                let observed_state = response_state_id(candidate.deployment.transport_kind, &value);
                if let Some(observed) = observed_state {
                    if state_id
                        .as_ref()
                        .is_some_and(|current| current != &observed)
                    {
                        close_with_error(
                            downstream,
                            &gateway_error(admission, ProtocolErrorKind::StateOriginUnavailable),
                        )
                        .await;
                        return TurnOutcome::ClosedFailure;
                    }
                    if state_id.is_none() {
                        if persist_state_origin(admission, candidate, &observed)
                            .await
                            .is_err()
                        {
                            close_with_error(
                                downstream,
                                &gateway_error(
                                    admission,
                                    ProtocolErrorKind::StateOriginUnavailable,
                                ),
                            )
                            .await;
                            return TurnOutcome::Closed;
                        }
                        state_id = Some(observed);
                    }
                }
                let terminal = matches!(
                    event_type,
                    "response.completed"
                        | "response.failed"
                        | "response.cancelled"
                        | "response.incomplete"
                        | "error"
                );
                if !committed {
                    precommit_bytes = precommit_bytes.saturating_add(length);
                    precommit.push(text.to_string());
                    if precommit_bytes > reliability.commitment_policy.stream_precommit_buffer_bytes
                        || u64::try_from(precommit.len()).unwrap_or(u64::MAX)
                            > reliability.commitment_policy.stream_precommit_buffer_events
                    {
                        if let Some(outcome) = pre_exposure_failure(
                            committed,
                            state_id.as_ref(),
                            RetryCondition::ProviderOverloaded,
                            ProtocolErrorKind::UpstreamUnavailable,
                        ) {
                            return outcome;
                        }
                        close_with_error(
                            downstream,
                            &gateway_error(admission, ProtocolErrorKind::UpstreamUnavailable),
                        )
                        .await;
                        return TurnOutcome::Closed;
                    }
                }
                if terminal {
                    if !committed && state_id.is_none() && event_type != "error" {
                        close_with_error(
                            downstream,
                            &gateway_error(admission, ProtocolErrorKind::StateOriginUnavailable),
                        )
                        .await;
                        return TurnOutcome::Closed;
                    }
                    let usage = (event_type != "error")
                        .then(|| extract_json_usage(candidate.deployment.transport_kind, &value));
                    if let Some(usage) = &usage {
                        settle_from_usage(&mut reservation, &candidate.deployment, usage.clone());
                    }
                    telemetry.finish(AttemptTerminalClass::Actual, usage.as_ref());
                    logical.finish(
                        if event_type == "response.completed" {
                            "success"
                        } else {
                            "provider_terminal"
                        },
                        usage.as_ref(),
                        Some(&candidate.deployment),
                    );
                    if committed {
                        if !send_downstream_until(
                            downstream,
                            DownstreamMessage::Text(text.to_string().into()),
                            turn_deadline,
                        )
                        .await
                        {
                            return TurnOutcome::Closed;
                        }
                    } else {
                        for buffered in precommit.drain(..) {
                            if !send_downstream_until(
                                downstream,
                                DownstreamMessage::Text(buffered.into()),
                                turn_deadline,
                            )
                            .await
                            {
                                return TurnOutcome::Closed;
                            }
                        }
                    }
                    return if event_type == "response.completed"
                        || event_type == "response.cancelled"
                    {
                        TurnOutcome::Completed
                    } else {
                        TurnOutcome::CompletedFailure
                    };
                }
                if !committed && state_id.is_some() {
                    for buffered in precommit.drain(..) {
                        if !send_downstream_until(
                            downstream,
                            DownstreamMessage::Text(buffered.into()),
                            turn_deadline,
                        )
                        .await
                        {
                            return TurnOutcome::Closed;
                        }
                    }
                    committed = true;
                } else if committed
                    && !send_downstream_until(
                        downstream,
                        DownstreamMessage::Text(text.to_string().into()),
                        turn_deadline,
                    )
                    .await
                {
                    return TurnOutcome::Closed;
                }
            }
            TurnEvent::Upstream(Some(Ok(UpstreamMessage::Close(_))))
            | TurnEvent::Upstream(None)
            | TurnEvent::Upstream(Some(Err(_)))
            | TurnEvent::Upstream(Some(Ok(UpstreamMessage::Binary(_))))
            | TurnEvent::Upstream(Some(Ok(UpstreamMessage::Frame(_)))) => {
                if let Some(outcome) = pre_exposure_failure(
                    committed,
                    state_id.as_ref(),
                    RetryCondition::ProviderOverloaded,
                    ProtocolErrorKind::UpstreamUnavailable,
                ) {
                    return outcome;
                }
                close_with_error(
                    downstream,
                    &gateway_error(admission, ProtocolErrorKind::UpstreamUnavailable),
                )
                .await;
                return TurnOutcome::ClosedFailure;
            }
        }
    }
}

fn websocket_provider_error_condition(value: &Value) -> Option<RetryCondition> {
    let error = value.get("error")?.as_object()?;
    let code = error
        .get("code")
        .and_then(Value::as_str)
        .or_else(|| error.get("type").and_then(Value::as_str))?;
    match code {
        "rate_limit_exceeded" | "rate_limit_error" => Some(RetryCondition::ProviderRateLimited),
        "overloaded_error" | "service_unavailable" => Some(RetryCondition::ProviderOverloaded),
        "server_error" | "internal_server_error" => Some(RetryCondition::Provider5xx),
        _ => None,
    }
}

fn pre_exposure_failure(
    committed: bool,
    state_id: Option<&String>,
    condition: RetryCondition,
    kind: ProtocolErrorKind,
) -> Option<TurnOutcome> {
    (!committed && state_id.is_none())
        .then_some(TurnOutcome::PreExposureFailure { condition, kind })
}

async fn send_downstream_until(
    downstream: &mut WebSocket,
    message: DownstreamMessage,
    deadline: Instant,
) -> bool {
    timeout(
        deadline.saturating_duration_since(Instant::now()),
        downstream.send(message),
    )
    .await
    .is_ok_and(|result| result.is_ok())
}

async fn send_upstream_until(
    upstream: &mut WebSocketStream<reqwest::Upgraded>,
    message: UpstreamMessage,
    deadline: Instant,
) -> bool {
    timeout(
        deadline.saturating_duration_since(Instant::now()),
        upstream.send(message),
    )
    .await
    .is_ok_and(|result| result.is_ok())
}

async fn close_with_error(downstream: &mut WebSocket, error: &ProtocolError) {
    let code = error.code();
    let body = json!({
        "type": "error",
        "error": {
            "message": error.message,
            "type": code,
            "param": null,
            "code": code,
        },
        "request_id": error.request_id,
    });
    let deadline = Instant::now() + CONTROL_WRITE_TIMEOUT;
    let _ = send_downstream_until(
        downstream,
        DownstreamMessage::Text(body.to_string().into()),
        deadline,
    )
    .await;
    let _ = send_downstream_until(
        downstream,
        DownstreamMessage::Close(Some(CloseFrame {
            code: if matches!(
                error.kind,
                ProtocolErrorKind::Authentication
                    | ProtocolErrorKind::ConflictingAuthentication
                    | ProtocolErrorKind::Forbidden
                    | ProtocolErrorKind::InvalidRequest
                    | ProtocolErrorKind::RequestTooLarge
                    | ProtocolErrorKind::UnsupportedCapability
            ) {
                1008
            } else {
                1011
            },
            reason: code.into(),
        })),
        deadline,
    )
    .await;
}

async fn close_normally(downstream: &mut WebSocket, reason: &'static str) {
    let _ = send_downstream_until(
        downstream,
        DownstreamMessage::Close(Some(CloseFrame {
            code: 1000,
            reason: reason.into(),
        })),
        Instant::now() + CONTROL_WRITE_TIMEOUT,
    )
    .await;
}

async fn close_upstream(upstream: &mut Option<PinnedUpstream>) {
    if let Some(upstream) = upstream.as_mut() {
        let _ = timeout(CONTROL_WRITE_TIMEOUT, upstream.socket.close(None)).await;
    }
    *upstream = None;
}
