use std::{
    io,
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_stream::stream;
use axum::{
    body::{Body, Bytes},
    http::{HeaderName, HeaderValue, Response, StatusCode, header},
};
use futures_util::StreamExt as _;
use rand::Rng as _;
use tokio::{
    sync::OwnedSemaphorePermit,
    time::{Instant, sleep, timeout},
};

use crate::{
    adapters::{
        coordinator::StateOrigin,
        provider::wire::{
            AwsEventStreamDecoder, ProviderUsage, SseInspector, StreamTerminalOutcome,
            UsageCompleteness, adapt_provider_body, extract_json_usage, response_state_id,
            upstream_url,
        },
    },
    domain::{AccountingOrigin, TransportKind},
    protocols::{NativeRequest, ProtocolError, ProtocolErrorKind, ResponseMode},
    runtime::{
        CredentialClient, CredentialInjection, DeploymentSnapshot, PricingOutcome,
        ReliabilityPolicySnapshot, RetryCondition,
    },
};

use super::{
    AdmissionContext, AttemptReservation, Candidate, GatewayPrincipal, LogicalAdmissionError,
    LogicalRequestPermit, TargetAttemptPermit, usage::AttemptTerminalClass,
};

pub async fn dispatch(
    admission: AdmissionContext,
    native: NativeRequest,
) -> Result<Response<Body>, ProtocolError> {
    let logical_started = Instant::now();
    let global_permit = match admission.protection.try_acquire_global() {
        Ok(permit) => permit,
        Err(_) => {
            admission.usage.record_logical(
                &admission,
                "admission_denied",
                None,
                None,
                logical_started.elapsed(),
            );
            return Err(gateway_error(&admission, ProtocolErrorKind::Overloaded));
        }
    };
    if let Err(error) = validate_request_bounds(&admission, &native) {
        admission.usage.record_logical(
            &admission,
            "invalid_request",
            None,
            None,
            logical_started.elapsed(),
        );
        return Err(error);
    }
    let permit = match &admission.principal {
        GatewayPrincipal::GatewayKey { verifier, .. } => match admission
            .admission_state
            .admit_gateway_key(
                admission.coordinator.as_ref(),
                &admission.generation,
                verifier,
                u64::try_from(native.original_body.len()).unwrap_or(u64::MAX),
            )
            .await
        {
            Ok(permit) => permit,
            Err(error) => {
                admission.usage.record_logical(
                    &admission,
                    "admission_denied",
                    None,
                    None,
                    logical_started.elapsed(),
                );
                return Err(logical_admission_error(&admission, error));
            }
        },
        GatewayPrincipal::LocalUser { .. } => LogicalRequestPermit::unconstrained(),
    };
    match dispatch_admitted(&admission, &native, logical_started).await {
        Ok(response) => Ok(hold_request_permits(response, permit, global_permit)),
        Err(error) => {
            admission.usage.record_logical(
                &admission,
                "failed",
                None,
                None,
                logical_started.elapsed(),
            );
            Err(error)
        }
    }
}

async fn dispatch_admitted(
    admission: &AdmissionContext,
    native: &NativeRequest,
    logical_started: Instant,
) -> Result<Response<Body>, ProtocolError> {
    let candidates = candidates_for_request(admission, native).await?;
    let reliability = admission
        .generation
        .snapshot
        .catalog
        .reliability_policies
        .get(&admission.route.reliability_policy_id)
        .filter(|policy| policy.active)
        .cloned()
        .ok_or_else(|| gateway_error(&admission, ProtocolErrorKind::RouteUnavailable))?;
    let deadline =
        logical_started + Duration::from_millis(reliability.deadline_policy.overall_timeout_ms);
    let mut attempts = 0_u8;
    let mut distinct = 0_u8;
    let mut last_error = None;

    for candidate in candidates {
        if distinct > reliability.attempt_policy.max_distinct_failover_targets {
            break;
        }
        if !candidate_policy_ready(&admission, candidate) {
            last_error = Some(ProtocolErrorKind::BudgetDenied);
            continue;
        }
        distinct = distinct.saturating_add(1);
        let mut same_target = 0_u8;
        loop {
            if attempts >= reliability.attempt_policy.max_total_attempts
                || same_target > reliability.attempt_policy.max_same_target_retries
                || Instant::now() >= deadline
            {
                break;
            }
            let mut reservation = match &admission.principal {
                GatewayPrincipal::GatewayKey { verifier, .. } => match admission
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
                {
                    Ok(reservation) => reservation,
                    Err(_) => {
                        last_error = Some(ProtocolErrorKind::BudgetDenied);
                        break;
                    }
                },
                GatewayPrincipal::LocalUser { .. } => AttemptReservation::unconstrained(),
            };
            let target_permit = match admission
                .protection
                .try_acquire_target(candidate, &reliability.circuit_policy)
            {
                Ok(permit) => permit,
                Err(_) => {
                    reservation.definitely_not_dispatched();
                    last_error = Some(ProtocolErrorKind::Overloaded);
                    break;
                }
            };
            attempts = attempts.saturating_add(1);
            same_target = same_target.saturating_add(1);
            let outcome = execute_attempt(
                admission,
                native,
                candidate,
                &reliability,
                deadline,
                reservation,
                target_permit,
                logical_started,
            )
            .await;
            let (condition, kind, retry_after) = match outcome {
                AttemptResult::Response(response) => return Ok(response),
                AttemptResult::Failure { condition, kind } => (Some(condition), kind, None),
                AttemptResult::RetryAfter {
                    condition,
                    kind,
                    delay,
                } => (Some(condition), kind, Some(delay)),
                AttemptResult::FailoverOnly { kind } => (None, kind, None),
            };
            last_error = Some(kind);
            if matches!(
                kind,
                ProtocolErrorKind::InvalidRequest
                    | ProtocolErrorKind::RequestTooLarge
                    | ProtocolErrorKind::UnsupportedCapability
                    | ProtocolErrorKind::StateOriginUnavailable
            ) {
                return Err(gateway_error(&admission, kind));
            }
            let retry_same = native.intent.replay_safe
                && condition.is_some_and(|condition| {
                    reliability.retry_policy.conditions.contains(&condition)
                })
                && same_target <= reliability.attempt_policy.max_same_target_retries
                && attempts < reliability.attempt_policy.max_total_attempts;
            if retry_same && retry_backoff(&reliability, same_target, deadline, retry_after).await {
                continue;
            }
            if !reliability.failover_policy.enabled
                || (reliability.failover_policy.require_replay_safe_request
                    && !native.intent.replay_safe)
            {
                return Err(gateway_error(&admission, kind));
            }
            break;
        }
    }
    let kind = if Instant::now() >= deadline {
        ProtocolErrorKind::DeadlineExceeded
    } else {
        last_error.unwrap_or(ProtocolErrorKind::RouteUnavailable)
    };
    Err(gateway_error(&admission, kind))
}

pub(super) async fn candidates_for_request<'a>(
    admission: &'a AdmissionContext,
    native: &NativeRequest,
) -> Result<Vec<&'a Candidate>, ProtocolError> {
    let Some(reference) = native.intent.continuation_reference.as_deref() else {
        return Ok(admission.candidates.iter().collect());
    };
    let coordinator = admission
        .coordinator
        .as_ref()
        .ok_or_else(|| gateway_error(admission, ProtocolErrorKind::StateOriginUnavailable))?;
    let principal_kind = match admission.principal {
        GatewayPrincipal::GatewayKey { .. } => "gateway_key",
        GatewayPrincipal::LocalUser { .. } => "local_user",
    };
    let origin = coordinator
        .get_state_origin(
            admission.organization.id,
            principal_kind,
            admission.principal.affinity_uuid(),
            admission.route.id.as_uuid(),
            native.family.as_str(),
            reference,
        )
        .await
        .map_err(|_| gateway_error(admission, ProtocolErrorKind::StateOriginUnavailable))?;
    if origin.organization_id != admission.organization.id.as_uuid()
        || origin.principal_kind != principal_kind
        || origin.principal_affinity_id != admission.principal.affinity_uuid()
        || origin.route_id != admission.route.id.as_uuid()
        || origin.protocol_family != native.family.as_str()
    {
        return Err(gateway_error(
            admission,
            ProtocolErrorKind::StateOriginUnavailable,
        ));
    }
    let candidate = admission.candidates.iter().find(|candidate| {
        let key = candidate.deployment.client_key();
        origin.target_id == candidate.target.id.as_uuid()
            && origin.deployment_id == candidate.deployment.id.as_uuid()
            && origin.deployment_config_version == candidate.deployment.config_version
            && origin.endpoint_id == candidate.deployment.endpoint_id.as_uuid()
            && origin.endpoint_config_version == key.endpoint_config_version
            && origin.credential_id == key.credential_id.as_uuid()
            && origin.credential_state_identity_version
                == candidate.deployment.credential_state_identity_version
            && origin.transport_kind == candidate.deployment.transport_kind.as_str()
            && origin.origin == accounting_origin_str(candidate.deployment.origin)
    });
    candidate
        .map(|candidate| vec![candidate])
        .ok_or_else(|| gateway_error(admission, ProtocolErrorKind::StateOriginUnavailable))
}

pub(super) fn logical_admission_error(
    admission: &AdmissionContext,
    error: LogicalAdmissionError,
) -> ProtocolError {
    let kind = match error {
        LogicalAdmissionError::RateDenied => ProtocolErrorKind::RateLimited,
        LogicalAdmissionError::ConcurrencyDenied => ProtocolErrorKind::Overloaded,
        LogicalAdmissionError::BudgetDenied => ProtocolErrorKind::BudgetDenied,
        LogicalAdmissionError::PolicyUnavailable
        | LogicalAdmissionError::CoordinatorUnavailable => ProtocolErrorKind::RouteUnavailable,
    };
    gateway_error(admission, kind)
}

fn hold_request_permits(
    response: Response<Body>,
    permit: LogicalRequestPermit,
    global_permit: OwnedSemaphorePermit,
) -> Response<Body> {
    let (parts, body) = response.into_parts();
    let output = stream! {
        let _permit = permit;
        let _global_permit = global_permit;
        let mut body = body.into_data_stream();
        while let Some(chunk) = body.next().await {
            yield chunk;
        }
    };
    Response::from_parts(parts, Body::from_stream(output))
}

pub(super) fn validate_request_bounds(
    admission: &AdmissionContext,
    native: &NativeRequest,
) -> Result<(), ProtocolError> {
    let length = u64::try_from(native.original_body.len()).unwrap_or(u64::MAX);
    if length > admission.effective_request_policy.max_request_body_bytes {
        return Err(gateway_error(admission, ProtocolErrorKind::RequestTooLarge));
    }
    if native
        .intent
        .requested_output_bound
        .is_some_and(|bound| bound > admission.effective_request_policy.max_output_units)
    {
        return Err(ProtocolError::new(
            native.family,
            ProtocolErrorKind::InvalidRequest,
            admission.request_id.clone(),
            "requested output exceeds the route limit",
        ));
    }
    Ok(())
}

pub(super) fn maximum_output_units(admission: &AdmissionContext, candidate: &Candidate) -> u64 {
    candidate
        .target
        .narrowing_constraints
        .max_output_units
        .unwrap_or(admission.effective_request_policy.max_output_units)
        .min(admission.effective_request_policy.max_output_units)
}

pub(super) fn candidate_policy_ready(admission: &AdmissionContext, candidate: &Candidate) -> bool {
    let GatewayPrincipal::GatewayKey { verifier, .. } = &admission.principal else {
        return true;
    };
    let Some(key_policy) = admission
        .generation
        .snapshot
        .catalog
        .key_budget_policies
        .get(&verifier.budget_policy_id)
        .filter(|policy| policy.active)
        .and_then(|policy| policy.active_version.as_ref())
    else {
        return false;
    };
    let Some(origin_policy) = admission
        .organization
        .origin_budgets
        .get(&candidate.deployment.origin)
        .filter(|policy| policy.active)
        .and_then(|policy| policy.active_version.as_ref())
    else {
        return false;
    };
    let _ = (key_policy, origin_policy);
    true
}

enum AttemptResult {
    Response(Response<Body>),
    Failure {
        condition: RetryCondition,
        kind: ProtocolErrorKind,
    },
    RetryAfter {
        condition: RetryCondition,
        kind: ProtocolErrorKind,
        delay: Duration,
    },
    FailoverOnly {
        kind: ProtocolErrorKind,
    },
}

pub(super) struct LogicalTelemetry {
    admission: AdmissionContext,
    started: Instant,
    recorded: bool,
}

impl LogicalTelemetry {
    pub(super) fn new(admission: &AdmissionContext, started: Instant) -> Self {
        Self {
            admission: admission.clone(),
            started,
            recorded: false,
        }
    }

    pub(super) fn deadline_after(&self, duration: Duration) -> Instant {
        self.started + duration
    }

    pub(super) fn finish(
        &mut self,
        outcome_class: &'static str,
        usage: Option<&ProviderUsage>,
        deployment: Option<&DeploymentSnapshot>,
    ) {
        if !self.recorded {
            self.admission.usage.record_logical(
                &self.admission,
                outcome_class,
                usage,
                deployment,
                self.started.elapsed(),
            );
            self.recorded = true;
        }
    }
}

impl Drop for LogicalTelemetry {
    fn drop(&mut self) {
        if !self.recorded {
            self.admission.usage.record_logical(
                &self.admission,
                "stream_interrupted",
                None,
                None,
                self.started.elapsed(),
            );
        }
    }
}

pub(super) struct AttemptTelemetry {
    admission: AdmissionContext,
    candidate: Candidate,
    estimated_cost_nanos: Option<u128>,
    started: Instant,
    recorded: bool,
}

impl AttemptTelemetry {
    pub(super) fn new(
        admission: &AdmissionContext,
        candidate: &Candidate,
        reservation: &AttemptReservation,
    ) -> Self {
        Self {
            admission: admission.clone(),
            candidate: candidate.clone(),
            estimated_cost_nanos: reservation.estimated_cost_nanos(),
            started: Instant::now(),
            recorded: false,
        }
    }

    pub(super) fn finish(
        mut self,
        terminal_class: AttemptTerminalClass,
        usage: Option<&ProviderUsage>,
    ) {
        self.admission.usage.record_attempt(
            &self.admission,
            &self.candidate,
            terminal_class,
            self.estimated_cost_nanos,
            usage,
            self.started.elapsed(),
        );
        self.recorded = true;
    }
}

impl Drop for AttemptTelemetry {
    fn drop(&mut self) {
        if !self.recorded {
            self.admission.usage.record_attempt(
                &self.admission,
                &self.candidate,
                AttemptTerminalClass::UnknownOrAmbiguous,
                self.estimated_cost_nanos,
                None,
                self.started.elapsed(),
            );
        }
    }
}

async fn execute_attempt(
    admission: &AdmissionContext,
    native: &NativeRequest,
    candidate: &Candidate,
    reliability: &ReliabilityPolicySnapshot,
    overall_deadline: Instant,
    mut reservation: AttemptReservation,
    target_permit: TargetAttemptPermit,
    logical_started: Instant,
) -> AttemptResult {
    let telemetry = AttemptTelemetry::new(admission, candidate, &reservation);
    let Some(client) = admission
        .generation
        .credential_clients
        .clients
        .get(&candidate.deployment.client_key())
        .cloned()
    else {
        reservation.definitely_not_dispatched();
        telemetry.finish(AttemptTerminalClass::DefinitelyNotDispatched, None);
        return unavailable(RetryCondition::ConnectFailure);
    };
    let request_length = u64::try_from(native.original_body.len()).unwrap_or(u64::MAX);
    if !client.request_body_allowed(request_length) {
        reservation.definitely_not_dispatched();
        telemetry.finish(AttemptTerminalClass::DefinitelyNotDispatched, None);
        return AttemptResult::Failure {
            condition: RetryCondition::ConnectFailure,
            kind: ProtocolErrorKind::RequestTooLarge,
        };
    }
    let maximum_output = maximum_output_units(admission, candidate);
    let body = match adapt_provider_body(
        native,
        candidate.deployment.transport_kind,
        &candidate.deployment.upstream_model_id,
        maximum_output,
    ) {
        Ok(body) => body,
        Err(_) => {
            reservation.definitely_not_dispatched();
            telemetry.finish(AttemptTerminalClass::DefinitelyNotDispatched, None);
            return AttemptResult::Failure {
                condition: RetryCondition::ConnectFailure,
                kind: ProtocolErrorKind::InvalidRequest,
            };
        }
    };
    let endpoint = admission
        .generation
        .snapshot
        .catalog
        .endpoints
        .get(&candidate.deployment.endpoint_id)
        .expect("runtime deployments reference an endpoint");
    let url = match upstream_url(
        native,
        candidate.deployment.transport_kind,
        &candidate.deployment.upstream_model_id,
        endpoint,
    ) {
        Ok(url) => url,
        Err(_) => {
            reservation.definitely_not_dispatched();
            telemetry.finish(AttemptTerminalClass::DefinitelyNotDispatched, None);
            return unavailable(RetryCondition::ConnectFailure);
        }
    };
    let connect_timeout_ms = candidate
        .target
        .timeout_overrides
        .connect_timeout_ms
        .unwrap_or(reliability.deadline_policy.connect_timeout_ms);
    let authentication_timeout = bounded_phase_timeout(overall_deadline, connect_timeout_ms);
    let request = match timeout(
        authentication_timeout,
        upstream_request(
            &client.http,
            client.as_ref(),
            candidate.deployment.transport_kind,
            url,
            body,
            &admission.request_id,
        ),
    )
    .await
    {
        Ok(Ok(request)) => request,
        Ok(Err(())) => {
            reservation.definitely_not_dispatched();
            telemetry.finish(AttemptTerminalClass::DefinitelyNotDispatched, None);
            target_permit.failure();
            return failover_only();
        }
        Err(_) => {
            reservation.definitely_not_dispatched();
            telemetry.finish(AttemptTerminalClass::DefinitelyNotDispatched, None);
            target_permit.failure();
            return unavailable(RetryCondition::ConnectTimeout);
        }
    };
    let header_timeout = bounded_phase_timeout(
        overall_deadline,
        candidate
            .target
            .timeout_overrides
            .response_header_timeout_ms
            .unwrap_or(reliability.deadline_policy.response_header_timeout_ms),
    );
    let response = match timeout(
        header_timeout,
        client.execute_attempt(request, connect_timeout_ms),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            let condition = classify_pre_header_transport_error(&error);
            if error.is_connect() {
                reservation.definitely_not_dispatched();
                telemetry.finish(AttemptTerminalClass::DefinitelyNotDispatched, None);
            }
            target_permit.failure();
            return unavailable(condition);
        }
        Err(_) => {
            target_permit.failure();
            return unavailable(RetryCondition::ResponseHeaderTimeout);
        }
    };
    match classify_upstream_status(response.status()) {
        Some(UpstreamStatusFailure::Retryable(condition)) => {
            let retry_after = parse_retry_after(
                response.headers().get(header::RETRY_AFTER),
                SystemTime::now(),
            );
            telemetry.finish(AttemptTerminalClass::Actual, None);
            target_permit.failure();
            return retry_after.map_or(
                AttemptResult::Failure {
                    condition,
                    kind: ProtocolErrorKind::UpstreamUnavailable,
                },
                |delay| AttemptResult::RetryAfter {
                    condition,
                    kind: ProtocolErrorKind::UpstreamUnavailable,
                    delay,
                },
            );
        }
        Some(UpstreamStatusFailure::AuthOrConfiguration) => {
            telemetry.finish(AttemptTerminalClass::Actual, None);
            target_permit.failure();
            return failover_only();
        }
        Some(UpstreamStatusFailure::ClientInvalid) => {
            telemetry.finish(AttemptTerminalClass::Actual, None);
            return AttemptResult::Failure {
                condition: RetryCondition::Provider5xx,
                kind: ProtocolErrorKind::InvalidRequest,
            };
        }
        None => {}
    }
    match native.intent.response_mode {
        ResponseMode::Json => {
            non_streaming_response(
                response,
                client.as_ref(),
                admission,
                candidate,
                reliability,
                overall_deadline,
                reservation,
                target_permit,
                telemetry,
                logical_started,
            )
            .await
        }
        ResponseMode::Sse => {
            streaming_response(
                response,
                client,
                admission,
                candidate,
                reliability,
                overall_deadline,
                reservation,
                target_permit,
                telemetry,
                logical_started,
            )
            .await
        }
        ResponseMode::WebSocket => {
            reservation.definitely_not_dispatched();
            telemetry.finish(AttemptTerminalClass::DefinitelyNotDispatched, None);
            AttemptResult::Failure {
                condition: RetryCondition::ConnectFailure,
                kind: ProtocolErrorKind::UnsupportedCapability,
            }
        }
    }
}

async fn non_streaming_response(
    mut upstream: reqwest::Response,
    client: &CredentialClient,
    admission: &AdmissionContext,
    candidate: &Candidate,
    reliability: &ReliabilityPolicySnapshot,
    overall_deadline: Instant,
    mut reservation: AttemptReservation,
    target_permit: TargetAttemptPermit,
    telemetry: AttemptTelemetry,
    logical_started: Instant,
) -> AttemptResult {
    let mut target_permit = Some(target_permit);
    let maximum = client
        .max_response_body_bytes
        .min(admission.effective_request_policy.max_response_body_bytes);
    let body_timeout = candidate
        .target
        .timeout_overrides
        .body_timeout_ms
        .unwrap_or(reliability.deadline_policy.body_timeout_ms);
    let read = async {
        let mut body = Vec::new();
        while let Some(chunk) = upstream.chunk().await.map_err(|_| ())? {
            let next = body.len().checked_add(chunk.len()).ok_or(())?;
            if u64::try_from(next).unwrap_or(u64::MAX) > maximum {
                return Err(());
            }
            body.extend_from_slice(&chunk);
        }
        Ok::<_, ()>(body)
    };
    let duration = bounded_phase_timeout(overall_deadline, body_timeout);
    let Ok(Ok(body)) = timeout(duration, read).await else {
        mark_target_failure(&mut target_permit);
        return AttemptResult::Failure {
            condition: RetryCondition::ResponseHeaderTimeout,
            kind: ProtocolErrorKind::UpstreamUnavailable,
        };
    };
    let value = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(value) => value,
        Err(_) => {
            mark_target_failure(&mut target_permit);
            return AttemptResult::Failure {
                condition: RetryCondition::Provider5xx,
                kind: ProtocolErrorKind::UpstreamUnavailable,
            };
        }
    };
    let usage = extract_json_usage(candidate.deployment.transport_kind, &value);
    if let Some(state_id) = response_state_id(candidate.deployment.transport_kind, &value)
        && persist_state_origin(admission, candidate, &state_id)
            .await
            .is_err()
    {
        settle_from_usage(&mut reservation, &candidate.deployment, usage.clone());
        telemetry.finish(AttemptTerminalClass::Actual, Some(&usage));
        mark_target_success(&mut target_permit);
        return AttemptResult::Failure {
            condition: RetryCondition::ConnectFailure,
            kind: ProtocolErrorKind::StateOriginUnavailable,
        };
    }
    settle_from_usage(&mut reservation, &candidate.deployment, usage.clone());
    telemetry.finish(AttemptTerminalClass::Actual, Some(&usage));
    mark_target_success(&mut target_permit);
    admission.usage.record_logical(
        admission,
        "success",
        Some(&usage),
        Some(&candidate.deployment),
        logical_started.elapsed(),
    );
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::OK;
    set_downstream_headers(response.headers_mut(), admission, false);
    AttemptResult::Response(response)
}

async fn streaming_response(
    mut upstream: reqwest::Response,
    client: Arc<CredentialClient>,
    admission: &AdmissionContext,
    candidate: &Candidate,
    reliability: &ReliabilityPolicySnapshot,
    overall_deadline: Instant,
    mut reservation: AttemptReservation,
    target_permit: TargetAttemptPermit,
    telemetry: AttemptTelemetry,
    logical_started: Instant,
) -> AttemptResult {
    let mut target_permit = Some(target_permit);
    let transport = candidate.deployment.transport_kind;
    let requires_state_origin = matches!(
        transport,
        TransportKind::OpenaiResponsesHttp
            | TransportKind::OpenaiCodexResponses
            | TransportKind::AzureOpenaiResponses
    );
    let maximum = client
        .max_response_body_bytes
        .min(admission.effective_request_policy.max_response_body_bytes);
    let precommit_maximum = reliability
        .commitment_policy
        .stream_precommit_buffer_bytes
        .min(maximum);
    let classification_deadline = overall_deadline.min(
        Instant::now()
            + Duration::from_millis(
                reliability
                    .deadline_policy
                    .pre_commit_classification_timeout_ms,
            ),
    );
    let mut inspection = StreamInspection::new(transport);
    let mut precommit = Vec::new();
    let mut upstream_total = 0_usize;
    let mut precommit_events = 0_u64;
    loop {
        let wait = classification_deadline.saturating_duration_since(Instant::now());
        if wait.is_zero() {
            mark_target_failure(&mut target_permit);
            return AttemptResult::Failure {
                condition: RetryCondition::ResponseHeaderTimeout,
                kind: ProtocolErrorKind::UpstreamUnavailable,
            };
        }
        let next = match timeout(wait, upstream.chunk()).await {
            Ok(Ok(Some(chunk))) if !chunk.is_empty() => chunk,
            Ok(Ok(None)) => {
                mark_target_failure(&mut target_permit);
                return AttemptResult::Failure {
                    condition: RetryCondition::ProviderOverloaded,
                    kind: ProtocolErrorKind::UpstreamUnavailable,
                };
            }
            _ => {
                mark_target_failure(&mut target_permit);
                return AttemptResult::Failure {
                    condition: RetryCondition::ResponseHeaderTimeout,
                    kind: ProtocolErrorKind::UpstreamUnavailable,
                };
            }
        };
        upstream_total = match upstream_total.checked_add(next.len()) {
            Some(total) if u64::try_from(total).unwrap_or(u64::MAX) <= maximum => total,
            _ => {
                mark_target_failure(&mut target_permit);
                return AttemptResult::Failure {
                    condition: RetryCondition::ProviderOverloaded,
                    kind: ProtocolErrorKind::UpstreamUnavailable,
                };
            }
        };
        let transformed = match inspection.push(&next) {
            Ok(value) => value,
            Err(()) => {
                mark_target_failure(&mut target_permit);
                return AttemptResult::Failure {
                    condition: RetryCondition::ProviderOverloaded,
                    kind: ProtocolErrorKind::UpstreamUnavailable,
                };
            }
        };
        if !transformed.is_empty() {
            precommit_events = precommit_events.saturating_add(1);
            precommit.extend_from_slice(&transformed);
        }
        if u64::try_from(precommit.len()).unwrap_or(u64::MAX) > precommit_maximum
            || precommit_events > reliability.commitment_policy.stream_precommit_buffer_events
        {
            mark_target_failure(&mut target_permit);
            return AttemptResult::Failure {
                condition: RetryCondition::ProviderOverloaded,
                kind: ProtocolErrorKind::UpstreamUnavailable,
            };
        }
        if !precommit.is_empty()
            && (!requires_state_origin || !inspection.inspector.state_ids().is_empty())
        {
            break;
        }
    }
    let pinned_state_ids = inspection.inspector.state_ids().clone();
    for state_id in &pinned_state_ids {
        if persist_state_origin(admission, candidate, state_id)
            .await
            .is_err()
        {
            let usage = inspection.inspector.latest_usage();
            settle_from_usage(&mut reservation, &candidate.deployment, usage.clone());
            telemetry.finish(AttemptTerminalClass::Actual, Some(&usage));
            mark_target_success(&mut target_permit);
            return AttemptResult::Failure {
                condition: RetryCondition::ConnectFailure,
                kind: ProtocolErrorKind::StateOriginUnavailable,
            };
        }
    }
    let idle_ms = candidate
        .target
        .timeout_overrides
        .stream_idle_timeout_ms
        .unwrap_or(reliability.deadline_policy.stream_idle_timeout_ms);
    let stream_seconds = effective_stream_duration_limit(admission);
    let stream_deadline = Instant::now() + Duration::from_secs(u64::from(stream_seconds));
    let deployment = candidate.deployment.clone();
    let logical = LogicalTelemetry::new(admission, logical_started);
    let output = stream! {
        let mut reservation = reservation;
        let telemetry = telemetry;
        let mut logical = logical;
        let mut completed = false;
        let mut terminal_error = None;
        yield Ok::<_, io::Error>(Bytes::from(precommit));
        loop {
            if Instant::now() >= stream_deadline {
                terminal_error = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "stream duration exceeded",
                ));
                break;
            }
            let next = timeout(Duration::from_millis(idle_ms), upstream.chunk()).await;
            let chunk = match next {
                Ok(Ok(Some(chunk))) => chunk,
                Ok(Ok(None)) => {
                    match inspection.inspector.terminal_outcome() {
                        StreamTerminalOutcome::Complete => completed = true,
                        StreamTerminalOutcome::ProviderFailure => {
                            terminal_error = Some(io::Error::other(
                                "upstream reported a terminal provider failure",
                            ));
                        }
                        StreamTerminalOutcome::Incomplete => {
                            terminal_error = Some(io::Error::other(
                                "upstream stream ended without a terminal event",
                            ));
                        }
                    }
                    break;
                }
                Ok(Err(_)) => {
                    terminal_error = Some(io::Error::other("upstream stream interrupted"));
                    break;
                }
                Err(_) => {
                    terminal_error = Some(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "upstream stream idle timeout",
                    ));
                    break;
                }
            };
            let Some(next_total) = upstream_total.checked_add(chunk.len()) else {
                terminal_error = Some(io::Error::other("response size overflow"));
                break;
            };
            upstream_total = next_total;
            if u64::try_from(upstream_total).unwrap_or(u64::MAX) > maximum {
                terminal_error = Some(io::Error::other("response body limit exceeded"));
                break;
            }
            let transformed = match inspection.push(&chunk) {
                Ok(value) => value,
                Err(()) => {
                    terminal_error = Some(io::Error::other(
                        "upstream stream framing is invalid",
                    ));
                    break;
                }
            };
            if requires_state_origin && inspection.inspector.state_ids() != &pinned_state_ids {
                terminal_error = Some(io::Error::other(
                    "upstream changed the response state identity",
                ));
                break;
            }
            if !transformed.is_empty() {
                yield Ok(Bytes::from(transformed));
            }
        }
        let usage = inspection.inspector.latest_usage();
        if completed {
            settle_from_usage(&mut reservation, &deployment, usage.clone());
            telemetry.finish(AttemptTerminalClass::Actual, Some(&usage));
            mark_target_success(&mut target_permit);
            logical.finish("success", Some(&usage), Some(&deployment));
        } else {
            let settled_actual = settle_from_usage(&mut reservation, &deployment, usage.clone());
            telemetry.finish(
                if settled_actual {
                    AttemptTerminalClass::Actual
                } else {
                    AttemptTerminalClass::UnknownOrAmbiguous
                },
                Some(&usage),
            );
            mark_target_failure(&mut target_permit);
            logical.finish("stream_interrupted", Some(&usage), Some(&deployment));
        }
        if let Some(error) = terminal_error {
            yield Err(error);
        }
    };
    let mut response = Response::new(Body::from_stream(output));
    *response.status_mut() = StatusCode::OK;
    set_downstream_headers(response.headers_mut(), admission, true);
    AttemptResult::Response(response)
}

struct StreamInspection {
    transport: TransportKind,
    event_stream: Option<AwsEventStreamDecoder>,
    inspector: SseInspector,
}

impl StreamInspection {
    fn new(transport: TransportKind) -> Self {
        Self {
            transport,
            event_stream: (transport == TransportKind::AnthropicMessagesBedrock)
                .then(AwsEventStreamDecoder::default),
            inspector: SseInspector::default(),
        }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>, ()> {
        let output = if let Some(decoder) = &mut self.event_stream {
            let mut output = Vec::new();
            for payload in decoder.push(bytes).map_err(|_| ())? {
                let value: serde_json::Value = serde_json::from_slice(&payload).map_err(|_| ())?;
                let event = value
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(())?;
                output.extend_from_slice(format!("event: {event}\ndata: ").as_bytes());
                output.extend_from_slice(&payload);
                output.extend_from_slice(b"\n\n");
            }
            output
        } else {
            bytes.to_vec()
        };
        self.inspector
            .push(self.transport, &output)
            .map_err(|_| ())?;
        Ok(output)
    }
}

async fn upstream_request(
    http: &reqwest::Client,
    client: &CredentialClient,
    transport: TransportKind,
    url: url::Url,
    body: Vec<u8>,
    request_id: &str,
) -> Result<reqwest::Request, ()> {
    let mut builder = http
        .post(url)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            "x-request-id",
            HeaderValue::from_str(request_id).map_err(|_| ())?,
        );
    if transport == TransportKind::AnthropicMessagesNative {
        builder = builder.header("anthropic-version", "2023-06-01");
    }
    if transport == TransportKind::AnthropicMessagesBedrock {
        builder = builder.header(header::ACCEPT, "application/vnd.amazon.eventstream");
    }
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
    let mut request = builder.body(body.clone()).build().map_err(|_| ())?;
    if let CredentialInjection::Dynamic(authenticator) = &client.injection {
        authenticator
            .apply(&mut request, &body)
            .await
            .map_err(|_| ())?;
    }
    Ok(request)
}

pub(super) fn prefixed_header(
    prefix: &str,
    value: &HeaderValue,
) -> Result<HeaderValue, http::header::InvalidHeaderValue> {
    let mut bytes = Vec::with_capacity(prefix.len() + value.as_bytes().len());
    bytes.extend_from_slice(prefix.as_bytes());
    bytes.extend_from_slice(value.as_bytes());
    HeaderValue::from_bytes(&bytes)
}

pub(super) fn classify_pre_header_transport_error(error: &reqwest::Error) -> RetryCondition {
    if error.is_connect() && error.is_timeout() {
        RetryCondition::ConnectTimeout
    } else if error.is_connect() {
        RetryCondition::ConnectFailure
    } else if error.is_timeout() {
        RetryCondition::ResponseHeaderTimeout
    } else {
        RetryCondition::ConnectFailure
    }
}

pub(super) fn settle_from_usage(
    reservation: &mut AttemptReservation,
    deployment: &DeploymentSnapshot,
    usage: crate::adapters::provider::wire::ProviderUsage,
) -> bool {
    if usage.completeness == UsageCompleteness::Absent {
        return false;
    }
    if let Some(PricingOutcome::Known { cost_nanos }) = usage.price(deployment) {
        reservation.settle_actual_cost(cost_nanos);
        true
    } else {
        false
    }
}

pub(super) async fn persist_state_origin(
    admission: &AdmissionContext,
    candidate: &Candidate,
    state_id: &str,
) -> Result<(), ()> {
    let coordinator = admission.coordinator.as_ref().ok_or(())?;
    let key = candidate.deployment.client_key();
    let principal_kind = match &admission.principal {
        GatewayPrincipal::GatewayKey { .. } => "gateway_key",
        GatewayPrincipal::LocalUser { .. } => "local_user",
    };
    coordinator
        .put_state_origin(
            admission.organization.id,
            principal_kind,
            admission.principal.affinity_uuid(),
            admission.route.id.as_uuid(),
            admission.route.ingress_protocol_family.as_str(),
            state_id,
            &StateOrigin {
                organization_id: admission.organization.id.as_uuid(),
                principal_kind: principal_kind.to_owned(),
                principal_affinity_id: admission.principal.affinity_uuid(),
                route_id: admission.route.id.as_uuid(),
                protocol_family: admission.route.ingress_protocol_family.as_str().to_owned(),
                target_id: candidate.target.id.as_uuid(),
                deployment_id: candidate.deployment.id.as_uuid(),
                deployment_config_version: candidate.deployment.config_version,
                endpoint_id: candidate.deployment.endpoint_id.as_uuid(),
                endpoint_config_version: key.endpoint_config_version,
                credential_id: key.credential_id.as_uuid(),
                credential_state_identity_version: candidate
                    .deployment
                    .credential_state_identity_version,
                origin: accounting_origin_str(candidate.deployment.origin).to_owned(),
                transport_kind: candidate.deployment.transport_kind.as_str().to_owned(),
            },
            Duration::from_secs(u64::from(
                admission.effective_request_policy.state_origin_ttl_seconds,
            )),
        )
        .await
        .map_err(|_| ())
}

const fn accounting_origin_str(origin: AccountingOrigin) -> &'static str {
    match origin {
        AccountingOrigin::SystemProvided => "system_provided",
        AccountingOrigin::OrganizationByok => "organization_byok",
    }
}

fn set_downstream_headers(
    headers: &mut axum::http::HeaderMap,
    admission: &AdmissionContext,
    streaming: bool,
) {
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(if streaming {
            "text/event-stream"
        } else {
            "application/json"
        }),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(value) = HeaderValue::from_str(&admission.request_id) {
        headers.insert(HeaderName::from_static("x-request-id"), value);
    }
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UpstreamStatusFailure {
    Retryable(RetryCondition),
    AuthOrConfiguration,
    ClientInvalid,
}

pub(super) fn classify_upstream_status(
    status: reqwest::StatusCode,
) -> Option<UpstreamStatusFailure> {
    if status.is_success() || status == StatusCode::SWITCHING_PROTOCOLS {
        None
    } else if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        Some(UpstreamStatusFailure::Retryable(
            RetryCondition::ProviderRateLimited,
        ))
    } else if status == reqwest::StatusCode::SERVICE_UNAVAILABLE
        || status == reqwest::StatusCode::BAD_GATEWAY
    {
        Some(UpstreamStatusFailure::Retryable(
            RetryCondition::ProviderOverloaded,
        ))
    } else if status.is_server_error() {
        Some(UpstreamStatusFailure::Retryable(
            RetryCondition::Provider5xx,
        ))
    } else if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
        || !status.is_client_error()
    {
        Some(UpstreamStatusFailure::AuthOrConfiguration)
    } else {
        Some(UpstreamStatusFailure::ClientInvalid)
    }
}

fn unavailable(condition: RetryCondition) -> AttemptResult {
    AttemptResult::Failure {
        condition,
        kind: ProtocolErrorKind::UpstreamUnavailable,
    }
}

fn failover_only() -> AttemptResult {
    AttemptResult::FailoverOnly {
        kind: ProtocolErrorKind::UpstreamUnavailable,
    }
}

fn mark_target_failure(permit: &mut Option<TargetAttemptPermit>) {
    if let Some(permit) = permit.take() {
        permit.failure();
    }
}

fn mark_target_success(permit: &mut Option<TargetAttemptPermit>) {
    if let Some(permit) = permit.take() {
        permit.success();
    }
}

pub(super) async fn retry_backoff(
    reliability: &ReliabilityPolicySnapshot,
    retry_number: u8,
    deadline: Instant,
    retry_after: Option<Duration>,
) -> bool {
    let shift = u32::from(retry_number.saturating_sub(1)).min(16);
    let base = reliability
        .retry_policy
        .initial_backoff_ms
        .saturating_mul(1_u64 << shift)
        .min(reliability.retry_policy.max_backoff_ms);
    let jitter = u64::from(reliability.retry_policy.jitter_ratio_millis);
    let spread = base.saturating_mul(jitter) / 1000;
    let mut delay = if spread == 0 {
        Duration::from_millis(base)
    } else {
        Duration::from_millis(
            rand::rng().random_range(base.saturating_sub(spread)..=base.saturating_add(spread)),
        )
    };
    if reliability.retry_policy.honor_retry_after
        && let Some(retry_after) = retry_after
    {
        delay = delay.max(retry_after);
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if delay.saturating_add(Duration::from_millis(10)) >= remaining {
        return false;
    }
    sleep(delay).await;
    true
}

pub(super) fn bounded_phase_timeout(deadline: Instant, milliseconds: u64) -> Duration {
    Duration::from_millis(milliseconds).min(deadline.saturating_duration_since(Instant::now()))
}

pub(super) fn gateway_error(
    admission: &AdmissionContext,
    kind: ProtocolErrorKind,
) -> ProtocolError {
    let message = match kind {
        ProtocolErrorKind::RequestTooLarge => "request exceeds the configured size limit",
        ProtocolErrorKind::UnsupportedCapability => "requested capability is unavailable",
        ProtocolErrorKind::BudgetDenied => "request cannot be admitted by the active budget policy",
        ProtocolErrorKind::DeadlineExceeded => "request deadline was exhausted",
        ProtocolErrorKind::InvalidRequest => "upstream rejected the request",
        _ => "no upstream target is currently available",
    };
    ProtocolError::new(
        admission.route.ingress_protocol_family,
        kind,
        admission.request_id.clone(),
        message,
    )
}

pub(super) fn effective_stream_duration_limit(admission: &AdmissionContext) -> u32 {
    let principal_rate_limit = match &admission.principal {
        GatewayPrincipal::GatewayKey { verifier, .. } => verifier
            .rate_policy_id
            .and_then(|id| admission.generation.snapshot.catalog.rate_policies.get(&id))
            .filter(|policy| policy.active)
            .and_then(|policy| policy.active_version.as_ref())
            .map_or(u32::MAX, |version| version.max_stream_seconds),
        GatewayPrincipal::LocalUser { .. } => u32::MAX,
    };
    narrower_stream_duration_limit(
        admission.effective_request_policy.max_stream_seconds,
        principal_rate_limit,
    )
}

const fn narrower_stream_duration_limit(route_limit: u32, principal_limit: u32) -> u32 {
    if route_limit < principal_limit {
        route_limit
    } else {
        principal_limit
    }
}

fn parse_retry_after(value: Option<&HeaderValue>, now: SystemTime) -> Option<Duration> {
    let value = value?.to_str().ok()?;
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let retry_at = httpdate::parse_http_date(value).ok()?;
    Some(retry_at.duration_since(now).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_and_principal_stream_limits_use_the_narrower_value() {
        assert_eq!(narrower_stream_duration_limit(30, 3_600), 30);
        assert_eq!(narrower_stream_duration_limit(3_600, 45), 45);
    }

    #[test]
    fn upstream_auth_status_is_failover_only_and_never_retryable() {
        assert_eq!(
            classify_upstream_status(StatusCode::UNAUTHORIZED),
            Some(UpstreamStatusFailure::AuthOrConfiguration)
        );
        assert_eq!(
            classify_upstream_status(StatusCode::FORBIDDEN),
            Some(UpstreamStatusFailure::AuthOrConfiguration)
        );
        assert_eq!(
            classify_upstream_status(StatusCode::TOO_MANY_REQUESTS),
            Some(UpstreamStatusFailure::Retryable(
                RetryCondition::ProviderRateLimited
            ))
        );
        assert_eq!(
            classify_upstream_status(StatusCode::BAD_REQUEST),
            Some(UpstreamStatusFailure::ClientInvalid)
        );
        assert_eq!(
            classify_upstream_status(StatusCode::SWITCHING_PROTOCOLS),
            None
        );
    }

    #[test]
    fn retry_after_preserves_delta_and_http_date_requirements() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(
            parse_retry_after(Some(&HeaderValue::from_static("7")), now),
            Some(Duration::from_secs(7))
        );
        assert_eq!(
            parse_retry_after(Some(&HeaderValue::from_static("3600")), now),
            Some(Duration::from_secs(3600))
        );
        let date = httpdate::fmt_http_date(now + Duration::from_secs(11));
        assert_eq!(
            parse_retry_after(Some(&HeaderValue::from_str(&date).unwrap()), now),
            Some(Duration::from_secs(11))
        );
        assert_eq!(
            parse_retry_after(Some(&HeaderValue::from_static("not-a-delay")), now),
            None
        );
    }
}
