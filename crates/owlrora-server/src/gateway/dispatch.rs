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
    sync::{OwnedSemaphorePermit, mpsc},
    time::{Instant, sleep, timeout},
};

use crate::{
    adapters::{
        coordinator::StateOrigin,
        provider::wire::{
            AwsEventStreamDecoder, ProviderUsage, SseInspector, StreamCommitment,
            StreamFailureClass, StreamTerminalOutcome, UsageCompleteness, extract_json_usage,
            response_state_id, upstream_url,
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
    LogicalRequestPermit, TargetAttemptPermit,
    lifetime::{RequestLifetime, before},
    usage::AttemptTerminalClass,
};

pub async fn dispatch(
    admission: AdmissionContext,
    native: NativeRequest,
) -> Result<Response<Body>, ProtocolError> {
    let logical_started = Instant::now();
    let mut lifetime =
        RequestLifetime::new(&admission, native.intent.response_mode, logical_started)?;
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
        GatewayPrincipal::GatewayKey { verifier, .. } => match before(
            lifetime.precommit,
            admission.admission_state.admit_gateway_key(
                admission.coordinator.as_ref(),
                &admission.generation,
                verifier,
                u64::try_from(native.original_body.len()).unwrap_or(u64::MAX),
            ),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Err(()) => {
                admission.usage.record_logical(
                    &admission,
                    "deadline_exceeded",
                    None,
                    None,
                    logical_started.elapsed(),
                );
                return Err(gateway_error(
                    &admission,
                    ProtocolErrorKind::DeadlineExceeded,
                ));
            }
            Ok(Err(error)) => {
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
    lifetime.constrain(permit.deadline());
    let mut logical = Some(LogicalTelemetry::new(&admission, logical_started));
    let result = before(
        lifetime.precommit,
        Box::pin(dispatch_admitted(
            &admission,
            &native,
            &mut logical,
            lifetime,
        )),
    )
    .await
    .unwrap_or_else(|()| {
        Err(gateway_error(
            &admission,
            ProtocolErrorKind::DeadlineExceeded,
        ))
    });
    match result {
        Ok(response) => Ok(hold_request_permits(
            response,
            permit,
            global_permit,
            lifetime.terminal,
            Arc::clone(&admission.lifecycle),
            admission.shutdown_stream_timeout,
        )),
        Err(error) => {
            if let Some(logical) = logical.as_mut() {
                logical.finish("failed", None, None);
            }
            Err(error)
        }
    }
}

async fn dispatch_admitted(
    admission: &AdmissionContext,
    native: &NativeRequest,
    logical: &mut Option<LogicalTelemetry>,
    lifetime: RequestLifetime,
) -> Result<Response<Body>, ProtocolError> {
    let mut candidates = candidates_for_request(admission, native).await?;
    if super::isolation::has_semantic_reference(native.family, &native.envelope) {
        candidates.truncate(1);
    }
    let reliability = admission
        .generation
        .snapshot
        .catalog
        .reliability_policies
        .get(&admission.route.reliability_policy_id)
        .filter(|policy| policy.active)
        .cloned()
        .ok_or_else(|| gateway_error(&admission, ProtocolErrorKind::RouteUnavailable))?;
    let deadline = lifetime.precommit;
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
                lifetime,
                reservation,
                target_permit,
                logical,
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
    deadline: Instant,
    lifecycle: Arc<crate::lifecycle::Lifecycle>,
    shutdown_grace: std::time::Duration,
) -> Response<Body> {
    let (parts, body) = response.into_parts();
    let (sender, mut receiver) = mpsc::channel(1);
    // This owner is polled independently of downstream demand. A stalled client
    // cannot keep an upstream attempt or concurrency lease alive past expiry.
    let tracker = lifecycle.response_pumps.clone();
    tracker.spawn(async move {
        let _permit = permit;
        let _global_permit = global_permit;
        let mut body = body.into_data_stream();
        let forward = async {
            while let Some(chunk) = body.next().await {
                let failed = chunk.is_err();
                if sender.send(chunk).await.is_err() || failed {
                    break;
                }
            }
        };
        tokio::select! {
            biased;
            () = lifecycle.cancelled_after(shutdown_grace) => {},
            () = sender.closed() => {},
            _ = before(deadline, forward) => {},
        }
        // Drop the upstream body before releasing the request permits.
        drop(body);
    });
    let output = stream! {
        loop {
            match before(deadline, receiver.recv()).await {
                Ok(Some(chunk)) => yield chunk,
                Ok(None) => break,
                Err(()) => {
                    yield Err(axum::Error::new(io::Error::new(io::ErrorKind::TimedOut, "request lifetime exceeded")));
                    break;
                }
            }
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
    span: Option<crate::telemetry::TraceSpan>,
    admission: AdmissionContext,
    started: Instant,
    latest_usage: Option<ProviderUsage>,
    deployment: Option<DeploymentSnapshot>,
    recorded: bool,
}

impl LogicalTelemetry {
    pub(super) fn new(admission: &AdmissionContext, started: Instant) -> Self {
        let span = admission.usage.telemetry.get().map(|telemetry| {
            let span = telemetry.span(
                "logical",
                admission.route.ingress_protocol_family.as_str(),
                &opentelemetry::Context::new(),
            );
            let _ = admission.trace_parent.set(span.context());
            span
        });
        Self {
            span,
            admission: admission.clone(),
            started,
            latest_usage: None,
            deployment: None,
            recorded: false,
        }
    }

    pub(super) fn observe(&mut self, usage: &ProviderUsage, deployment: &DeploymentSnapshot) {
        if usage.completeness != UsageCompleteness::Absent {
            self.latest_usage = Some(usage.clone());
            self.deployment = Some(deployment.clone());
        }
    }

    pub(super) fn finish(
        &mut self,
        outcome_class: &'static str,
        usage: Option<&ProviderUsage>,
        deployment: Option<&DeploymentSnapshot>,
    ) {
        if !self.recorded {
            if let Some(span) = &self.span {
                span.finish(outcome_class);
            }
            self.admission.usage.record_logical(
                &self.admission,
                outcome_class,
                usage.or(self.latest_usage.as_ref()),
                deployment.or(self.deployment.as_ref()),
                self.started.elapsed(),
            );
            self.recorded = true;
        }
    }
}

impl Drop for LogicalTelemetry {
    fn drop(&mut self) {
        if !self.recorded {
            if let Some(span) = &self.span {
                span.finish("stream_interrupted");
            }
            self.admission.usage.record_logical(
                &self.admission,
                "stream_interrupted",
                self.latest_usage.as_ref(),
                self.deployment.as_ref(),
                self.started.elapsed(),
            );
        }
    }
}

/// Owns response evidence and its reservation together across awaits and yields.
/// Drop is the cancellation path, not a separate estimate-only settlement.
pub(super) struct ResponseSettlement {
    reservation: AttemptReservation,
    telemetry: Option<AttemptTelemetry>,
    usage: ProviderUsage,
}

impl ResponseSettlement {
    pub(super) fn new(reservation: AttemptReservation, telemetry: AttemptTelemetry) -> Self {
        Self {
            reservation,
            telemetry: Some(telemetry),
            usage: ProviderUsage::absent(),
        }
    }

    pub(super) fn observe(&mut self, usage: ProviderUsage) {
        if usage.completeness != UsageCompleteness::Absent {
            self.usage = usage;
        }
    }

    pub(super) fn usage(&self) -> &ProviderUsage {
        &self.usage
    }

    pub(super) fn finish(&mut self) {
        if let Some(telemetry) = self.telemetry.take() {
            let actual = settle_from_usage(
                &mut self.reservation,
                &telemetry.candidate.deployment,
                self.usage.clone(),
            );
            telemetry.finish(
                if actual {
                    AttemptTerminalClass::Actual
                } else {
                    AttemptTerminalClass::UnknownOrAmbiguous
                },
                Some(&self.usage),
            );
        }
    }
}

impl Drop for ResponseSettlement {
    fn drop(&mut self) {
        self.finish();
    }
}

pub(super) struct AttemptTelemetry {
    span: Option<crate::telemetry::TraceSpan>,
    admission: AdmissionContext,
    candidate: Candidate,
    estimated_cost_nanos: Option<u128>,
    started: Instant,
    dispatched: bool,
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
            span: admission.usage.telemetry.get().map(|telemetry| {
                telemetry.span(
                    "attempt",
                    admission.route.ingress_protocol_family.as_str(),
                    &admission.trace_parent.get().cloned().unwrap_or_default(),
                )
            }),
            estimated_cost_nanos: reservation.estimated_cost_nanos(),
            started: Instant::now(),
            dispatched: false,
            recorded: false,
        }
    }

    pub(super) fn mark_dispatched(&mut self) {
        self.dispatched = true;
    }

    pub(super) fn finish(
        mut self,
        terminal_class: AttemptTerminalClass,
        usage: Option<&ProviderUsage>,
    ) {
        if let Some(span) = &self.span {
            span.finish(terminal_class.as_str());
        }
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
            if let Some(span) = &self.span {
                span.finish(if self.dispatched {
                    "unknown_or_ambiguous"
                } else {
                    "definitely_not_dispatched"
                });
            }
            self.admission.usage.record_attempt(
                &self.admission,
                &self.candidate,
                if self.dispatched {
                    AttemptTerminalClass::UnknownOrAmbiguous
                } else {
                    AttemptTerminalClass::DefinitelyNotDispatched
                },
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
    lifetime: RequestLifetime,
    mut reservation: AttemptReservation,
    target_permit: TargetAttemptPermit,
    logical: &mut Option<LogicalTelemetry>,
) -> AttemptResult {
    let overall_deadline = lifetime.precommit;
    let mut telemetry = AttemptTelemetry::new(admission, candidate, &reservation);
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
    let body = match super::isolation::prepare_body(admission, candidate, native, maximum_output) {
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
    reservation.mark_dispatched();
    telemetry.mark_dispatched();
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
                logical,
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
                lifetime,
                reservation,
                target_permit,
                telemetry,
                logical,
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
    reservation: AttemptReservation,
    target_permit: TargetAttemptPermit,
    telemetry: AttemptTelemetry,
    logical: &mut Option<LogicalTelemetry>,
) -> AttemptResult {
    let mut settlement = ResponseSettlement::new(reservation, telemetry);
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
    settlement.observe(usage.clone());
    logical
        .as_mut()
        .expect("logical owner before commitment")
        .observe(&usage, &candidate.deployment);
    if let Some(state_id) = response_state_id(candidate.deployment.transport_kind, &value)
        && persist_state_origin(admission, candidate, &state_id)
            .await
            .is_err()
    {
        settlement.finish();
        mark_target_success(&mut target_permit);
        return AttemptResult::Failure {
            condition: RetryCondition::ConnectFailure,
            kind: ProtocolErrorKind::StateOriginUnavailable,
        };
    }
    settlement.finish();
    mark_target_success(&mut target_permit);
    logical
        .as_mut()
        .expect("logical owner before commitment")
        .finish("success", Some(&usage), Some(&candidate.deployment));
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
    lifetime: RequestLifetime,
    reservation: AttemptReservation,
    target_permit: TargetAttemptPermit,
    telemetry: AttemptTelemetry,
    logical: &mut Option<LogicalTelemetry>,
) -> AttemptResult {
    let mut settlement = ResponseSettlement::new(reservation, telemetry);
    let overall_deadline = lifetime.precommit;
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
    let mut inspection = StreamInspection::new(transport, maximum);
    let mut precommit = Vec::new();
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
        let inspected = inspection.push(&next);
        settlement.observe(inspection.inspector.latest_usage());
        logical
            .as_mut()
            .expect("logical owner before commitment")
            .observe(settlement.usage(), &candidate.deployment);
        let transformed = match inspected {
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
            precommit.extend_from_slice(&transformed);
        }
        let (prefix_bytes, prefix_events) = inspection.inspector.precommit_size();
        if prefix_bytes > precommit_maximum
            || prefix_events > reliability.commitment_policy.stream_precommit_buffer_events
            || (requires_state_origin
                && inspection.inspector.state_ids().is_empty()
                && u64::try_from(precommit.len()).unwrap_or(u64::MAX) > precommit_maximum)
        {
            mark_target_failure(&mut target_permit);
            return AttemptResult::Failure {
                condition: RetryCondition::ProviderOverloaded,
                kind: ProtocolErrorKind::UpstreamUnavailable,
            };
        }
        if inspection.inspector.commitment() == StreamCommitment::Rejected {
            settlement.finish();
            let failure = inspection
                .inspector
                .failure_class()
                .unwrap_or(StreamFailureClass::Unknown);
            if failure != StreamFailureClass::InvalidRequest {
                mark_target_failure(&mut target_permit);
            }
            return stream_failure_result(failure);
        }
        if inspection.inspector.commitment() == StreamCommitment::Ready
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
            settlement.finish();
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
    let stream_deadline = lifetime.terminal;
    let deployment = candidate.deployment.clone();
    let mut logical = logical
        .take()
        .expect("transfer logical owner to response stream");
    logical.observe(settlement.usage(), &deployment);
    let output = stream! {
        let mut settlement = settlement;
        let mut logical = logical;
        let mut completed = false;
        let mut terminal_error = None;
        yield Ok::<_, io::Error>(Bytes::from(precommit));
        loop {
            if inspection.failed {
                terminal_error = Some(io::Error::other("upstream stream framing is invalid"));
                break;
            }
            if inspection.inspector.terminal_outcome() == StreamTerminalOutcome::ProviderFailure {
                terminal_error = Some(io::Error::other("upstream reported a terminal provider failure"));
                break;
            }
            if Instant::now() >= stream_deadline {
                terminal_error = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "stream duration exceeded",
                ));
                break;
            }
            let next = before(stream_deadline.min(Instant::now() + Duration::from_millis(idle_ms)), upstream.chunk()).await;
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
            let inspected = inspection.push(&chunk);
            settlement.observe(inspection.inspector.latest_usage());
            logical.observe(settlement.usage(), &deployment);
            let transformed = match inspected {
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
        let usage = settlement.usage().clone();
        settlement.finish();
        if completed {
            mark_target_success(&mut target_permit);
            logical.finish("success", Some(&usage), Some(&deployment));
        } else {
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

fn stream_failure_result(failure: StreamFailureClass) -> AttemptResult {
    let condition = match failure {
        StreamFailureClass::InvalidRequest => {
            return AttemptResult::Failure {
                condition: RetryCondition::Provider5xx,
                kind: ProtocolErrorKind::InvalidRequest,
            };
        }
        StreamFailureClass::AuthOrConfiguration | StreamFailureClass::Unknown => {
            return failover_only();
        }
        StreamFailureClass::RateLimited => RetryCondition::ProviderRateLimited,
        StreamFailureClass::Overloaded => RetryCondition::ProviderOverloaded,
        StreamFailureClass::ProviderFailure => RetryCondition::Provider5xx,
    };
    AttemptResult::Failure {
        condition,
        kind: ProtocolErrorKind::UpstreamUnavailable,
    }
}

struct StreamInspection {
    transport: TransportKind,
    event_stream: Option<AwsEventStreamDecoder>,
    inspector: SseInspector,
    failed: bool,
    remaining_bytes: u64,
}

impl StreamInspection {
    fn new(transport: TransportKind, maximum_bytes: u64) -> Self {
        Self {
            transport,
            event_stream: (transport == TransportKind::AnthropicMessagesBedrock)
                .then(AwsEventStreamDecoder::default),
            inspector: SseInspector::default(),
            failed: false,
            remaining_bytes: maximum_bytes,
        }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>, ()> {
        if self.failed {
            return Err(());
        }
        let allowed = bytes
            .len()
            .min(usize::try_from(self.remaining_bytes).unwrap_or(usize::MAX));
        let exceeded_size = allowed < bytes.len();
        self.remaining_bytes -= allowed as u64;
        let bytes = &bytes[..allowed];
        let output = if let Some(decoder) = &mut self.event_stream {
            let batch = decoder.push_messages(bytes);
            self.failed = batch.error.is_some();
            let mut output = Vec::new();
            for payload in batch.payloads {
                let value = serde_json::from_slice::<serde_json::Value>(&payload).ok();
                let Some(event) = value
                    .as_ref()
                    .and_then(|value| value.get("type"))
                    .and_then(serde_json::Value::as_str)
                else {
                    self.failed = true;
                    break;
                };
                output.extend_from_slice(format!("event: {event}\ndata: ").as_bytes());
                output.extend_from_slice(&payload);
                output.extend_from_slice(b"\n\n");
            }
            output
        } else {
            bytes.to_vec()
        };
        let batch = self.inspector.push_frames(self.transport, &output);
        self.failed |= exceeded_size || batch.error.is_some();
        if self.failed && self.inspector.commitment() != StreamCommitment::Ready {
            return Err(());
        }
        Ok(batch.bytes)
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
    if usage.completeness != UsageCompleteness::Complete {
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

    #[tokio::test]
    async fn unpolled_response_cancels_upstream_and_releases_permits_at_deadline() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
        let (dropped, receiver) = tokio::sync::oneshot::channel::<()>();
        let upstream = stream! {
            let _dropped = dropped;
            loop {
                yield Ok::<_, io::Error>(Bytes::from_static(b"data: heartbeat\n\n"));
            }
        };
        let response = hold_request_permits(
            Response::new(Body::from_stream(upstream)),
            LogicalRequestPermit::unconstrained(),
            permit,
            Instant::now() + Duration::from_millis(30),
            Arc::new(crate::lifecycle::Lifecycle::default()),
            Duration::from_secs(30),
        );
        // Never poll the downstream body. The bounded channel fills, then expires.
        assert!(
            timeout(Duration::from_secs(2), receiver)
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(semaphore.available_permits(), 1);
        let mut body = response.into_body().into_data_stream();
        assert!(body.next().await.unwrap().is_err());
    }

    #[tokio::test]
    async fn downstream_drop_cancels_pending_upstream_without_waiting_for_deadline() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
        let (dropped, receiver) = tokio::sync::oneshot::channel::<()>();
        let upstream = stream! {
            let _dropped = dropped;
            std::future::pending::<()>().await;
            yield Ok::<_, io::Error>(Bytes::new());
        };
        let response = hold_request_permits(
            Response::new(Body::from_stream(upstream)),
            LogicalRequestPermit::unconstrained(),
            permit,
            Instant::now() + Duration::from_secs(60),
            Arc::new(crate::lifecycle::Lifecycle::default()),
            Duration::from_secs(30),
        );
        drop(response);
        assert!(
            timeout(Duration::from_secs(2), receiver)
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[test]
    fn stream_size_error_preserves_commitment_before_the_limit() {
        let ready = b"data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n";
        let input = [ready.as_slice(), b"data: too-long"].concat();
        for chunk_size in 1..=input.len() {
            let mut inspection =
                StreamInspection::new(TransportKind::OpenaiChatCompletions, ready.len() as u64 + 4);
            let mut forwarded = Vec::new();
            for chunk in input.chunks(chunk_size) {
                forwarded.extend(inspection.push(chunk).unwrap());
                if inspection.failed {
                    break;
                }
            }
            assert_eq!(forwarded, ready);
            assert!(inspection.failed);
            assert_eq!(inspection.inspector.commitment(), StreamCommitment::Ready);
        }
    }

    #[test]
    fn bedrock_frame_error_preserves_prior_valid_events_across_chunks() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let document: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/provider/contracts-v1.json"
        ))
        .unwrap();
        let case = document["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["transport"] == "anthropic_messages_bedrock")
            .unwrap();
        let first = STANDARD
            .decode(case["stream"]["chunks"][0].as_str().unwrap())
            .unwrap();
        let mut broken = first.clone();
        *broken.last_mut().unwrap() ^= 1;
        let input = [first.as_slice(), broken.as_slice()].concat();
        for chunk_size in [1, first.len(), input.len()] {
            let mut inspection =
                StreamInspection::new(TransportKind::AnthropicMessagesBedrock, u64::MAX);
            let mut forwarded = Vec::new();
            for chunk in input.chunks(chunk_size) {
                forwarded.extend(inspection.push(chunk).unwrap());
                if inspection.failed {
                    break;
                }
            }
            assert!(inspection.failed);
            assert_eq!(inspection.inspector.commitment(), StreamCommitment::Ready);
            assert!(String::from_utf8_lossy(&forwarded).contains("message_start"));
        }
    }

    #[test]
    fn precommit_provider_failure_preserves_native_retry_classification() {
        for (native, expected) in [
            ("invalid_request_error", StreamFailureClass::InvalidRequest),
            (
                "authentication_error",
                StreamFailureClass::AuthOrConfiguration,
            ),
            ("rate_limit_error", StreamFailureClass::RateLimited),
            ("overloaded_error", StreamFailureClass::Overloaded),
            ("api_error", StreamFailureClass::ProviderFailure),
            ("future_error", StreamFailureClass::Unknown),
        ] {
            let mut inspection =
                StreamInspection::new(TransportKind::AnthropicMessagesNative, 4096);
            inspection
                .push(
                    format!("data: {{\"type\":\"error\",\"error\":{{\"type\":\"{native}\"}}}}\n\n")
                        .as_bytes(),
                )
                .unwrap();
            assert_eq!(
                inspection.inspector.commitment(),
                StreamCommitment::Rejected
            );
            assert_eq!(inspection.inspector.failure_class(), Some(expected));
            let result = stream_failure_result(expected);
            match expected {
                StreamFailureClass::InvalidRequest => assert!(matches!(
                    result,
                    AttemptResult::Failure {
                        kind: ProtocolErrorKind::InvalidRequest,
                        ..
                    }
                )),
                StreamFailureClass::AuthOrConfiguration | StreamFailureClass::Unknown => {
                    assert!(matches!(result, AttemptResult::FailoverOnly { .. }));
                }
                StreamFailureClass::RateLimited => assert!(matches!(
                    result,
                    AttemptResult::Failure {
                        condition: RetryCondition::ProviderRateLimited,
                        ..
                    }
                )),
                StreamFailureClass::Overloaded => assert!(matches!(
                    result,
                    AttemptResult::Failure {
                        condition: RetryCondition::ProviderOverloaded,
                        ..
                    }
                )),
                StreamFailureClass::ProviderFailure => assert!(matches!(
                    result,
                    AttemptResult::Failure {
                        condition: RetryCondition::Provider5xx,
                        ..
                    }
                )),
            }
        }
    }

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
