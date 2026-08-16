use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use serde_json::json;

use crate::{
    application::{
        AuditQuery, CleanupStateOrigins, CreateCoordinatorRecoveries, ProbeTargets,
        UsageBreakdownQuery, UsageQuery,
    },
    domain::{OrganizationId, SessionId},
};

use super::{app_error, json_response, no_content, no_store, reject_idempotency_key};
use crate::http::{
    ApiError, HttpState,
    auth::{
        authenticate, authenticate_management_key_exchange, clear_oidc_transaction_cookie_header,
        clear_session_cookie_header, oidc_transaction_cookie, oidc_transaction_cookie_header,
        require_command_security, session_cookie_header,
    },
    descriptor::openapi_document,
    extract::{ApiJson, CallbackQuery, LoginQuery, PageQuery},
};

pub async fn ready(State(state): State<HttpState>) -> Response {
    if state.application.public_ready().await {
        (StatusCode::OK, Json(json!({"status":"ready"}))).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status":"not_ready"})),
        )
            .into_response()
    }
}

pub async fn browser_login_issuers(State(state): State<HttpState>) -> Result<Response, ApiError> {
    state
        .application
        .list_browser_login_issuers()
        .await
        .map(json_response)
        .map_err(|error| ApiError::new(error, format!("req_{}", uuid::Uuid::now_v7())))
}

pub async fn oidc_login(
    State(state): State<HttpState>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    Path(issuer_name): Path<String>,
    Query(query): Query<LoginQuery>,
) -> Result<Response, ApiError> {
    let redirect = state
        .application
        .begin_oidc_login(&issuer_name, query.return_to.as_deref(), source.ip())
        .await
        .map_err(|error| ApiError::new(error, format!("req_{}", uuid::Uuid::now_v7())))?;
    let location = HeaderValue::from_str(&redirect.authorization_url).map_err(|_| {
        ApiError::new(
            crate::application::ApplicationError::Internal,
            format!("req_{}", uuid::Uuid::now_v7()),
        )
    })?;
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(header::LOCATION, location);
    response.headers_mut().append(
        header::SET_COOKIE,
        oidc_transaction_cookie_header(&redirect.transaction_token),
    );
    Ok(no_store(response))
}

pub async fn oidc_callback(
    State(state): State<HttpState>,
    Path(issuer_name): Path<String>,
    Query(query): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let request_id = crate::http::auth::request_id(&headers);
    let transaction_token = oidc_transaction_cookie(&headers)
        .map(str::to_owned)
        .map_err(|error| ApiError::new(error, request_id.clone()))?;
    let result = state
        .application
        .complete_oidc_login(
            &issuer_name,
            &query.state,
            &transaction_token,
            &query.code,
            request_id.clone(),
        )
        .await
        .map_err(|error| ApiError::new(error, request_id))?;
    let mut response = Redirect::to(&result.return_to).into_response();
    set_session_headers(&state, &result.session, &mut response);
    response
        .headers_mut()
        .append(header::SET_COOKIE, clear_oidc_transaction_cookie_header());
    Ok(no_store(response))
}

pub async fn create_management_key_session(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let direct = authenticate_management_key_exchange(&state.application, &headers)?;
    reject_idempotency_key(&headers, &direct)?;
    let created = state
        .application
        .create_key_session(&direct)
        .await
        .map_err(|error| app_error(error, &direct))?;
    let mut response = json_response(&created);
    set_session_headers(&state, &created, &mut response);
    Ok(no_store(response))
}

pub async fn session(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .current_principal(&identity)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn me(State(state): State<HttpState>, headers: HeaderMap) -> Result<Response, ApiError> {
    session(State(state), headers).await
}

pub async fn me_organizations(
    State(state): State<HttpState>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .list_allowed_organizations(&identity, query.cursor.as_deref(), query.limit)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn logout(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    state
        .application
        .logout(&identity)
        .await
        .map_err(|error| app_error(error, &identity))?;
    let mut response = no_content();
    response
        .headers_mut()
        .append(header::SET_COOKIE, clear_session_cookie_header());
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static("owlrora_csrf=; Path=/; Secure; SameSite=Lax; Max-Age=0"),
    );
    Ok(no_store(response))
}

pub async fn list_sessions(
    State(state): State<HttpState>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .list_principal_sessions(&identity, query.cursor.as_deref(), query.limit)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn revoke_session(
    State(state): State<HttpState>,
    Path(session_id): Path<SessionId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    state
        .application
        .revoke_principal_session(&identity, session_id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(no_content())
}

pub async fn audit(
    State(state): State<HttpState>,
    Query(query): Query<AuditQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .list_system_audit(&identity, &query)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

fn require_operator_source(
    state: &HttpState,
    source: SocketAddr,
    identity: &crate::application::RequestIdentity,
) -> Result<(), ApiError> {
    state
        .application
        .require_operator_network(Some(source.ip()))
        .map_err(|error| app_error(error, identity))
}

pub async fn organization_audit(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    Query(query): Query<AuditQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .list_organization_audit(&identity, organization_id, &query)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn organization_usage(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    Query(query): Query<UsageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .get_organization_usage(&identity, organization_id, &query)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn organization_usage_breakdown(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    Query(query): Query<UsageBreakdownQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .get_organization_usage_breakdown(&identity, organization_id, &query)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn system_usage(
    State(state): State<HttpState>,
    Query(query): Query<UsageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .get_system_usage(&identity, &query)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn system_usage_breakdown(
    State(state): State<HttpState>,
    Query(query): Query<UsageBreakdownQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .get_system_usage_breakdown(&identity, &query)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn operations_readiness(
    State(state): State<HttpState>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_operator_source(&state, source, &identity)?;
    state
        .application
        .operations_readiness(&identity)
        .await
        .map(|value| no_store(json_response(value)))
        .map_err(|error| app_error(error, &identity))
}

macro_rules! operations_view_handler {
    ($name:ident, $view:literal) => {
        pub async fn $name(
            State(state): State<HttpState>,
            ConnectInfo(source): ConnectInfo<SocketAddr>,
            headers: HeaderMap,
        ) -> Result<Response, ApiError> {
            let identity = authenticate(&state.application, &headers).await?;
            require_operator_source(&state, source, &identity)?;
            state
                .application
                .operations_view(&identity, $view)
                .await
                .map(|value| no_store(json_response(value)))
                .map_err(|error| app_error(error, &identity))
        }
    };
}

operations_view_handler!(operations_overview, "overview");
operations_view_handler!(operations_runtime, "runtime");
operations_view_handler!(operations_coordination, "coordination");
operations_view_handler!(operations_recoveries, "recoveries");
operations_view_handler!(operations_activations, "activations");
operations_view_handler!(operations_state_origins, "state-origins");
operations_view_handler!(operations_upstream_credentials, "upstream-credentials");
operations_view_handler!(operations_secret_custody, "secret-custody");
operations_view_handler!(operations_telemetry, "telemetry");

pub async fn operations_target_health(
    State(state): State<HttpState>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_operator_source(&state, source, &identity)?;
    state
        .application
        .operations_target_health(&identity)
        .map(|value| no_store(json_response(value)))
        .map_err(|error| app_error(error, &identity))
}

pub async fn operations_usage_pipeline(
    State(state): State<HttpState>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_operator_source(&state, source, &identity)?;
    state
        .application
        .operations_usage_pipeline(&identity)
        .await
        .map(|value| no_store(json_response(value)))
        .map_err(|error| app_error(error, &identity))
}

pub async fn reconcile_runtime(
    State(state): State<HttpState>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_operator_source(&state, source, &identity)?;
    require_command_security(&state.application, &identity, &headers)?;
    state
        .application
        .reconcile_runtime(&identity)
        .await
        .map(|value| no_store(json_response(value)))
        .map_err(|error| app_error(error, &identity))
}

pub async fn create_coordinator_recoveries(
    State(state): State<HttpState>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CreateCoordinatorRecoveries>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_operator_source(&state, source, &identity)?;
    require_command_security(&state.application, &identity, &headers)?;
    reject_idempotency_key(&headers, &identity)?;
    state
        .application
        .create_coordinator_recoveries(&identity, &input)
        .await
        .map(|value| no_store(json_response(value)))
        .map_err(|error| app_error(error, &identity))
}

pub async fn reconcile_policy_activations(
    State(state): State<HttpState>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_operator_source(&state, source, &identity)?;
    require_command_security(&state.application, &identity, &headers)?;
    reject_idempotency_key(&headers, &identity)?;
    state
        .application
        .reconcile_policy_activations_now(&identity)
        .await
        .map(|value| no_store(json_response(value)))
        .map_err(|error| app_error(error, &identity))
}

pub async fn cleanup_state_origins(
    State(state): State<HttpState>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CleanupStateOrigins>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_operator_source(&state, source, &identity)?;
    require_command_security(&state.application, &identity, &headers)?;
    reject_idempotency_key(&headers, &identity)?;
    state
        .application
        .cleanup_state_origins(&identity, &input)
        .await
        .map(|value| no_store(json_response(value)))
        .map_err(|error| app_error(error, &identity))
}

pub async fn reconcile_upstream_credentials(
    State(state): State<HttpState>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_operator_source(&state, source, &identity)?;
    require_command_security(&state.application, &identity, &headers)?;
    reject_idempotency_key(&headers, &identity)?;
    state
        .application
        .reconcile_upstream_credentials(&identity)
        .await
        .map(|value| no_store(json_response(value)))
        .map_err(|error| app_error(error, &identity))
}

pub async fn probe_targets(
    State(state): State<HttpState>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<ProbeTargets>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_operator_source(&state, source, &identity)?;
    require_command_security(&state.application, &identity, &headers)?;
    reject_idempotency_key(&headers, &identity)?;
    state
        .application
        .probe_targets_now(&identity, &input)
        .await
        .map(|value| no_store(json_response(value)))
        .map_err(|error| app_error(error, &identity))
}

pub async fn flush_usage_pipeline(
    State(state): State<HttpState>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_operator_source(&state, source, &identity)?;
    require_command_security(&state.application, &identity, &headers)?;
    reject_idempotency_key(&headers, &identity)?;
    state
        .application
        .flush_usage_pipeline(&identity)
        .await
        .map(|value| no_store(json_response(value)))
        .map_err(|error| app_error(error, &identity))
}

pub async fn reconcile_codex_refresh_leases(
    State(state): State<HttpState>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_operator_source(&state, source, &identity)?;
    require_command_security(&state.application, &identity, &headers)?;
    state
        .application
        .reconcile_codex_refresh_leases(&identity)
        .await
        .map(|value| no_store(json_response(value)))
        .map_err(|error| app_error(error, &identity))
}

pub async fn cleanup_identity_state(
    State(state): State<HttpState>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_operator_source(&state, source, &identity)?;
    require_command_security(&state.application, &identity, &headers)?;
    state
        .application
        .cleanup_expired_identity_state(&identity)
        .await
        .map(|changed| no_store(json_response(json!({"changed":changed}))))
        .map_err(|error| app_error(error, &identity))
}

pub async fn openapi(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .authorize(
            &identity,
            &[crate::domain::ManagementScope::Read],
            crate::application::AuthorizationTarget::CurrentPrincipal,
        )
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_response(openapi_document()))
}

fn set_session_headers(
    state: &HttpState,
    created: &crate::application::SessionCreated,
    response: &mut Response,
) {
    response.headers_mut().append(
        header::SET_COOKIE,
        session_cookie_header(
            &created.session_cookie,
            state.application.config.session_lifetime.as_secs(),
        ),
    );
    let csrf_cookie = format!(
        "owlrora_csrf={}; Path=/; Secure; SameSite=Lax; Max-Age={}",
        created.csrf_token,
        state.application.config.session_lifetime.as_secs()
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&csrf_cookie).expect("canonical CSRF token is a valid cookie value"),
    );
}
