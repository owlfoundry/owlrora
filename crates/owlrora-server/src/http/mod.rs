mod auth;
mod descriptor;
mod error;
mod extract;
mod handlers;

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::{DefaultBodyLimit, State},
    http::{HeaderName, HeaderValue, Method, Request, header},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use tower_http::{
    cors::CorsLayer, sensitive_headers::SetSensitiveHeadersLayer,
    set_header::SetResponseHeaderLayer,
};

use crate::application::Application;

pub use descriptor::{
    CheckedOperationContract, MODULE_I_OPERATIONS, OperationAuthorizationVariant,
    OperationDescriptor, openapi_document, operation_catalog,
};
pub use error::ApiError;

#[derive(Clone)]
pub struct HttpState {
    pub application: Arc<Application>,
}

#[must_use]
pub fn management_router(application: Arc<Application>) -> Router {
    let origin = application
        .config
        .public_origin
        .as_ref()
        .map(|origin| origin.origin().ascii_serialization())
        .and_then(|origin| HeaderValue::from_str(&origin).ok());
    let mut cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::IF_MATCH,
            HeaderName::from_static("idempotency-key"),
            HeaderName::from_static("x-owlrora-csrf-token"),
            HeaderName::from_static("x-request-id"),
        ])
        .allow_credentials(true);
    if let Some(origin) = origin {
        cors = cors.allow_origin(origin);
    }
    let state = HttpState { application };
    Router::new()
        .route("/ready", get(handlers::ready))
        .route("/auth/v1/issuers", get(handlers::browser_login_issuers))
        .route(
            "/auth/v1/issuers/{issuer_name}/login",
            get(handlers::oidc_login),
        )
        .route(
            "/auth/v1/issuers/{issuer_name}/callback",
            get(handlers::oidc_callback),
        )
        .route(
            "/auth/v1/management-api-key/session/actions/create",
            post(handlers::create_management_key_session),
        )
        .route("/api/v1/session", get(handlers::session))
        .route(
            "/api/v1/session/actions/logout",
            post(handlers::logout),
        )
        .route("/api/v1/me", get(handlers::me))
        .route(
            "/api/v1/me/organizations",
            get(handlers::me_organizations),
        )
        .route("/api/v1/me/sessions", get(handlers::list_sessions))
        .route(
            "/api/v1/me/sessions/{session_id}/actions/revoke",
            post(handlers::revoke_session),
        )
        .route(
            "/api/v1/system/users",
            get(handlers::list_users),
        )
        .route(
            "/api/v1/system/users/actions/create",
            post(handlers::create_user),
        )
        .route(
            "/api/v1/system/users/{user_id}",
            get(handlers::get_user),
        )
        .route(
            "/api/v1/system/users/{user_id}/actions/update",
            post(handlers::update_user),
        )
        .route(
            "/api/v1/system/organizations",
            get(handlers::list_system_organizations),
        )
        .route(
            "/api/v1/system/organizations/actions/create",
            post(handlers::create_organization),
        )
        .route(
            "/api/v1/system/organizations/{organization_id}",
            get(handlers::get_system_organization),
        )
        .route(
            "/api/v1/system/organizations/{organization_id}/actions/update",
            post(handlers::update_system_organization),
        )
        .route(
            "/api/v1/organizations/{organization_id}",
            get(handlers::get_tenant_organization),
        )
        .route(
            "/api/v1/organizations/{organization_id}/actions/update",
            post(handlers::update_tenant_organization),
        )
        .route(
            "/api/v1/organizations/{organization_id}/memberships",
            get(handlers::list_memberships),
        )
        .route(
            "/api/v1/organizations/{organization_id}/memberships/actions/create",
            post(handlers::create_membership),
        )
        .route(
            "/api/v1/organizations/{organization_id}/memberships/{user_id}",
            get(handlers::get_membership),
        )
        .route(
            "/api/v1/organizations/{organization_id}/memberships/{user_id}/actions/update",
            post(handlers::update_membership),
        )
        .route(
            "/api/v1/organizations/{organization_id}/memberships/{user_id}/actions/remove",
            post(handlers::remove_membership),
        )
        .route(
            "/api/v1/system/management-api-keys",
            get(handlers::list_system_management_keys),
        )
        .route(
            "/api/v1/system/management-api-keys/actions/create",
            post(handlers::create_system_management_key),
        )
        .route(
            "/api/v1/system/management-api-keys/{key_id}",
            get(handlers::get_system_management_key),
        )
        .route(
            "/api/v1/system/management-api-keys/{key_id}/actions/update",
            post(handlers::update_system_management_key),
        )
        .route(
            "/api/v1/system/management-api-keys/{key_id}/actions/rotate",
            post(handlers::rotate_system_management_key),
        )
        .route(
            "/api/v1/system/management-api-key-policy",
            get(handlers::get_deployment_management_key_policy),
        )
        .route(
            "/api/v1/system/management-api-key-policy/actions/update",
            post(handlers::update_deployment_management_key_policy),
        )
        .route(
            "/api/v1/organizations/{organization_id}/management-api-keys",
            get(handlers::list_organization_management_keys),
        )
        .route(
            "/api/v1/organizations/{organization_id}/management-api-keys/actions/create",
            post(handlers::create_organization_management_key),
        )
        .route(
            "/api/v1/organizations/{organization_id}/management-api-keys/{key_id}",
            get(handlers::get_organization_management_key),
        )
        .route(
            "/api/v1/organizations/{organization_id}/management-api-keys/{key_id}/actions/update",
            post(handlers::update_organization_management_key),
        )
        .route(
            "/api/v1/organizations/{organization_id}/management-api-keys/{key_id}/actions/rotate",
            post(handlers::rotate_organization_management_key),
        )
        .route(
            "/api/v1/organizations/{organization_id}/api-key-policy",
            get(handlers::get_api_key_policy),
        )
        .route(
            "/api/v1/organizations/{organization_id}/api-key-policy/actions/update",
            post(handlers::update_api_key_policy),
        )
        .route(
            "/api/v1/organizations/{organization_id}/invitations",
            get(handlers::list_invitations),
        )
        .route(
            "/api/v1/organizations/{organization_id}/invitations/actions/create",
            post(handlers::create_invitation),
        )
        .route(
            "/api/v1/organizations/{organization_id}/invitations/{invitation_id}",
            get(handlers::get_invitation),
        )
        .route(
            "/api/v1/organizations/{organization_id}/invitations/{invitation_id}/actions/resend",
            post(handlers::resend_invitation),
        )
        .route(
            "/api/v1/organizations/{organization_id}/invitations/{invitation_id}/actions/revoke",
            post(handlers::revoke_invitation),
        )
        .route(
            "/api/v1/invitations/actions/accept",
            post(handlers::accept_invitation),
        )
        .route(
            "/api/v1/system/administrators",
            get(handlers::list_administrators),
        )
        .route(
            "/api/v1/system/administrators/actions/grant",
            post(handlers::grant_administrator),
        )
        .route(
            "/api/v1/system/administrators/{subject_kind}/{subject_id}/actions/revoke",
            post(handlers::revoke_administrator),
        )
        .route(
            "/api/v1/system/identity-issuers",
            get(handlers::list_issuers),
        )
        .route(
            "/api/v1/system/identity-issuers/actions/create",
            post(handlers::create_issuer),
        )
        .route(
            "/api/v1/system/identity-issuers/{issuer_id}",
            get(handlers::get_issuer),
        )
        .route(
            "/api/v1/system/identity-issuers/{issuer_id}/actions/update",
            post(handlers::update_issuer),
        )
        .route(
            "/api/v1/system/identity-issuers/{issuer_id}/actions/refresh-verifier-material",
            post(handlers::refresh_issuer),
        )
        .route(
            "/api/v1/system/identity-issuers/{issuer_id}/browser-login/actions/replace-client-secret",
            post(handlers::replace_client_secret),
        )
        .route(
            "/api/v1/system/identity-issuers/{issuer_id}/browser-login/actions/validate",
            post(handlers::validate_browser_login),
        )
        .route(
            "/api/v1/system/identity-bindings",
            get(handlers::list_bindings),
        )
        .route(
            "/api/v1/system/identity-bindings/actions/create",
            post(handlers::create_binding),
        )
        .route(
            "/api/v1/system/identity-bindings/{binding_id}",
            get(handlers::get_binding),
        )
        .route(
            "/api/v1/system/identity-bindings/{binding_id}/actions/relink",
            post(handlers::relink_binding),
        )
        .route(
            "/api/v1/system/identity-bindings/{binding_id}/actions/remove",
            post(handlers::remove_binding),
        )
        .route(
            "/api/v1/system/provisioning-policies",
            get(handlers::list_provisioning_policies),
        )
        .route(
            "/api/v1/system/provisioning-policies/actions/create",
            post(handlers::create_provisioning_policy),
        )
        .route(
            "/api/v1/system/provisioning-policies/{policy_id}",
            get(handlers::get_provisioning_policy),
        )
        .route(
            "/api/v1/system/provisioning-policies/{policy_id}/actions/update",
            post(handlers::update_provisioning_policy),
        )
        .route(
            "/api/v1/organizations/{organization_id}/audit",
            get(handlers::organization_audit),
        )
        .route("/api/v1/system/audit", get(handlers::audit))
        .route(
            "/api/v1/system/operations",
            get(handlers::operations_overview),
        )
        .route(
            "/api/v1/system/operations/readiness",
            get(handlers::operations_readiness),
        )
        .route(
            "/api/v1/system/operations/runtime",
            get(handlers::operations_runtime),
        )
        .route(
            "/api/v1/system/operations/runtime/actions/reconcile",
            post(handlers::reconcile_runtime),
        )
        .route(
            "/api/v1/system/operations/coordination",
            get(handlers::operations_coordination),
        )
        .route(
            "/api/v1/system/operations/coordination/recoveries",
            get(handlers::operations_recoveries),
        )
        .route(
            "/api/v1/system/operations/identity-state/actions/cleanup",
            post(handlers::cleanup_identity_state),
        )
        .route(
            "/api/v1/system/operations/secret-custody",
            get(handlers::operations_secret_custody),
        )
        .route(
            "/api/v1/system/operations/telemetry",
            get(handlers::operations_telemetry),
        )
        .route("/api/v1/openapi.json", get(handlers::openapi))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            attach_command_status,
        ))
        .with_state(state)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(cors)
        .layer(SetSensitiveHeadersLayer::new([
            header::AUTHORIZATION,
            header::COOKIE,
            header::SET_COOKIE,
        ]))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
}

async fn attach_command_status(
    State(state): State<HttpState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let command = request.method() == Method::POST;
    let mut response = next.run(request).await;
    if command && response.status().is_success() {
        response.headers_mut().insert(
            HeaderName::from_static("x-owlrora-command-status"),
            HeaderValue::from_static("committed"),
        );
        let publication = state.application.runtime.status();
        let database_revision = match state.application.store().current_revision().await {
            Ok(revision) => Some(revision),
            Err(error) => {
                tracing::error!(%error, "could not confirm command publication revision");
                None
            }
        };
        let publication_state =
            if database_revision.is_some_and(|revision| publication.applied_revision >= revision) {
                "applied"
            } else {
                "pending"
            };
        response.headers_mut().insert(
            HeaderName::from_static("x-owlrora-node-publication"),
            HeaderValue::from_static(publication_state),
        );
        if let Ok(value) = HeaderValue::from_str(&publication.applied_revision.to_string()) {
            response
                .headers_mut()
                .insert(HeaderName::from_static("x-owlrora-applied-revision"), value);
        }
        if let Some(database_revision) = database_revision {
            if let Ok(value) = HeaderValue::from_str(&database_revision.to_string()) {
                response.headers_mut().insert(
                    HeaderName::from_static("x-owlrora-database-revision"),
                    value,
                );
            }
        }
    }
    response
}
