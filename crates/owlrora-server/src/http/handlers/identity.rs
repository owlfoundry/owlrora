use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};

use crate::{
    application::{
        CreateExternalIdentityBinding, CreateExternalIdentityIssuer, CreateProvisioningPolicy,
        IdempotentCommand, RelinkExternalIdentityBinding, ReplaceBrowserClientSecret,
        UpdateExternalIdentityIssuer, UpdateProvisioningPolicy,
    },
    domain::{BindingId, IssuerId, PolicyId},
    http::{
        ApiError, HttpState,
        auth::{authenticate, if_match, require_command_security},
        extract::{ApiJson, PageQuery},
    },
};

use super::{
    app_error, idempotency_key, idempotency_replay_response, json_etag_response, json_response,
    no_content, reject_idempotency_key,
};

pub async fn list_issuers(
    State(state): State<HttpState>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .list_external_identity_issuers(&identity, query.cursor.as_deref(), query.limit)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn get_issuer(
    State(state): State<HttpState>,
    Path(issuer_id): Path<IssuerId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_external_identity_issuer(&identity, issuer_id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn create_issuer(
    State(state): State<HttpState>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CreateExternalIdentityIssuer>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    match state
        .application
        .create_external_identity_issuer(&identity, input, idempotency_key(&headers, &identity)?)
        .await
        .map_err(|error| app_error(error, &identity))?
    {
        IdempotentCommand::Executed((value, etag)) => Ok(json_etag_response(value, &etag)),
        IdempotentCommand::Replay(replay) => Ok(idempotency_replay_response(replay)),
    }
}

pub async fn update_issuer(
    State(state): State<HttpState>,
    Path(issuer_id): Path<IssuerId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateExternalIdentityIssuer>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let if_match = if_match(&headers, &identity.request_id)?;
    let (value, etag) = state
        .application
        .update_external_identity_issuer(&identity, issuer_id, if_match, input)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn refresh_issuer(
    State(state): State<HttpState>,
    Path(issuer_id): Path<IssuerId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    state
        .application
        .refresh_external_identity_issuer_material(&identity, issuer_id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(no_content())
}

pub async fn replace_client_secret(
    State(state): State<HttpState>,
    Path(issuer_id): Path<IssuerId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<ReplaceBrowserClientSecret>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    reject_idempotency_key(&headers, &identity)?;
    state
        .application
        .replace_browser_client_secret(&identity, issuer_id, input)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(no_content())
}

pub async fn validate_browser_login(
    State(state): State<HttpState>,
    Path(issuer_id): Path<IssuerId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    state
        .application
        .validate_browser_login(&identity, issuer_id)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn list_bindings(
    State(state): State<HttpState>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .list_external_identity_bindings(&identity, query.cursor.as_deref(), query.limit)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn get_binding(
    State(state): State<HttpState>,
    Path(binding_id): Path<BindingId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_external_identity_binding(&identity, binding_id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn create_binding(
    State(state): State<HttpState>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CreateExternalIdentityBinding>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    match state
        .application
        .create_external_identity_binding(&identity, input, idempotency_key(&headers, &identity)?)
        .await
        .map_err(|error| app_error(error, &identity))?
    {
        IdempotentCommand::Executed((value, etag)) => Ok(json_etag_response(value, &etag)),
        IdempotentCommand::Replay(replay) => Ok(idempotency_replay_response(replay)),
    }
}

pub async fn relink_binding(
    State(state): State<HttpState>,
    Path(binding_id): Path<BindingId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<RelinkExternalIdentityBinding>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let if_match = if_match(&headers, &identity.request_id)?;
    let (value, etag) = state
        .application
        .relink_external_identity_binding(&identity, binding_id, if_match, input)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn remove_binding(
    State(state): State<HttpState>,
    Path(binding_id): Path<BindingId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let if_match = if_match(&headers, &identity.request_id)?;
    let (value, etag) = state
        .application
        .remove_external_identity_binding(&identity, binding_id, if_match)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn list_provisioning_policies(
    State(state): State<HttpState>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .list_provisioning_policies(&identity, query.cursor.as_deref(), query.limit)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn get_provisioning_policy(
    State(state): State<HttpState>,
    Path(policy_id): Path<PolicyId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_provisioning_policy(&identity, policy_id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn create_provisioning_policy(
    State(state): State<HttpState>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CreateProvisioningPolicy>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    match state
        .application
        .create_provisioning_policy(&identity, input, idempotency_key(&headers, &identity)?)
        .await
        .map_err(|error| app_error(error, &identity))?
    {
        IdempotentCommand::Executed((value, etag)) => Ok(json_etag_response(value, &etag)),
        IdempotentCommand::Replay(replay) => Ok(idempotency_replay_response(replay)),
    }
}

pub async fn update_provisioning_policy(
    State(state): State<HttpState>,
    Path(policy_id): Path<PolicyId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateProvisioningPolicy>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let if_match = if_match(&headers, &identity.request_id)?;
    let (value, etag) = state
        .application
        .update_provisioning_policy(&identity, policy_id, if_match, input)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}
