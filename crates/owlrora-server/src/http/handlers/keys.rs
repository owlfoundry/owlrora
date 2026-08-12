use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};

use crate::{
    application::{
        CreateManagementApiKey, GrantAdministrator, RotateManagementApiKey,
        UpdateDeploymentManagementKeyPolicy, UpdateManagementApiKey,
        UpdateOrganizationApiKeyPolicy,
    },
    domain::{KeyId, OrganizationId, ResourceScope},
    http::{
        ApiError, HttpState,
        auth::{authenticate, if_match, require_command_security},
        extract::{ApiJson, PageQuery},
    },
};

use super::{
    app_error, json_etag_response, json_response, no_content, no_store, reject_idempotency_key,
};

pub async fn list_system_management_keys(
    State(state): State<HttpState>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    list_keys(state, headers, ResourceScope::Deployment, query).await
}

pub async fn list_organization_management_keys(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    list_keys(
        state,
        headers,
        ResourceScope::Organization { organization_id },
        query,
    )
    .await
}

async fn list_keys(
    state: HttpState,
    headers: HeaderMap,
    scope: ResourceScope,
    query: PageQuery,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .list_management_keys(&identity, scope, query.cursor.as_deref(), query.limit)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn get_system_management_key(
    State(state): State<HttpState>,
    Path(key_id): Path<KeyId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    get_key(state, headers, ResourceScope::Deployment, key_id).await
}

pub async fn get_organization_management_key(
    State(state): State<HttpState>,
    Path((organization_id, key_id)): Path<(OrganizationId, KeyId)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    get_key(
        state,
        headers,
        ResourceScope::Organization { organization_id },
        key_id,
    )
    .await
}

async fn get_key(
    state: HttpState,
    headers: HeaderMap,
    scope: ResourceScope,
    key_id: KeyId,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_management_key(&identity, scope, key_id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn create_system_management_key(
    State(state): State<HttpState>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CreateManagementApiKey>,
) -> Result<Response, ApiError> {
    create_key(state, headers, ResourceScope::Deployment, input).await
}

pub async fn create_organization_management_key(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CreateManagementApiKey>,
) -> Result<Response, ApiError> {
    create_key(
        state,
        headers,
        ResourceScope::Organization { organization_id },
        input,
    )
    .await
}

async fn create_key(
    state: HttpState,
    headers: HeaderMap,
    scope: ResourceScope,
    input: CreateManagementApiKey,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    reject_idempotency_key(&headers, &identity)?;
    let (value, etag) = state
        .application
        .create_management_key(&identity, scope, input)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(no_store(json_etag_response(value, &etag)))
}

pub async fn update_system_management_key(
    State(state): State<HttpState>,
    Path(key_id): Path<KeyId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateManagementApiKey>,
) -> Result<Response, ApiError> {
    update_key(state, headers, ResourceScope::Deployment, key_id, input).await
}

pub async fn update_organization_management_key(
    State(state): State<HttpState>,
    Path((organization_id, key_id)): Path<(OrganizationId, KeyId)>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateManagementApiKey>,
) -> Result<Response, ApiError> {
    update_key(
        state,
        headers,
        ResourceScope::Organization { organization_id },
        key_id,
        input,
    )
    .await
}

async fn update_key(
    state: HttpState,
    headers: HeaderMap,
    scope: ResourceScope,
    key_id: KeyId,
    input: UpdateManagementApiKey,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let if_match = if_match(&headers, &identity.request_id)?;
    let (value, etag) = state
        .application
        .update_management_key(&identity, scope, key_id, if_match, input)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn rotate_system_management_key(
    State(state): State<HttpState>,
    Path(key_id): Path<KeyId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<RotateManagementApiKey>,
) -> Result<Response, ApiError> {
    rotate_key(state, headers, ResourceScope::Deployment, key_id, input).await
}

pub async fn rotate_organization_management_key(
    State(state): State<HttpState>,
    Path((organization_id, key_id)): Path<(OrganizationId, KeyId)>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<RotateManagementApiKey>,
) -> Result<Response, ApiError> {
    rotate_key(
        state,
        headers,
        ResourceScope::Organization { organization_id },
        key_id,
        input,
    )
    .await
}

async fn rotate_key(
    state: HttpState,
    headers: HeaderMap,
    scope: ResourceScope,
    key_id: KeyId,
    input: RotateManagementApiKey,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    reject_idempotency_key(&headers, &identity)?;
    let (value, etag) = state
        .application
        .rotate_management_key(&identity, scope, key_id, input)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(no_store(json_etag_response(value, &etag)))
}

pub async fn get_deployment_management_key_policy(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_deployment_management_key_policy(&identity)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn update_deployment_management_key_policy(
    State(state): State<HttpState>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateDeploymentManagementKeyPolicy>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let if_match = if_match(&headers, &identity.request_id)?;
    let (value, etag) = state
        .application
        .update_deployment_management_key_policy(&identity, if_match, input)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn get_api_key_policy(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_organization_api_key_policy(&identity, organization_id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn update_api_key_policy(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateOrganizationApiKeyPolicy>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let if_match = if_match(&headers, &identity.request_id)?;
    let (value, etag) = state
        .application
        .update_organization_api_key_policy(&identity, organization_id, if_match, input)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn list_administrators(
    State(state): State<HttpState>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .list_administrators(&identity, query.cursor.as_deref(), query.limit)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn grant_administrator(
    State(state): State<HttpState>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<GrantAdministrator>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    state
        .application
        .grant_administrator(&identity, input)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(no_content())
}

pub async fn revoke_administrator(
    State(state): State<HttpState>,
    Path((subject_kind, subject_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    state
        .application
        .revoke_administrator(&identity, &subject_kind, &subject_id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(no_content())
}
