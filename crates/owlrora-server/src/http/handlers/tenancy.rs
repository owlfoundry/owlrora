use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};

use crate::{
    application::{
        AcceptInvitation, CreateInvitation, CreateMembership, CreateOrganization, CreateUser,
        IdempotentCommand, UpdateMembership, UpdateOrganization, UpdateUser,
    },
    domain::{InvitationId, OrganizationId, UserId},
    http::{
        ApiError, HttpState,
        auth::{authenticate, if_match, require_command_security},
        extract::{ApiJson, PageQuery},
    },
};

use super::{
    app_error, idempotency_key, idempotency_replay_response, json_etag_response, json_response,
    no_content, no_store, reject_idempotency_key,
};

pub async fn list_users(
    State(state): State<HttpState>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .list_users(&identity, query.cursor.as_deref(), query.limit)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn get_user(
    State(state): State<HttpState>,
    Path(user_id): Path<UserId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_user(&identity, user_id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn create_user(
    State(state): State<HttpState>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CreateUser>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    match state
        .application
        .create_user(&identity, input, idempotency_key(&headers, &identity)?)
        .await
        .map_err(|error| app_error(error, &identity))?
    {
        IdempotentCommand::Executed((value, etag)) => Ok(json_etag_response(value, &etag)),
        IdempotentCommand::Replay(replay) => Ok(idempotency_replay_response(replay)),
    }
}

pub async fn update_user(
    State(state): State<HttpState>,
    Path(user_id): Path<UserId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateUser>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let if_match = if_match(&headers, &identity.request_id)?;
    let (value, etag) = state
        .application
        .update_user(&identity, user_id, if_match, input)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn list_system_organizations(
    State(state): State<HttpState>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .list_system_organizations(&identity, query.cursor.as_deref(), query.limit)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn get_system_organization(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    get_organization(state, organization_id, headers, true).await
}

pub async fn get_tenant_organization(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    get_organization(state, organization_id, headers, false).await
}

async fn get_organization(
    state: HttpState,
    organization_id: OrganizationId,
    headers: HeaderMap,
    system_path: bool,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_organization(&identity, organization_id, system_path)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn create_organization(
    State(state): State<HttpState>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CreateOrganization>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    match state
        .application
        .create_organization(&identity, input, idempotency_key(&headers, &identity)?)
        .await
        .map_err(|error| app_error(error, &identity))?
    {
        IdempotentCommand::Executed((value, etag)) => Ok(json_etag_response(value, &etag)),
        IdempotentCommand::Replay(replay) => Ok(idempotency_replay_response(replay)),
    }
}

pub async fn update_system_organization(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateOrganization>,
) -> Result<Response, ApiError> {
    update_organization(state, organization_id, headers, input, true).await
}

pub async fn update_tenant_organization(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateOrganization>,
) -> Result<Response, ApiError> {
    update_organization(state, organization_id, headers, input, false).await
}

async fn update_organization(
    state: HttpState,
    organization_id: OrganizationId,
    headers: HeaderMap,
    input: UpdateOrganization,
    system_path: bool,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let if_match = if_match(&headers, &identity.request_id)?;
    let (value, etag) = state
        .application
        .update_organization(&identity, organization_id, system_path, if_match, input)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn list_memberships(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .list_memberships(
            &identity,
            organization_id,
            query.cursor.as_deref(),
            query.limit,
        )
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn get_membership(
    State(state): State<HttpState>,
    Path((organization_id, user_id)): Path<(OrganizationId, UserId)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_membership(&identity, organization_id, user_id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn create_membership(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CreateMembership>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    match state
        .application
        .create_membership(
            &identity,
            organization_id,
            input,
            idempotency_key(&headers, &identity)?,
        )
        .await
        .map_err(|error| app_error(error, &identity))?
    {
        IdempotentCommand::Executed((value, etag)) => Ok(json_etag_response(value, &etag)),
        IdempotentCommand::Replay(replay) => Ok(idempotency_replay_response(replay)),
    }
}

pub async fn update_membership(
    State(state): State<HttpState>,
    Path((organization_id, user_id)): Path<(OrganizationId, UserId)>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateMembership>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let if_match = if_match(&headers, &identity.request_id)?;
    let (value, etag) = state
        .application
        .update_membership(&identity, organization_id, user_id, if_match, input)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn remove_membership(
    State(state): State<HttpState>,
    Path((organization_id, user_id)): Path<(OrganizationId, UserId)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    state
        .application
        .remove_membership(&identity, organization_id, user_id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(no_content())
}

pub async fn list_invitations(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .list_invitations(
            &identity,
            organization_id,
            query.cursor.as_deref(),
            query.limit,
        )
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn get_invitation(
    State(state): State<HttpState>,
    Path((organization_id, invitation_id)): Path<(OrganizationId, InvitationId)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .get_invitation(&identity, organization_id, invitation_id)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn create_invitation(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CreateInvitation>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    reject_idempotency_key(&headers, &identity)?;
    state
        .application
        .create_invitation(&identity, organization_id, input)
        .await
        .map(|value| no_store(json_response(value)))
        .map_err(|error| app_error(error, &identity))
}

pub async fn resend_invitation(
    State(state): State<HttpState>,
    Path((organization_id, invitation_id)): Path<(OrganizationId, InvitationId)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    reject_idempotency_key(&headers, &identity)?;
    state
        .application
        .resend_invitation(&identity, organization_id, invitation_id)
        .await
        .map(|value| no_store(json_response(value)))
        .map_err(|error| app_error(error, &identity))
}

pub async fn revoke_invitation(
    State(state): State<HttpState>,
    Path((organization_id, invitation_id)): Path<(OrganizationId, InvitationId)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    state
        .application
        .revoke_invitation(&identity, organization_id, invitation_id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(no_content())
}

pub async fn accept_invitation(
    State(state): State<HttpState>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<AcceptInvitation>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    state
        .application
        .accept_invitation(&identity, input)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}
