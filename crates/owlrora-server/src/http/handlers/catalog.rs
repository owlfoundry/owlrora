use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};

use crate::{
    application::{
        BeginBudgetEpoch, CatalogGrantKind, CompleteCodexLogin, CreateEgressNetworkPolicy,
        CreateGatewayApiKey, CreateModelDeployment, CreateModelRoute, CreatePricingPolicy,
        CreateReliabilityPolicy, CreateUpstreamCredential, CreateUpstreamEndpoint,
        IdempotentCommand, PublishPricingPolicyVersion, ReplaceEgressCustomCa,
        ReplaceUpstreamCredentialSecret, RotateGatewayApiKey, StartCodexLogin,
        TransferModelRouteOwnership, UpdateBudgetPolicy, UpdateCatalogGrantSet,
        UpdateEgressNetworkPolicy, UpdateGatewayApiKey, UpdateGatewayPolicyCeilings,
        UpdateGatewayRequestLimits, UpdateModelDeployment, UpdateModelRoute, UpdatePricingPolicy,
        UpdateReliabilityPolicy, UpdateUpstreamCredential, UpdateUpstreamEndpoint,
    },
    domain::{
        AccountingOrigin, CredentialId, CredentialLoginSessionId, DeploymentId, EndpointId,
        GatewayKeyId, NetworkPolicyId, OrganizationId, PricingPolicyId, ReliabilityPolicyId,
        ResourceScope, RouteId,
    },
    http::{
        ApiError, HttpState,
        auth::{authenticate, if_match, require_command_security},
        extract::{ApiJson, PageQuery},
    },
};

use super::{
    app_error, idempotency_key, idempotency_replay_response, json_etag_response, json_response,
    no_store, reject_idempotency_key,
};

macro_rules! list_handler {
    ($name:ident, $method:ident) => {
        pub async fn $name(
            State(state): State<HttpState>,
            Query(query): Query<PageQuery>,
            headers: HeaderMap,
        ) -> Result<Response, ApiError> {
            let identity = authenticate(&state.application, &headers).await?;
            state
                .application
                .$method(&identity, query.cursor.as_deref(), query.limit)
                .await
                .map(json_response)
                .map_err(|error| app_error(error, &identity))
        }
    };
}

list_handler!(list_egress_network_policies, list_egress_network_policies);
list_handler!(list_reliability_policies, list_reliability_policies);
list_handler!(list_upstream_endpoints, list_upstream_endpoints);
list_handler!(list_pricing_policies, list_pricing_policies);

pub async fn list_system_upstream_credentials(
    State(state): State<HttpState>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    list_upstream_credentials(state, headers, ResourceScope::Deployment, query).await
}

pub async fn list_organization_upstream_credentials(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    list_upstream_credentials(
        state,
        headers,
        ResourceScope::Organization { organization_id },
        query,
    )
    .await
}

async fn list_upstream_credentials(
    state: HttpState,
    headers: HeaderMap,
    scope: ResourceScope,
    query: PageQuery,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .list_upstream_credentials(&identity, scope, query.cursor.as_deref(), query.limit)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn get_system_upstream_credential(
    State(state): State<HttpState>,
    Path(credential_id): Path<CredentialId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    get_upstream_credential(state, headers, ResourceScope::Deployment, credential_id).await
}

pub async fn get_organization_upstream_credential(
    State(state): State<HttpState>,
    Path((organization_id, credential_id)): Path<(OrganizationId, CredentialId)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    get_upstream_credential(
        state,
        headers,
        ResourceScope::Organization { organization_id },
        credential_id,
    )
    .await
}

async fn get_upstream_credential(
    state: HttpState,
    headers: HeaderMap,
    scope: ResourceScope,
    credential_id: CredentialId,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_upstream_credential(&identity, scope, credential_id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(no_store(json_etag_response(value, &etag)))
}

pub async fn create_system_upstream_credential(
    State(state): State<HttpState>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CreateUpstreamCredential>,
) -> Result<Response, ApiError> {
    create_upstream_credential(state, headers, ResourceScope::Deployment, input).await
}

pub async fn create_organization_upstream_credential(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CreateUpstreamCredential>,
) -> Result<Response, ApiError> {
    create_upstream_credential(
        state,
        headers,
        ResourceScope::Organization { organization_id },
        input,
    )
    .await
}

async fn create_upstream_credential(
    state: HttpState,
    headers: HeaderMap,
    scope: ResourceScope,
    input: CreateUpstreamCredential,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    match state
        .application
        .create_upstream_credential(
            &identity,
            scope,
            input,
            idempotency_key(&headers, &identity)?,
        )
        .await
        .map_err(|error| app_error(error, &identity))?
    {
        IdempotentCommand::Executed((value, etag)) => {
            Ok(no_store(json_etag_response(value, &etag)))
        }
        IdempotentCommand::Replay(replay) => Ok(no_store(idempotency_replay_response(replay))),
    }
}

pub async fn update_system_upstream_credential(
    State(state): State<HttpState>,
    Path(credential_id): Path<CredentialId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateUpstreamCredential>,
) -> Result<Response, ApiError> {
    update_upstream_credential(
        state,
        headers,
        ResourceScope::Deployment,
        credential_id,
        input,
    )
    .await
}

pub async fn update_organization_upstream_credential(
    State(state): State<HttpState>,
    Path((organization_id, credential_id)): Path<(OrganizationId, CredentialId)>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateUpstreamCredential>,
) -> Result<Response, ApiError> {
    update_upstream_credential(
        state,
        headers,
        ResourceScope::Organization { organization_id },
        credential_id,
        input,
    )
    .await
}

async fn update_upstream_credential(
    state: HttpState,
    headers: HeaderMap,
    scope: ResourceScope,
    credential_id: CredentialId,
    input: UpdateUpstreamCredential,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let (value, etag) = state
        .application
        .update_upstream_credential(
            &identity,
            scope,
            credential_id,
            if_match(&headers, &identity.request_id)?,
            input,
        )
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn replace_system_upstream_credential_secret(
    State(state): State<HttpState>,
    Path(credential_id): Path<CredentialId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<ReplaceUpstreamCredentialSecret>,
) -> Result<Response, ApiError> {
    replace_upstream_credential_secret(
        state,
        headers,
        ResourceScope::Deployment,
        credential_id,
        input,
    )
    .await
}

pub async fn replace_organization_upstream_credential_secret(
    State(state): State<HttpState>,
    Path((organization_id, credential_id)): Path<(OrganizationId, CredentialId)>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<ReplaceUpstreamCredentialSecret>,
) -> Result<Response, ApiError> {
    replace_upstream_credential_secret(
        state,
        headers,
        ResourceScope::Organization { organization_id },
        credential_id,
        input,
    )
    .await
}

async fn replace_upstream_credential_secret(
    state: HttpState,
    headers: HeaderMap,
    scope: ResourceScope,
    credential_id: CredentialId,
    input: ReplaceUpstreamCredentialSecret,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    match state
        .application
        .replace_upstream_credential_secret(
            &identity,
            scope,
            credential_id,
            input,
            idempotency_key(&headers, &identity)?,
        )
        .await
        .map_err(|error| app_error(error, &identity))?
    {
        IdempotentCommand::Executed((value, etag)) => {
            Ok(no_store(json_etag_response(value, &etag)))
        }
        IdempotentCommand::Replay(replay) => Ok(no_store(idempotency_replay_response(replay))),
    }
}

pub async fn reload_system_upstream_credential_source(
    State(state): State<HttpState>,
    Path(credential_id): Path<CredentialId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    match state
        .application
        .reload_upstream_credential_source(
            &identity,
            credential_id,
            idempotency_key(&headers, &identity)?,
        )
        .await
        .map_err(|error| app_error(error, &identity))?
    {
        IdempotentCommand::Executed(value) => Ok(no_store(json_response(value))),
        IdempotentCommand::Replay(replay) => Ok(no_store(idempotency_replay_response(replay))),
    }
}

pub async fn validate_system_upstream_credential(
    State(state): State<HttpState>,
    Path(credential_id): Path<CredentialId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    validate_upstream_credential(state, headers, ResourceScope::Deployment, credential_id).await
}

pub async fn validate_organization_upstream_credential(
    State(state): State<HttpState>,
    Path((organization_id, credential_id)): Path<(OrganizationId, CredentialId)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    validate_upstream_credential(
        state,
        headers,
        ResourceScope::Organization { organization_id },
        credential_id,
    )
    .await
}

async fn validate_upstream_credential(
    state: HttpState,
    headers: HeaderMap,
    scope: ResourceScope,
    credential_id: CredentialId,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    match state
        .application
        .validate_upstream_credential(
            &identity,
            scope,
            credential_id,
            idempotency_key(&headers, &identity)?,
        )
        .await
        .map_err(|error| app_error(error, &identity))?
    {
        IdempotentCommand::Executed(value) => Ok(json_response(value)),
        IdempotentCommand::Replay(replay) => Ok(idempotency_replay_response(replay)),
    }
}

pub async fn start_codex_login(
    State(state): State<HttpState>,
    Path(credential_id): Path<CredentialId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<StartCodexLogin>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    reject_idempotency_key(&headers, &identity)?;
    state
        .application
        .start_codex_login(&identity, credential_id, input)
        .await
        .map(json_response)
        .map(no_store)
        .map_err(|error| app_error(error, &identity))
}

pub async fn get_codex_login(
    State(state): State<HttpState>,
    Path((credential_id, session_id)): Path<(CredentialId, CredentialLoginSessionId)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .get_codex_login(&identity, credential_id, session_id)
        .await
        .map(json_response)
        .map(no_store)
        .map_err(|error| app_error(error, &identity))
}

pub async fn complete_codex_login(
    State(state): State<HttpState>,
    Path((credential_id, session_id)): Path<(CredentialId, CredentialLoginSessionId)>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CompleteCodexLogin>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    reject_idempotency_key(&headers, &identity)?;
    state
        .application
        .complete_codex_login(&identity, credential_id, session_id, input)
        .await
        .map(json_response)
        .map(no_store)
        .map_err(|error| app_error(error, &identity))
}

pub async fn cancel_codex_login(
    State(state): State<HttpState>,
    Path((credential_id, session_id)): Path<(CredentialId, CredentialLoginSessionId)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    state
        .application
        .cancel_codex_login(&identity, credential_id, session_id)
        .await
        .map(json_response)
        .map(no_store)
        .map_err(|error| app_error(error, &identity))
}

pub async fn refresh_codex_credential(
    State(state): State<HttpState>,
    Path(credential_id): Path<CredentialId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    state
        .application
        .refresh_codex_credential(&identity, credential_id)
        .await
        .map(json_response)
        .map(no_store)
        .map_err(|error| app_error(error, &identity))
}

pub async fn revoke_codex_credential(
    State(state): State<HttpState>,
    Path(credential_id): Path<CredentialId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    state
        .application
        .revoke_codex_credential(&identity, credential_id)
        .await
        .map(json_response)
        .map(no_store)
        .map_err(|error| app_error(error, &identity))
}

pub async fn get_pricing_policy(
    State(state): State<HttpState>,
    Path(id): Path<PricingPolicyId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_pricing_policy(&identity, id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn create_pricing_policy(
    State(state): State<HttpState>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CreatePricingPolicy>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    match state
        .application
        .create_pricing_policy(&identity, input, idempotency_key(&headers, &identity)?)
        .await
        .map_err(|error| app_error(error, &identity))?
    {
        IdempotentCommand::Executed((value, etag)) => Ok(json_etag_response(value, &etag)),
        IdempotentCommand::Replay(replay) => Ok(idempotency_replay_response(replay)),
    }
}

pub async fn update_pricing_policy(
    State(state): State<HttpState>,
    Path(id): Path<PricingPolicyId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdatePricingPolicy>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let (value, etag) = state
        .application
        .update_pricing_policy(
            &identity,
            id,
            if_match(&headers, &identity.request_id)?,
            input,
        )
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn publish_pricing_policy_version(
    State(state): State<HttpState>,
    Path(id): Path<PricingPolicyId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<PublishPricingPolicyVersion>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    match state
        .application
        .publish_pricing_policy_version(
            &identity,
            id,
            if_match(&headers, &identity.request_id)?,
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

pub async fn get_egress_network_policy(
    State(state): State<HttpState>,
    Path(id): Path<NetworkPolicyId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_egress_network_policy(&identity, id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn create_egress_network_policy(
    State(state): State<HttpState>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CreateEgressNetworkPolicy>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    match state
        .application
        .create_egress_network_policy(&identity, input, idempotency_key(&headers, &identity)?)
        .await
        .map_err(|error| app_error(error, &identity))?
    {
        IdempotentCommand::Executed((value, etag)) => {
            Ok(no_store(json_etag_response(value, &etag)))
        }
        IdempotentCommand::Replay(replay) => Ok(no_store(idempotency_replay_response(replay))),
    }
}

pub async fn update_egress_network_policy(
    State(state): State<HttpState>,
    Path(id): Path<NetworkPolicyId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateEgressNetworkPolicy>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let (value, etag) = state
        .application
        .update_egress_network_policy(
            &identity,
            id,
            if_match(&headers, &identity.request_id)?,
            input,
        )
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn replace_egress_custom_ca(
    State(state): State<HttpState>,
    Path(id): Path<NetworkPolicyId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<ReplaceEgressCustomCa>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let (value, etag) = state
        .application
        .replace_egress_custom_ca(
            &identity,
            id,
            if_match(&headers, &identity.request_id)?,
            input,
        )
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(no_store(json_etag_response(value, &etag)))
}

pub async fn get_reliability_policy(
    State(state): State<HttpState>,
    Path(id): Path<ReliabilityPolicyId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_reliability_policy(&identity, id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn create_reliability_policy(
    State(state): State<HttpState>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CreateReliabilityPolicy>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    match state
        .application
        .create_reliability_policy(&identity, input, idempotency_key(&headers, &identity)?)
        .await
        .map_err(|error| app_error(error, &identity))?
    {
        IdempotentCommand::Executed((value, etag)) => Ok(json_etag_response(value, &etag)),
        IdempotentCommand::Replay(replay) => Ok(idempotency_replay_response(replay)),
    }
}

pub async fn update_reliability_policy(
    State(state): State<HttpState>,
    Path(id): Path<ReliabilityPolicyId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateReliabilityPolicy>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let (value, etag) = state
        .application
        .update_reliability_policy(
            &identity,
            id,
            if_match(&headers, &identity.request_id)?,
            input,
        )
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn get_upstream_endpoint(
    State(state): State<HttpState>,
    Path(id): Path<EndpointId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_upstream_endpoint(&identity, id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn create_upstream_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CreateUpstreamEndpoint>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    match state
        .application
        .create_upstream_endpoint(&identity, input, idempotency_key(&headers, &identity)?)
        .await
        .map_err(|error| app_error(error, &identity))?
    {
        IdempotentCommand::Executed((value, etag)) => Ok(json_etag_response(value, &etag)),
        IdempotentCommand::Replay(replay) => Ok(idempotency_replay_response(replay)),
    }
}

pub async fn update_upstream_endpoint(
    State(state): State<HttpState>,
    Path(id): Path<EndpointId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateUpstreamEndpoint>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let (value, etag) = state
        .application
        .update_upstream_endpoint(
            &identity,
            id,
            if_match(&headers, &identity.request_id)?,
            input,
        )
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn validate_upstream_endpoint(
    State(state): State<HttpState>,
    Path(id): Path<EndpointId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    match state
        .application
        .validate_upstream_endpoint(&identity, id, idempotency_key(&headers, &identity)?)
        .await
        .map_err(|error| app_error(error, &identity))?
    {
        IdempotentCommand::Executed(value) => Ok(json_response(value)),
        IdempotentCommand::Replay(replay) => Ok(idempotency_replay_response(replay)),
    }
}

pub async fn list_gateway_api_keys(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .list_gateway_api_keys(
            &identity,
            organization_id,
            query.cursor.as_deref(),
            query.limit,
        )
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn get_gateway_api_key(
    State(state): State<HttpState>,
    Path((organization_id, key_id)): Path<(OrganizationId, GatewayKeyId)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_gateway_api_key(&identity, organization_id, key_id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn create_gateway_api_key(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CreateGatewayApiKey>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    reject_idempotency_key(&headers, &identity)?;
    let (value, etag) = state
        .application
        .create_gateway_api_key(&identity, organization_id, input)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(no_store(json_etag_response(value, &etag)))
}

pub async fn update_gateway_api_key(
    State(state): State<HttpState>,
    Path((organization_id, key_id)): Path<(OrganizationId, GatewayKeyId)>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateGatewayApiKey>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let (value, etag) = state
        .application
        .update_gateway_api_key(
            &identity,
            organization_id,
            key_id,
            if_match(&headers, &identity.request_id)?,
            input,
        )
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn rotate_gateway_api_key(
    State(state): State<HttpState>,
    Path((organization_id, key_id)): Path<(OrganizationId, GatewayKeyId)>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<RotateGatewayApiKey>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    reject_idempotency_key(&headers, &identity)?;
    let (value, etag) = state
        .application
        .rotate_gateway_api_key(
            &identity,
            organization_id,
            key_id,
            if_match(&headers, &identity.request_id)?,
            input,
        )
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(no_store(json_etag_response(value, &etag)))
}

pub async fn get_gateway_policy_ceilings(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_gateway_policy_ceilings(&identity)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn update_gateway_policy_ceilings(
    State(state): State<HttpState>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateGatewayPolicyCeilings>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let (value, etag) = state
        .application
        .update_gateway_policy_ceilings(&identity, if_match(&headers, &identity.request_id)?, input)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn get_gateway_key_budget(
    State(state): State<HttpState>,
    Path((organization_id, key_id)): Path<(OrganizationId, GatewayKeyId)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_gateway_key_budget(&identity, organization_id, key_id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn update_gateway_key_budget(
    State(state): State<HttpState>,
    Path((organization_id, key_id)): Path<(OrganizationId, GatewayKeyId)>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateBudgetPolicy>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let (value, etag) = state
        .application
        .update_gateway_key_budget(
            &identity,
            organization_id,
            key_id,
            if_match(&headers, &identity.request_id)?,
            input,
        )
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn begin_gateway_key_budget_epoch(
    State(state): State<HttpState>,
    Path((organization_id, key_id)): Path<(OrganizationId, GatewayKeyId)>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<BeginBudgetEpoch>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    match state
        .application
        .begin_gateway_key_budget_epoch(
            &identity,
            organization_id,
            key_id,
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

pub async fn get_gateway_key_limits(
    State(state): State<HttpState>,
    Path((organization_id, key_id)): Path<(OrganizationId, GatewayKeyId)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_gateway_key_limits(&identity, organization_id, key_id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn update_gateway_key_limits(
    State(state): State<HttpState>,
    Path((organization_id, key_id)): Path<(OrganizationId, GatewayKeyId)>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateGatewayRequestLimits>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let (value, etag) = state
        .application
        .update_gateway_key_limits(
            &identity,
            organization_id,
            key_id,
            if_match(&headers, &identity.request_id)?,
            input,
        )
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn get_system_provider_budget(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    get_provider_budget(
        state,
        headers,
        organization_id,
        AccountingOrigin::SystemProvided,
    )
    .await
}

pub async fn get_byok_provider_budget(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    get_provider_budget(
        state,
        headers,
        organization_id,
        AccountingOrigin::OrganizationByok,
    )
    .await
}

async fn get_provider_budget(
    state: HttpState,
    headers: HeaderMap,
    organization_id: OrganizationId,
    origin: AccountingOrigin,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_provider_budget(&identity, organization_id, origin)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn update_system_provider_budget(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateBudgetPolicy>,
) -> Result<Response, ApiError> {
    update_provider_budget(
        state,
        headers,
        organization_id,
        AccountingOrigin::SystemProvided,
        input,
    )
    .await
}

pub async fn update_byok_provider_budget(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateBudgetPolicy>,
) -> Result<Response, ApiError> {
    update_provider_budget(
        state,
        headers,
        organization_id,
        AccountingOrigin::OrganizationByok,
        input,
    )
    .await
}

async fn update_provider_budget(
    state: HttpState,
    headers: HeaderMap,
    organization_id: OrganizationId,
    origin: AccountingOrigin,
    input: UpdateBudgetPolicy,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let (value, etag) = state
        .application
        .update_provider_budget(
            &identity,
            organization_id,
            origin,
            if_match(&headers, &identity.request_id)?,
            input,
        )
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn begin_system_provider_budget_epoch(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<BeginBudgetEpoch>,
) -> Result<Response, ApiError> {
    begin_provider_budget_epoch(
        state,
        headers,
        organization_id,
        AccountingOrigin::SystemProvided,
        input,
    )
    .await
}

pub async fn begin_byok_provider_budget_epoch(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<BeginBudgetEpoch>,
) -> Result<Response, ApiError> {
    begin_provider_budget_epoch(
        state,
        headers,
        organization_id,
        AccountingOrigin::OrganizationByok,
        input,
    )
    .await
}

async fn begin_provider_budget_epoch(
    state: HttpState,
    headers: HeaderMap,
    organization_id: OrganizationId,
    origin: AccountingOrigin,
    input: BeginBudgetEpoch,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    match state
        .application
        .begin_provider_budget_epoch(
            &identity,
            organization_id,
            origin,
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

pub async fn list_system_model_deployments(
    State(state): State<HttpState>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    list_model_deployments(state, headers, ResourceScope::Deployment, query).await
}

pub async fn list_organization_model_deployments(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    list_model_deployments(
        state,
        headers,
        ResourceScope::Organization { organization_id },
        query,
    )
    .await
}

async fn list_model_deployments(
    state: HttpState,
    headers: HeaderMap,
    scope: ResourceScope,
    query: PageQuery,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .list_model_deployments(&identity, scope, query.cursor.as_deref(), query.limit)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn get_system_model_deployment(
    State(state): State<HttpState>,
    Path(id): Path<DeploymentId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    get_model_deployment(state, headers, ResourceScope::Deployment, id).await
}

pub async fn get_organization_model_deployment(
    State(state): State<HttpState>,
    Path((organization_id, id)): Path<(OrganizationId, DeploymentId)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    get_model_deployment(
        state,
        headers,
        ResourceScope::Organization { organization_id },
        id,
    )
    .await
}

async fn get_model_deployment(
    state: HttpState,
    headers: HeaderMap,
    scope: ResourceScope,
    id: DeploymentId,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_model_deployment(&identity, scope, id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn create_system_model_deployment(
    State(state): State<HttpState>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CreateModelDeployment>,
) -> Result<Response, ApiError> {
    create_model_deployment(state, headers, ResourceScope::Deployment, input).await
}

pub async fn create_organization_model_deployment(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CreateModelDeployment>,
) -> Result<Response, ApiError> {
    create_model_deployment(
        state,
        headers,
        ResourceScope::Organization { organization_id },
        input,
    )
    .await
}

async fn create_model_deployment(
    state: HttpState,
    headers: HeaderMap,
    scope: ResourceScope,
    input: CreateModelDeployment,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    match state
        .application
        .create_model_deployment(
            &identity,
            scope,
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

pub async fn update_system_model_deployment(
    State(state): State<HttpState>,
    Path(id): Path<DeploymentId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateModelDeployment>,
) -> Result<Response, ApiError> {
    update_model_deployment(state, headers, ResourceScope::Deployment, id, input).await
}

pub async fn update_organization_model_deployment(
    State(state): State<HttpState>,
    Path((organization_id, id)): Path<(OrganizationId, DeploymentId)>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateModelDeployment>,
) -> Result<Response, ApiError> {
    update_model_deployment(
        state,
        headers,
        ResourceScope::Organization { organization_id },
        id,
        input,
    )
    .await
}

async fn update_model_deployment(
    state: HttpState,
    headers: HeaderMap,
    scope: ResourceScope,
    id: DeploymentId,
    input: UpdateModelDeployment,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let (value, etag) = state
        .application
        .update_model_deployment(
            &identity,
            scope,
            id,
            if_match(&headers, &identity.request_id)?,
            input,
        )
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn validate_system_model_deployment(
    State(state): State<HttpState>,
    Path(id): Path<DeploymentId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    validate_model_deployment(state, headers, ResourceScope::Deployment, id).await
}

pub async fn validate_organization_model_deployment(
    State(state): State<HttpState>,
    Path((organization_id, id)): Path<(OrganizationId, DeploymentId)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    validate_model_deployment(
        state,
        headers,
        ResourceScope::Organization { organization_id },
        id,
    )
    .await
}

async fn validate_model_deployment(
    state: HttpState,
    headers: HeaderMap,
    scope: ResourceScope,
    id: DeploymentId,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    match state
        .application
        .validate_model_deployment(&identity, scope, id, idempotency_key(&headers, &identity)?)
        .await
        .map_err(|error| app_error(error, &identity))?
    {
        IdempotentCommand::Executed(value) => Ok(json_response(value)),
        IdempotentCommand::Replay(replay) => Ok(idempotency_replay_response(replay)),
    }
}

pub async fn list_system_model_routes(
    State(state): State<HttpState>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    list_model_routes(state, headers, ResourceScope::Deployment, query).await
}

pub async fn list_organization_model_routes(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    list_model_routes(
        state,
        headers,
        ResourceScope::Organization { organization_id },
        query,
    )
    .await
}

async fn list_model_routes(
    state: HttpState,
    headers: HeaderMap,
    scope: ResourceScope,
    query: PageQuery,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .list_model_routes(&identity, scope, query.cursor.as_deref(), query.limit)
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn get_system_model_route(
    State(state): State<HttpState>,
    Path(id): Path<RouteId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    get_model_route(state, headers, ResourceScope::Deployment, id).await
}

pub async fn get_organization_model_route(
    State(state): State<HttpState>,
    Path((organization_id, id)): Path<(OrganizationId, RouteId)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    get_model_route(
        state,
        headers,
        ResourceScope::Organization { organization_id },
        id,
    )
    .await
}

async fn get_model_route(
    state: HttpState,
    headers: HeaderMap,
    scope: ResourceScope,
    id: RouteId,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_model_route(&identity, scope, id)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn create_system_model_route(
    State(state): State<HttpState>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CreateModelRoute>,
) -> Result<Response, ApiError> {
    create_model_route(state, headers, ResourceScope::Deployment, input).await
}

pub async fn create_organization_model_route(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<CreateModelRoute>,
) -> Result<Response, ApiError> {
    create_model_route(
        state,
        headers,
        ResourceScope::Organization { organization_id },
        input,
    )
    .await
}

async fn create_model_route(
    state: HttpState,
    headers: HeaderMap,
    scope: ResourceScope,
    input: CreateModelRoute,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    match state
        .application
        .create_model_route(
            &identity,
            scope,
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

pub async fn update_system_model_route(
    State(state): State<HttpState>,
    Path(id): Path<RouteId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateModelRoute>,
) -> Result<Response, ApiError> {
    update_model_route(state, headers, ResourceScope::Deployment, id, input).await
}

pub async fn update_organization_model_route(
    State(state): State<HttpState>,
    Path((organization_id, id)): Path<(OrganizationId, RouteId)>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateModelRoute>,
) -> Result<Response, ApiError> {
    update_model_route(
        state,
        headers,
        ResourceScope::Organization { organization_id },
        id,
        input,
    )
    .await
}

async fn update_model_route(
    state: HttpState,
    headers: HeaderMap,
    scope: ResourceScope,
    id: RouteId,
    input: UpdateModelRoute,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let (value, etag) = state
        .application
        .update_model_route(
            &identity,
            scope,
            id,
            if_match(&headers, &identity.request_id)?,
            input,
        )
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn transfer_organization_model_route_ownership(
    State(state): State<HttpState>,
    Path((organization_id, id)): Path<(OrganizationId, RouteId)>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<TransferModelRouteOwnership>,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let (value, etag) = state
        .application
        .transfer_model_route_ownership(
            &identity,
            organization_id,
            id,
            if_match(&headers, &identity.request_id)?,
            input,
        )
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn get_system_route_grants(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    get_catalog_grants(
        state,
        headers,
        organization_id,
        CatalogGrantKind::SystemRoute,
    )
    .await
}

pub async fn update_system_route_grants(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateCatalogGrantSet>,
) -> Result<Response, ApiError> {
    update_catalog_grants(
        state,
        headers,
        organization_id,
        CatalogGrantKind::SystemRoute,
        input,
    )
    .await
}

pub async fn get_endpoint_grants(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    get_catalog_grants(state, headers, organization_id, CatalogGrantKind::Endpoint).await
}

pub async fn update_endpoint_grants(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateCatalogGrantSet>,
) -> Result<Response, ApiError> {
    update_catalog_grants(
        state,
        headers,
        organization_id,
        CatalogGrantKind::Endpoint,
        input,
    )
    .await
}

pub async fn get_deployment_grants(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    get_catalog_grants(
        state,
        headers,
        organization_id,
        CatalogGrantKind::Deployment,
    )
    .await
}

pub async fn update_deployment_grants(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateCatalogGrantSet>,
) -> Result<Response, ApiError> {
    update_catalog_grants(
        state,
        headers,
        organization_id,
        CatalogGrantKind::Deployment,
        input,
    )
    .await
}

pub async fn get_reliability_policy_grants(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    get_catalog_grants(
        state,
        headers,
        organization_id,
        CatalogGrantKind::ReliabilityPolicy,
    )
    .await
}

pub async fn update_reliability_policy_grants(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<UpdateCatalogGrantSet>,
) -> Result<Response, ApiError> {
    update_catalog_grants(
        state,
        headers,
        organization_id,
        CatalogGrantKind::ReliabilityPolicy,
        input,
    )
    .await
}

async fn get_catalog_grants(
    state: HttpState,
    headers: HeaderMap,
    organization_id: OrganizationId,
    kind: CatalogGrantKind,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    let (value, etag) = state
        .application
        .get_catalog_grant_set(&identity, organization_id, kind)
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

async fn update_catalog_grants(
    state: HttpState,
    headers: HeaderMap,
    organization_id: OrganizationId,
    kind: CatalogGrantKind,
    input: UpdateCatalogGrantSet,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    require_command_security(&state.application, &identity, &headers)?;
    let (value, etag) = state
        .application
        .update_catalog_grant_set(
            &identity,
            organization_id,
            kind,
            if_match(&headers, &identity.request_id)?,
            input,
        )
        .await
        .map_err(|error| app_error(error, &identity))?;
    Ok(json_etag_response(value, &etag))
}

pub async fn list_available_endpoints(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .list_available_endpoints(
            &identity,
            organization_id,
            query.cursor.as_deref(),
            query.limit,
        )
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn list_available_deployments(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .list_available_deployments(
            &identity,
            organization_id,
            query.cursor.as_deref(),
            query.limit,
        )
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn list_available_reliability_policies(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .list_available_reliability_policies(
            &identity,
            organization_id,
            query.cursor.as_deref(),
            query.limit,
        )
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}

pub async fn list_available_routes(
    State(state): State<HttpState>,
    Path(organization_id): Path<OrganizationId>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state.application, &headers).await?;
    state
        .application
        .list_available_routes(
            &identity,
            organization_id,
            query.cursor.as_deref(),
            query.limit,
        )
        .await
        .map(json_response)
        .map_err(|error| app_error(error, &identity))
}
