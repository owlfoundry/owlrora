mod admission;
mod dispatch;
mod health;
mod protection;
mod usage;
mod websocket;

#[cfg(test)]
mod e2e_tests;

pub(crate) use admission::{
    AttemptReservation, GatewayAdmissionState, LogicalAdmissionError, LogicalRequestPermit,
};
pub(crate) use health::{TargetProbeObservation, TargetProbeWorker};
pub(crate) use protection::{TargetAttemptPermit, TargetProtectionState};
pub(crate) use usage::{UsageAggregator, UsageConfig, UsageStatus};

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub use dispatch::dispatch;
pub use websocket::upgrade as upgrade_responses_websocket;

use axum::http::HeaderMap;
use chrono::Utc;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{
    adapters::coordinator::RedisCoordinator,
    application::{Application, ApplicationError},
    domain::{
        CapabilityClaimPolicy, GatewayKeyId, GatewayKeyMaterial, IngressProtocolFamily,
        JwtRouteCeiling, LlmFeatureCapability, LlmScope, LlmScopeSet, OrganizationId,
        OrganizationSelector, RouteAffinityMode, RouteId, RouteRequestPolicy, TargetId, UserId,
        compatibility, constant_time_gateway_digest_matches, gateway_key_digest,
    },
    protocols::{LlmIntent, ProtocolError, ProtocolErrorKind},
    runtime::{
        DeploymentSnapshot, ExternalIssuerSnapshot, GatewayKeyVerifier, MembershipSnapshot,
        OrganizationSnapshot, RouteSnapshot, RuntimeGeneration, TargetSnapshot,
    },
};

const ORGANIZATION_HEADER: &str = "x-owlrora-organization-id";
const SESSION_HEADER: &str = "x-owlrora-session-id";
const MAX_AFFINITY_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayPrincipalKind {
    GatewayKey,
    LocalUser,
}

#[derive(Clone, Debug)]
pub enum GatewayPrincipal {
    GatewayKey {
        key_id: GatewayKeyId,
        verifier: GatewayKeyVerifier,
    },
    LocalUser {
        user_id: UserId,
        issuer_id: crate::domain::IssuerId,
        subject: String,
        scopes: LlmScopeSet,
        capabilities: BTreeSet<LlmFeatureCapability>,
        routes: JwtRouteCeiling,
        membership: MembershipSnapshot,
    },
}

impl GatewayPrincipal {
    #[must_use]
    pub const fn kind(&self) -> GatewayPrincipalKind {
        match self {
            Self::GatewayKey { .. } => GatewayPrincipalKind::GatewayKey,
            Self::LocalUser { .. } => GatewayPrincipalKind::LocalUser,
        }
    }

    #[must_use]
    pub const fn affinity_uuid(&self) -> Uuid {
        match self {
            Self::GatewayKey { key_id, .. } => key_id.as_uuid(),
            Self::LocalUser { user_id, .. } => user_id.as_uuid(),
        }
    }

    #[must_use]
    pub fn allows_scopes(&self, required: &LlmScopeSet) -> bool {
        match self {
            Self::GatewayKey { verifier, .. } => verifier
                .scopes
                .as_ref()
                .is_some_and(|scopes| scopes.is_superset(required)),
            Self::LocalUser {
                scopes, membership, ..
            } => scopes.is_superset(required) && membership.llm_scopes.allows(required),
        }
    }

    #[must_use]
    pub fn allows_capabilities(&self, required: &BTreeSet<LlmFeatureCapability>) -> bool {
        match self {
            Self::GatewayKey { verifier, .. } => verifier.capabilities.is_superset(required),
            Self::LocalUser {
                capabilities,
                membership,
                ..
            } => {
                capabilities.is_superset(required)
                    && membership.llm_capabilities.is_superset(required)
            }
        }
    }

    #[must_use]
    pub fn allows_route(&self, route_id: RouteId) -> bool {
        match self {
            Self::GatewayKey { verifier, .. } => verifier.route_ids.contains(&route_id),
            Self::LocalUser {
                routes, membership, ..
            } => {
                route_ceiling_allows(routes, route_id)
                    && route_ceiling_allows(&membership.llm_routes, route_id)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct AdmissionContext {
    pub generation: Arc<RuntimeGeneration>,
    pub(crate) coordinator: Option<Arc<RedisCoordinator>>,
    pub(crate) admission_state: Arc<GatewayAdmissionState>,
    pub(crate) protection: Arc<TargetProtectionState>,
    pub(crate) usage: Arc<UsageAggregator>,
    pub request_id: String,
    pub organization: OrganizationSnapshot,
    pub principal: GatewayPrincipal,
    pub route: RouteSnapshot,
    pub effective_request_policy: RouteRequestPolicy,
    pub candidates: Vec<Candidate>,
}

#[derive(Clone, Debug)]
pub struct Candidate {
    pub target: TargetSnapshot,
    pub deployment: DeploymentSnapshot,
    pub client_build_fingerprint: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialLocation {
    AuthorizationBearer,
    AnthropicApiKey,
    GeminiApiKey,
}

pub fn authenticate_and_admit(
    application: &Application,
    family: IngressProtocolFamily,
    headers: &HeaderMap,
    intent: &LlmIntent,
    request_id: String,
) -> Result<AdmissionContext, ProtocolError> {
    let (generation, organization, principal) =
        authenticate_identity(application, family, headers, &request_id)?;
    let route = generation
        .snapshot
        .catalog
        .resolve_route(&organization, family, &intent.model_key)
        .cloned()
        .ok_or_else(|| {
            error(
                family,
                ProtocolErrorKind::RouteUnavailable,
                request_id.clone(),
                "model route is not available",
            )
        })?;
    if !principal.allows_route(route.id)
        || !principal.allows_scopes(&intent.required_scopes)
        || !principal.allows_capabilities(&intent.required_capabilities)
    {
        return Err(error(
            family,
            ProtocolErrorKind::Forbidden,
            request_id,
            "request exceeds the principal authorization ceiling",
        ));
    }
    let mut required = route.required_base_capabilities.clone();
    required.extend(intent.required_capabilities.iter().copied());
    let system_route_grant = route
        .organization_id
        .is_none()
        .then(|| organization.system_route_grants.get(&route.id))
        .flatten();
    if system_route_grant.is_some_and(|grant| {
        !grant
            .ceilings
            .allows_capabilities(&intent.required_capabilities)
    }) {
        return Err(error(
            family,
            ProtocolErrorKind::Forbidden,
            request_id,
            "request exceeds the system route grant capability ceiling",
        ));
    }
    let effective_request_policy = system_route_grant.map_or_else(
        || route.request_policy.clone(),
        |grant| grant.ceilings.narrow_request_policy(&route.request_policy),
    );
    let candidates = order_candidates(
        &generation,
        &organization,
        &principal,
        &route,
        intent,
        headers,
        &request_id,
        &required,
        &effective_request_policy,
        application.target_probes.as_deref(),
    );
    if candidates.is_empty() {
        return Err(error(
            family,
            ProtocolErrorKind::UnsupportedCapability,
            request_id,
            "no target supports the requested protocol capabilities",
        ));
    }
    Ok(AdmissionContext {
        generation,
        coordinator: application.coordinator.clone(),
        admission_state: Arc::clone(&application.gateway_admission),
        protection: Arc::clone(&application.target_protection),
        usage: Arc::clone(&application.usage),
        request_id,
        organization,
        principal,
        route,
        effective_request_policy,
        candidates,
    })
}

pub fn authenticate_websocket_connection(
    application: &Application,
    headers: &HeaderMap,
    request_id: &str,
) -> Result<(), ProtocolError> {
    let family = IngressProtocolFamily::OpenaiResponses;
    let (generation, organization, principal) =
        authenticate_identity(application, family, headers, request_id)?;
    let required_scopes = LlmScopeSet::new([LlmScope::Invoke, LlmScope::Stream])
        .expect("WebSocket connection scopes include llm:invoke");
    if !principal.allows_scopes(&required_scopes) {
        return Err(error(
            family,
            ProtocolErrorKind::Forbidden,
            request_id,
            "WebSocket connection exceeds the principal authorization ceiling",
        ));
    }
    let has_route = generation.snapshot.catalog.routes.values().any(|route| {
        let system_route_grant = route
            .organization_id
            .is_none()
            .then(|| organization.system_route_grants.get(&route.id))
            .flatten();
        let route_visible =
            route.organization_id == Some(organization.id) || system_route_grant.is_some();
        let request_capabilities = BTreeSet::from([LlmFeatureCapability::Streaming]);
        let mut target_capabilities = route.required_base_capabilities.clone();
        target_capabilities.extend(request_capabilities.iter().copied());
        if !route.active
            || !route_visible
            || route.ingress_protocol_family != family
            || !principal.allows_route(route.id)
            || !principal.allows_capabilities(&request_capabilities)
            || system_route_grant
                .is_some_and(|grant| !grant.ceilings.allows_capabilities(&request_capabilities))
        {
            return false;
        }
        let effective_request_policy = system_route_grant.map_or_else(
            || route.request_policy.clone(),
            |grant| grant.ceilings.narrow_request_policy(&route.request_policy),
        );
        let intent = LlmIntent {
            model_key: route.model_key.clone(),
            response_mode: crate::protocols::ResponseMode::WebSocket,
            required_scopes: required_scopes.clone(),
            required_capabilities: request_capabilities,
            requested_output_bound: None,
            continuation_reference: None,
            replay_safe: true,
        };
        !order_candidates(
            &generation,
            &organization,
            &principal,
            route,
            &intent,
            headers,
            request_id,
            &target_capabilities,
            &effective_request_policy,
            application.target_probes.as_deref(),
        )
        .is_empty()
    });
    if !has_route {
        return Err(error(
            family,
            ProtocolErrorKind::UnsupportedCapability,
            request_id,
            "no authorized Responses WebSocket route is available",
        ));
    }
    Ok(())
}

fn authenticate_identity(
    application: &Application,
    family: IngressProtocolFamily,
    headers: &HeaderMap,
    request_id: &str,
) -> Result<
    (
        Arc<RuntimeGeneration>,
        OrganizationSnapshot,
        GatewayPrincipal,
    ),
    ProtocolError,
> {
    let generation = application
        .runtime()
        .capture_for_admission(Utc::now(), application.config().max_security_snapshot_age)
        .ok_or_else(|| {
            error(
                family,
                ProtocolErrorKind::RouteUnavailable,
                request_id,
                "gateway runtime is not current",
            )
        })?;
    let credential = extract_credential(family, headers, request_id)?;
    let (organization_id, principal) = match credential.location {
        CredentialLocation::AnthropicApiKey | CredentialLocation::GeminiApiKey => {
            let verifier =
                authenticate_gateway_key(&generation, credential.value, family, request_id)?;
            (
                verifier.organization_id,
                GatewayPrincipal::GatewayKey {
                    key_id: verifier.key_id,
                    verifier,
                },
            )
        }
        CredentialLocation::AuthorizationBearer => {
            if credential.value.starts_with("owlrora_llm_v1.") {
                let verifier =
                    authenticate_gateway_key(&generation, credential.value, family, request_id)?;
                (
                    verifier.organization_id,
                    GatewayPrincipal::GatewayKey {
                        key_id: verifier.key_id,
                        verifier,
                    },
                )
            } else {
                authenticate_direct_jwt(
                    application,
                    &generation,
                    credential.value,
                    headers,
                    family,
                    request_id,
                )?
            }
        }
    };
    let organization = generation
        .snapshot
        .organizations
        .get(&organization_id)
        .filter(|organization| organization.active)
        .cloned()
        .ok_or_else(|| {
            error(
                family,
                ProtocolErrorKind::Forbidden,
                request_id,
                "organization is not available",
            )
        })?;
    Ok((generation, organization, principal))
}

struct ExtractedCredential<'a> {
    location: CredentialLocation,
    value: &'a str,
}

fn extract_credential<'a>(
    family: IngressProtocolFamily,
    headers: &'a HeaderMap,
    request_id: &str,
) -> Result<ExtractedCredential<'a>, ProtocolError> {
    let authorization = exactly_one_header(headers, "authorization", family, request_id)?
        .map(|value| {
            value
                .strip_prefix("Bearer ")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    error(
                        family,
                        ProtocolErrorKind::Authentication,
                        request_id,
                        "Authorization must use Bearer authentication",
                    )
                })
        })
        .transpose()?;
    let provider_key = match family {
        IngressProtocolFamily::AnthropicMessages => {
            exactly_one_header(headers, "x-api-key", family, request_id)?
                .map(|value| (CredentialLocation::AnthropicApiKey, value))
        }
        IngressProtocolFamily::GoogleGemini => {
            exactly_one_header(headers, "x-goog-api-key", family, request_id)?
                .map(|value| (CredentialLocation::GeminiApiKey, value))
        }
        IngressProtocolFamily::OpenaiChatCompletions | IngressProtocolFamily::OpenaiResponses => {
            None
        }
    };
    if authorization.is_some() && provider_key.is_some() {
        return Err(error(
            family,
            ProtocolErrorKind::ConflictingAuthentication,
            request_id,
            "more than one credential location was supplied",
        ));
    }
    if let Some((location, value)) = provider_key {
        if !value.starts_with("owlrora_llm_v1.") {
            return Err(error(
                family,
                ProtocolErrorKind::Authentication,
                request_id,
                "the protocol API-key location accepts only a Gateway API key",
            ));
        }
        return Ok(ExtractedCredential { location, value });
    }
    let value = authorization.ok_or_else(|| {
        error(
            family,
            ProtocolErrorKind::Authentication,
            request_id,
            "a supported credential is required",
        )
    })?;
    if matches!(
        family,
        IngressProtocolFamily::AnthropicMessages | IngressProtocolFamily::GoogleGemini
    ) && value.starts_with("owlrora_llm_v1.")
    {
        return Err(error(
            family,
            ProtocolErrorKind::Authentication,
            request_id,
            "Gateway API key is in the wrong credential location",
        ));
    }
    Ok(ExtractedCredential {
        location: CredentialLocation::AuthorizationBearer,
        value,
    })
}

fn exactly_one_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
    family: IngressProtocolFamily,
    request_id: &str,
) -> Result<Option<&'a str>, ProtocolError> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(error(
            family,
            ProtocolErrorKind::ConflictingAuthentication,
            request_id,
            "duplicate credential headers are not accepted",
        ));
    }
    first
        .map(|value| {
            value.to_str().map_err(|_| {
                error(
                    family,
                    ProtocolErrorKind::Authentication,
                    request_id,
                    "credential header is invalid",
                )
            })
        })
        .transpose()
}

fn authenticate_gateway_key(
    generation: &RuntimeGeneration,
    raw: &str,
    family: IngressProtocolFamily,
    request_id: &str,
) -> Result<GatewayKeyVerifier, ProtocolError> {
    let material = GatewayKeyMaterial::parse(raw).map_err(|_| {
        error(
            family,
            ProtocolErrorKind::Authentication,
            request_id,
            "Gateway API key is invalid",
        )
    })?;
    let verifier = generation
        .snapshot
        .gateway_keys
        .get(&material.lookup_text())
        .filter(|verifier| verifier.active)
        .filter(|verifier| verifier.expires_at.is_none_or(|expiry| expiry > Utc::now()))
        .cloned()
        .ok_or_else(|| {
            error(
                family,
                ProtocolErrorKind::Authentication,
                request_id,
                "Gateway API key is invalid",
            )
        })?;
    let digest = gateway_key_digest(&material);
    let current = constant_time_gateway_digest_matches(&digest, &verifier.current_digest);
    let overlap = verifier.overlap_digest.as_ref().is_some_and(|expected| {
        verifier
            .overlap_until
            .is_some_and(|deadline| deadline > Utc::now())
            && constant_time_gateway_digest_matches(&digest, expected)
    });
    if !current && !overlap {
        return Err(error(
            family,
            ProtocolErrorKind::Authentication,
            request_id,
            "Gateway API key is invalid",
        ));
    }
    Ok(verifier)
}

fn authenticate_direct_jwt(
    application: &Application,
    generation: &Arc<RuntimeGeneration>,
    raw: &str,
    headers: &HeaderMap,
    family: IngressProtocolFamily,
    request_id: &str,
) -> Result<(OrganizationId, GatewayPrincipal), ProtocolError> {
    let (issuer_id, subject, claims) = application
        .verify_external_jwt_evidence_for_gateway(raw, generation)
        .map_err(|_| {
            error(
                family,
                ProtocolErrorKind::Authentication,
                request_id,
                "JWT is invalid",
            )
        })?;
    let issuer = generation
        .snapshot
        .identity
        .external_issuers_by_id
        .get(&issuer_id)
        .filter(|issuer| issuer.active && issuer.llm_access)
        .ok_or_else(|| {
            error(
                family,
                ProtocolErrorKind::Forbidden,
                request_id,
                "issuer does not permit direct LLM access",
            )
        })?;
    let user_id = generation
        .snapshot
        .identity
        .external_bindings
        .get(&(issuer_id, subject.clone()))
        .copied()
        .filter(|user_id| {
            generation
                .snapshot
                .identity
                .active_users
                .get(user_id)
                .copied()
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            error(
                family,
                ProtocolErrorKind::Authentication,
                request_id,
                "JWT does not resolve to an active local user",
            )
        })?;
    let organization_id = selected_organization(issuer, &claims, headers, family, request_id)?;
    let membership = generation
        .snapshot
        .identity
        .memberships
        .get(&(organization_id, user_id))
        .cloned()
        .ok_or_else(|| {
            error(
                family,
                ProtocolErrorKind::Forbidden,
                request_id,
                "local user is not an active organization member",
            )
        })?;
    let (scopes, capabilities, routes) = derive_llm_ceiling(issuer, &claims).map_err(|_| {
        error(
            family,
            ProtocolErrorKind::Authentication,
            request_id,
            "JWT LLM claims are invalid",
        )
    })?;
    Ok((
        organization_id,
        GatewayPrincipal::LocalUser {
            user_id,
            issuer_id,
            subject,
            scopes,
            capabilities,
            routes,
            membership,
        },
    ))
}

fn selected_organization(
    issuer: &ExternalIssuerSnapshot,
    claims: &Value,
    headers: &HeaderMap,
    family: IngressProtocolFamily,
    request_id: &str,
) -> Result<OrganizationId, ProtocolError> {
    let header = exactly_one_header(headers, ORGANIZATION_HEADER, family, request_id)?
        .map(str::parse::<OrganizationId>)
        .transpose()
        .map_err(|_| {
            error(
                family,
                ProtocolErrorKind::Authentication,
                request_id,
                "organization header is invalid",
            )
        })?;
    let claim_at = |path: &str| claim_value(claims, path).and_then(Value::as_str);
    let selected = match &issuer.organization_selector {
        OrganizationSelector::None => None,
        OrganizationSelector::SignedClaim { claim } => claim_at(claim)
            .map(str::parse::<OrganizationId>)
            .transpose()
            .map_err(|_| invalid_org(family, request_id))?,
        OrganizationSelector::Header => header,
        OrganizationSelector::Either { claim } => {
            let claimed = claim_at(claim)
                .map(str::parse::<OrganizationId>)
                .transpose()
                .map_err(|_| invalid_org(family, request_id))?;
            if claimed.is_some() && header.is_some() && claimed != header {
                return Err(error(
                    family,
                    ProtocolErrorKind::ConflictingAuthentication,
                    request_id,
                    "signed and header organization selectors conflict",
                ));
            }
            claimed.or(header)
        }
    };
    selected.ok_or_else(|| invalid_org(family, request_id))
}

fn invalid_org(family: IngressProtocolFamily, request_id: &str) -> ProtocolError {
    error(
        family,
        ProtocolErrorKind::Authentication,
        request_id,
        "an explicit valid organization selection is required",
    )
}

fn derive_llm_ceiling(
    issuer: &ExternalIssuerSnapshot,
    claims: &Value,
) -> Result<(LlmScopeSet, BTreeSet<LlmFeatureCapability>, JwtRouteCeiling), ApplicationError> {
    let mut scopes = issuer
        .llm_scopes
        .as_scopes()
        .cloned()
        .ok_or(ApplicationError::Forbidden)?;
    let mut capabilities = issuer.llm_capabilities.clone();
    let mut routes = issuer.llm_routes.clone();
    if issuer.capability_claim_policy == CapabilityClaimPolicy::Ignore {
        return Ok((scopes, capabilities, routes));
    }
    if let Some(path) = &issuer.claim_mapping.llm_scopes_claim {
        match claim_string_set(claims, path)? {
            Some(values) => {
                let claimed = serde_json::from_value::<LlmScopeSet>(Value::Array(
                    values.into_iter().map(Value::String).collect(),
                ))
                .map_err(|_| ApplicationError::InvalidCredential)?;
                scopes = scopes
                    .intersection(&claimed)
                    .ok_or(ApplicationError::Forbidden)?;
            }
            None if issuer.capability_claim_policy == CapabilityClaimPolicy::RequiredNarrowing => {
                return Err(ApplicationError::InvalidCredential);
            }
            None => {}
        }
    }
    if let Some(path) = &issuer.claim_mapping.llm_capabilities_claim {
        match claim_string_set(claims, path)? {
            Some(values) => {
                let claimed = values
                    .into_iter()
                    .map(|value| {
                        serde_json::from_value::<LlmFeatureCapability>(Value::String(value))
                            .map_err(|_| ApplicationError::InvalidCredential)
                    })
                    .collect::<Result<BTreeSet<_>, _>>()?;
                capabilities = capabilities.intersection(&claimed).copied().collect();
            }
            None if issuer.capability_claim_policy == CapabilityClaimPolicy::RequiredNarrowing => {
                return Err(ApplicationError::InvalidCredential);
            }
            None => {}
        }
    }
    if let Some(path) = &issuer.claim_mapping.routes_claim {
        match claim_string_set(claims, path)? {
            Some(values) => {
                let claimed = values
                    .into_iter()
                    .map(|value| {
                        value
                            .parse::<RouteId>()
                            .map_err(|_| ApplicationError::InvalidCredential)
                    })
                    .collect::<Result<BTreeSet<_>, _>>()?;
                routes = intersect_route_ceiling(&routes, &claimed);
            }
            None if issuer.capability_claim_policy == CapabilityClaimPolicy::RequiredNarrowing => {
                return Err(ApplicationError::InvalidCredential);
            }
            None => {}
        }
    }
    Ok((scopes, capabilities, routes))
}

fn order_candidates(
    generation: &RuntimeGeneration,
    organization: &OrganizationSnapshot,
    principal: &GatewayPrincipal,
    route: &RouteSnapshot,
    intent: &LlmIntent,
    headers: &HeaderMap,
    request_id: &str,
    required_capabilities: &BTreeSet<LlmFeatureCapability>,
    request_policy: &RouteRequestPolicy,
    target_probes: Option<&TargetProbeWorker>,
) -> Vec<Candidate> {
    let requested_bound = intent
        .requested_output_bound
        .unwrap_or(request_policy.max_output_units);
    let affinity = affinity_source(route, headers, request_id);
    let affinity_hash = replicated_wrh_base(
        organization.id,
        principal.affinity_uuid(),
        route.id,
        affinity.0,
        affinity.1,
    );
    let mut tiers = BTreeMap::<u8, Vec<Candidate>>::new();
    for target in &route.targets {
        let Some(deployment) = generation
            .snapshot
            .catalog
            .deployments
            .get(&target.deployment_id)
            .filter(|deployment| deployment.operational)
        else {
            continue;
        };
        if !deployment.capabilities.is_superset(required_capabilities)
            || target
                .narrowing_constraints
                .max_output_units
                .is_some_and(|bound| requested_bound > bound)
        {
            continue;
        }
        let Some(entry) = compatibility(
            route.ingress_protocol_family,
            deployment.endpoint_adapter,
            deployment.credential_kind,
            deployment.transport_kind,
        ) else {
            continue;
        };
        let mode_supported = match intent.response_mode {
            crate::protocols::ResponseMode::Json => entry.supports_http,
            crate::protocols::ResponseMode::Sse => entry.supports_streaming,
            crate::protocols::ResponseMode::WebSocket => entry.supports_websocket,
        };
        if !mode_supported {
            continue;
        }
        if route.scope == crate::domain::CatalogScopeKind::Organization
            && deployment.scope == crate::domain::CatalogScopeKind::Deployment
            && !organization.deployment_grants.contains(&deployment.id)
        {
            continue;
        }
        let Some(client) = generation
            .credential_clients
            .clients
            .get(&deployment.client_key())
        else {
            continue;
        };
        let candidate = Candidate {
            target: target.clone(),
            deployment: deployment.clone(),
            client_build_fingerprint: *client.build_fingerprint(),
        };
        if let Some(target_probes) = target_probes
            && let Some(reliability) = generation
                .snapshot
                .catalog
                .reliability_policies
                .get(&route.reliability_policy_id)
            && !target_probes.allows_candidate(
                generation,
                route,
                &candidate,
                reliability,
                affinity_hash,
            )
        {
            continue;
        }
        tiers.entry(target.priority).or_default().push(candidate);
    }
    let mut result = Vec::new();
    for (_, tier) in tiers {
        let ordered = replicated_wrh_order(
            organization.id,
            principal.affinity_uuid(),
            route.id,
            affinity.0,
            affinity.1,
            tier.iter().map(|candidate| &candidate.target),
        );
        for target_id in ordered {
            if let Some(candidate) = tier
                .iter()
                .find(|candidate| candidate.target.id == target_id)
            {
                result.push(candidate.clone());
            }
        }
    }
    result
}

fn affinity_source<'a>(
    route: &RouteSnapshot,
    headers: &'a HeaderMap,
    request_id: &'a str,
) -> (u8, &'a [u8]) {
    if route.selection_policy.affinity_mode == RouteAffinityMode::Preferred
        && let Some(value) = headers
            .get(SESSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty() && value.len() <= MAX_AFFINITY_BYTES)
    {
        return (0, value.as_bytes());
    }
    (2, request_id.as_bytes())
}

fn replicated_wrh_base(
    organization_id: OrganizationId,
    principal_affinity_id: Uuid,
    route_id: RouteId,
    source_tag: u8,
    value: &[u8],
) -> [u8; 32] {
    let mut base = Sha256::new();
    base.update(b"owlrora/replicated-wrh-v1/base");
    base.update([0]);
    base.update(organization_id.as_uuid().as_bytes());
    base.update(principal_affinity_id.as_bytes());
    base.update(route_id.as_uuid().as_bytes());
    base.update([source_tag]);
    base.update(
        u32::try_from(value.len())
            .expect("affinity source is bounded")
            .to_be_bytes(),
    );
    base.update(value);
    base.finalize().into()
}

pub fn replicated_wrh_order<'a>(
    organization_id: OrganizationId,
    principal_affinity_id: Uuid,
    route_id: RouteId,
    source_tag: u8,
    value: &[u8],
    targets: impl IntoIterator<Item = &'a TargetSnapshot>,
) -> Vec<TargetId> {
    let base = replicated_wrh_base(
        organization_id,
        principal_affinity_id,
        route_id,
        source_tag,
        value,
    );
    let mut scored = targets
        .into_iter()
        .map(|target| {
            let score = (0..target.weight)
                .map(|replica| {
                    let mut digest = Sha256::new();
                    digest.update(b"owlrora/replicated-wrh-v1/replica");
                    digest.update([0]);
                    digest.update(base);
                    digest.update(target.affinity_identity);
                    digest.update(replica.to_be_bytes());
                    <[u8; 32]>::from(digest.finalize())
                })
                .max()
                .expect("target weights are nonzero runtime invariants");
            (target.id, target.affinity_identity, score)
        })
        .collect::<Vec<_>>();
    scored.sort_by(|left, right| right.2.cmp(&left.2).then_with(|| left.1.cmp(&right.1)));
    scored.into_iter().map(|(id, _, _)| id).collect()
}

fn route_ceiling_allows(ceiling: &JwtRouteCeiling, route_id: RouteId) -> bool {
    match ceiling {
        JwtRouteCeiling::None => false,
        JwtRouteCeiling::AllOrganizationGranted => true,
        JwtRouteCeiling::Routes { route_ids } => route_ids.contains(&route_id.to_string()),
    }
}

fn intersect_route_ceiling(
    ceiling: &JwtRouteCeiling,
    claimed: &BTreeSet<RouteId>,
) -> JwtRouteCeiling {
    match ceiling {
        JwtRouteCeiling::None => JwtRouteCeiling::None,
        JwtRouteCeiling::AllOrganizationGranted => JwtRouteCeiling::Routes {
            route_ids: claimed.iter().map(ToString::to_string).collect(),
        },
        JwtRouteCeiling::Routes { route_ids } => JwtRouteCeiling::Routes {
            route_ids: route_ids
                .iter()
                .filter(|id| id.parse::<RouteId>().is_ok_and(|id| claimed.contains(&id)))
                .cloned()
                .collect(),
        },
    }
}

fn claim_value<'a>(claims: &'a Value, path: &str) -> Option<&'a Value> {
    if path.starts_with('/') {
        claims.pointer(path)
    } else {
        claims.get(path)
    }
}

fn claim_string_set(
    claims: &Value,
    path: &str,
) -> Result<Option<BTreeSet<String>>, ApplicationError> {
    let Some(value) = claim_value(claims, path) else {
        return Ok(None);
    };
    let values = value
        .as_array()
        .ok_or(ApplicationError::InvalidCredential)?;
    if values.len() > 4096 {
        return Err(ApplicationError::InvalidCredential);
    }
    let mut result = BTreeSet::new();
    for value in values {
        let value = value
            .as_str()
            .filter(|value| !value.is_empty() && value.len() <= 512)
            .ok_or(ApplicationError::InvalidCredential)?;
        if !result.insert(value.to_owned()) {
            return Err(ApplicationError::InvalidCredential);
        }
    }
    Ok(Some(result))
}

fn error(
    family: IngressProtocolFamily,
    kind: ProtocolErrorKind,
    request_id: impl Into<String>,
    message: &'static str,
) -> ProtocolError {
    ProtocolError::new(family, kind, request_id, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        BudgetPolicyId, DeploymentId, LlmScope, TargetNarrowingConstraints, TargetTimeoutOverrides,
    };

    fn target(id: u128, affinity: [u8; 16], weight: u16) -> TargetSnapshot {
        TargetSnapshot {
            id: TargetId::from_uuid(Uuid::from_u128(id)),
            deployment_id: DeploymentId::from_uuid(Uuid::from_u128(id + 100)),
            affinity_identity: affinity,
            priority: 0,
            weight,
            narrowing_constraints: TargetNarrowingConstraints::default(),
            timeout_overrides: TargetTimeoutOverrides::default(),
        }
    }

    #[test]
    fn gateway_key_feature_capabilities_are_enforced() {
        let key_id = GatewayKeyId::new();
        let route_id = RouteId::new();
        let principal = GatewayPrincipal::GatewayKey {
            key_id,
            verifier: GatewayKeyVerifier {
                key_id,
                organization_id: OrganizationId::new(),
                scopes: Some(LlmScopeSet::new([LlmScope::Invoke]).unwrap()),
                capabilities: BTreeSet::from([LlmFeatureCapability::Streaming]),
                route_ids: BTreeSet::from([route_id]),
                budget_policy_id: BudgetPolicyId::new(),
                rate_policy_id: None,
                current_digest: [0; 32],
                overlap_digest: None,
                overlap_until: None,
                expires_at: None,
                active: true,
            },
        };
        assert!(principal.allows_capabilities(&BTreeSet::new()));
        assert!(principal.allows_capabilities(&BTreeSet::from([LlmFeatureCapability::Streaming])));
        assert!(
            !principal
                .allows_capabilities(&BTreeSet::from([LlmFeatureCapability::SystemInstructions]))
        );
    }

    #[test]
    fn wrh_v1_matches_authoritative_vector() {
        let organization = OrganizationId::from_uuid(Uuid::from_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]));
        let principal = Uuid::from_bytes([
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ]);
        let route = RouteId::from_uuid(Uuid::from_bytes([
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f,
        ]));
        let a = target(
            1,
            [
                0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
                0x3e, 0x3f,
            ],
            2,
        );
        let b = target(
            2,
            [
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
                0x4e, 0x4f,
            ],
            1,
        );
        assert_eq!(
            replicated_wrh_order(organization, principal, route, 0, b"session-a", [&a, &b]),
            vec![a.id, b.id]
        );
    }
}
