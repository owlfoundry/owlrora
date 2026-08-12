use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr as _,
    sync::Arc,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{AlgorithmParameters, JwkSet},
};
use serde_json::{Value, json};
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::{
    adapters::postgres::{AuditRecord, RuntimeEvent},
    domain::{
        Actor, AuthenticatedPrincipal, AuthenticationMethod, Capability, CapabilityClaimPolicy,
        ClaimMapping, IssuerId, IssuerStatus, JwksSource, ManagementOrganizationCeiling,
        ManagementScope, ManagementScopeSet, Principal, ResourceScope,
    },
    runtime::{ExternalIssuerSnapshot, RuntimeGeneration},
};

use super::identity_egress::read_bounded_response;
use super::{
    Application, ApplicationError, AuthorizationTarget, CreateExternalIdentityIssuer, EntityTag,
    ExternalIdentityIssuer, IdempotencyDecision, IdempotentCommand, Page, RequestIdentity,
};

const MAX_UNQUALIFIED_JWT_BYTES: usize = 65_536;
const MAX_JWKS_BYTES: usize = 1_048_576;

impl Application {
    pub async fn list_external_identity_issuers(
        &self,
        identity: &RequestIdentity,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<ExternalIdentityIssuer>, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read],
            AuthorizationTarget::System {
                capability: Capability::ManageIdentity,
            },
        )?;
        let family = "identity_issuers";
        let (cursor, limit) = super::resources::page_parameters(family, cursor, limit)?;
        let rows = sqlx::query(&format!(
            "{ISSUER_SELECT} WHERE ($1::uuid IS NULL OR i.id < $1)
             ORDER BY i.id DESC LIMIT $2"
        ))
        .bind(cursor)
        .bind(i64::from(limit) + 1)
        .fetch_all(self.store.pool())
        .await?;
        super::resources::page_from_rows(rows, limit, family, |row| issuer_from_row(&row))
    }

    pub async fn get_external_identity_issuer(
        &self,
        identity: &RequestIdentity,
        issuer_id: IssuerId,
    ) -> Result<(ExternalIdentityIssuer, EntityTag), ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read],
            AuthorizationTarget::System {
                capability: Capability::ManageIdentity,
            },
        )?;
        load_issuer(self.store.pool(), issuer_id).await
    }

    pub async fn create_external_identity_issuer(
        &self,
        identity: &RequestIdentity,
        input: CreateExternalIdentityIssuer,
        idempotency_key: Option<&str>,
    ) -> Result<IdempotentCommand<(ExternalIdentityIssuer, EntityTag)>, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Write, ManagementScope::Authority],
            AuthorizationTarget::System {
                capability: Capability::ManageIdentity,
            },
        )?;
        validate_issuer_input(&input)?;
        if let Some(replay) = self
            .replay_completed_idempotent_command(
                identity,
                &ResourceScope::Deployment,
                "system.identity_issuers.create",
                idempotency_key,
                &input,
            )
            .await?
        {
            return Ok(IdempotentCommand::Replay(replay));
        }
        if let Some(profile) = &input.browser_login {
            self.validate_identity_endpoint_resolution(&profile.authorization_endpoint)
                .await?;
            self.validate_identity_endpoint_resolution(&profile.token_endpoint)
                .await?;
        }
        let jwks = self
            .fetch_and_validate_jwks(&input.jwks_source, &input)
            .await?;
        let issuer_id = IssuerId::new();
        let etag_token = Uuid::now_v7();
        let material_id = Uuid::now_v7();
        let accepted_until = Utc::now()
            + chrono::Duration::seconds(i64::from(
                input.key_cache_policy.material_acceptance_seconds,
            ));
        let mut transaction = self.store.begin().await?;
        let handle = match self
            .begin_idempotent_command(
                &mut transaction,
                identity,
                &ResourceScope::Deployment,
                "system.identity_issuers.create",
                idempotency_key,
                &input,
            )
            .await?
        {
            IdempotencyDecision::Execute(handle) => handle,
            IdempotencyDecision::Replay(replay) => {
                return Ok(IdempotentCommand::Replay(replay));
            }
        };
        sqlx::query(
            "INSERT INTO external_identity_issuers(
                id, name, display_name, issuer, status, jwks_source,
                current_verifier_material_version_id, allowed_algorithms,
                accepted_audiences, subject_claim, claim_mapping, jwt_capability_ceiling,
                management_scope_ceiling, management_organization_ceiling,
                capability_claim_policy, jwt_route_ceiling, organization_selector,
                provisioning_policy_id, browser_login, clock_skew_seconds, key_cache_policy,
                created_by_principal, etag_token
             ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,
                $20,$21,$22,$23
             )",
        )
        .bind(issuer_id.as_uuid())
        .bind(&input.name)
        .bind(&input.display_name)
        .bind(&input.issuer)
        .bind(input.status.as_str())
        .bind(to_json(&input.jwks_source)?)
        .bind(material_id)
        .bind(to_json(&input.allowed_algorithms)?)
        .bind(to_json(&input.accepted_audiences)?)
        .bind(&input.subject_claim)
        .bind(to_json(&input.claim_mapping)?)
        .bind(to_json(&input.jwt_capability_ceiling)?)
        .bind(to_json(&input.management_scope_ceiling)?)
        .bind(to_json(&input.management_organization_ceiling)?)
        .bind(input.capability_claim_policy.as_str())
        .bind(to_json(&input.jwt_route_ceiling)?)
        .bind(to_json(&input.organization_selector)?)
        .bind(
            input
                .provisioning_policy_id
                .map(crate::domain::PolicyId::as_uuid),
        )
        .bind(input.browser_login.as_ref().map(to_json).transpose()?)
        .bind(
            i32::try_from(input.clock_skew_seconds).map_err(|_| {
                ApplicationError::Validation("clock skew is out of range".to_owned())
            })?,
        )
        .bind(to_json(&input.key_cache_policy)?)
        .bind(to_json(&identity.principal.principal)?)
        .bind(etag_token)
        .execute(&mut *transaction)
        .await?;
        insert_verifier_material(
            &mut transaction,
            issuer_id,
            material_id,
            1,
            &jwks,
            json!({"kind":"issuer_create"}),
            accepted_until,
        )
        .await?;
        let result = load_issuer(&mut *transaction, issuer_id).await?;
        self.complete_idempotent_command(
            &mut transaction,
            handle,
            200,
            &result.0,
            Some(result.1.as_str()),
        )
        .await?;
        self.store
            .commit_command(
                transaction,
                &identity_audit(
                    identity,
                    "external_identity_issuer",
                    issuer_id.to_string(),
                    "identity_issuers.create",
                    &["issuer", "policy", "verifier_material"],
                ),
                Some(&issuer_event(issuer_id, false)),
            )
            .await?;
        self.publish_committed_runtime(&identity.request_id, "identity_issuers.create")
            .await;
        Ok(IdempotentCommand::Executed(result))
    }

    pub async fn update_external_identity_issuer(
        &self,
        identity: &RequestIdentity,
        issuer_id: IssuerId,
        if_match: Option<&str>,
        input: super::UpdateExternalIdentityIssuer,
    ) -> Result<(ExternalIdentityIssuer, EntityTag), ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Write, ManagementScope::Authority],
            AuthorizationTarget::System {
                capability: Capability::ManageIdentity,
            },
        )?;
        let (current, current_etag) = load_issuer(self.store.pool(), issuer_id).await?;
        require_if_match(if_match, &current_etag)?;
        let refresh_material = !input.jwks_source.is_omitted()
            || !input.allowed_algorithms.is_omitted()
            || !input.key_cache_policy.is_omitted();
        let presentation_only = !input.display_name.is_omitted()
            && input.status.is_omitted()
            && input.jwks_source.is_omitted()
            && input.allowed_algorithms.is_omitted()
            && input.accepted_audiences.is_omitted()
            && input.subject_claim.is_omitted()
            && input.claim_mapping.is_omitted()
            && input.jwt_capability_ceiling.is_omitted()
            && input.management_scope_ceiling.is_omitted()
            && input.management_organization_ceiling.is_omitted()
            && input.capability_claim_policy.is_omitted()
            && input.jwt_route_ceiling.is_omitted()
            && input.organization_selector.is_omitted()
            && input.provisioning_policy_id.is_omitted()
            && input.browser_login.is_omitted()
            && input.clock_skew_seconds.is_omitted()
            && input.key_cache_policy.is_omitted();
        if input.display_name.is_omitted()
            && input.status.is_omitted()
            && input.jwks_source.is_omitted()
            && input.allowed_algorithms.is_omitted()
            && input.accepted_audiences.is_omitted()
            && input.subject_claim.is_omitted()
            && input.claim_mapping.is_omitted()
            && input.jwt_capability_ceiling.is_omitted()
            && input.management_scope_ceiling.is_omitted()
            && input.management_organization_ceiling.is_omitted()
            && input.capability_claim_policy.is_omitted()
            && input.jwt_route_ceiling.is_omitted()
            && input.organization_selector.is_omitted()
            && input.provisioning_policy_id.is_omitted()
            && input.browser_login.is_omitted()
            && input.clock_skew_seconds.is_omitted()
            && input.key_cache_policy.is_omitted()
        {
            return Err(ApplicationError::Validation(
                "at least one issuer field must be updated".to_owned(),
            ));
        }
        let mut candidate = CreateExternalIdentityIssuer {
            name: current.name.clone(),
            display_name: current.display_name.clone(),
            issuer: current.issuer.clone(),
            status: current.status,
            jwks_source: current.jwks_source.clone(),
            allowed_algorithms: current.allowed_algorithms.clone(),
            accepted_audiences: current.accepted_audiences.clone(),
            subject_claim: current.subject_claim.clone(),
            claim_mapping: current.claim_mapping.clone(),
            jwt_capability_ceiling: current.jwt_capability_ceiling.clone(),
            management_scope_ceiling: current.management_scope_ceiling.clone(),
            management_organization_ceiling: current.management_organization_ceiling.clone(),
            capability_claim_policy: current.capability_claim_policy,
            jwt_route_ceiling: current.jwt_route_ceiling.clone(),
            organization_selector: current.organization_selector.clone(),
            provisioning_policy_id: current.provisioning_policy_id,
            browser_login: current.browser_login.clone(),
            clock_skew_seconds: current.clock_skew_seconds,
            key_cache_policy: current.key_cache_policy.clone(),
        };
        apply_required(
            &mut candidate.display_name,
            input.display_name,
            "display_name",
        )?;
        apply_required(&mut candidate.status, input.status, "status")?;
        apply_required(&mut candidate.jwks_source, input.jwks_source, "jwks_source")?;
        apply_required(
            &mut candidate.allowed_algorithms,
            input.allowed_algorithms,
            "allowed_algorithms",
        )?;
        apply_required(
            &mut candidate.accepted_audiences,
            input.accepted_audiences,
            "accepted_audiences",
        )?;
        apply_required(
            &mut candidate.subject_claim,
            input.subject_claim,
            "subject_claim",
        )?;
        apply_required(
            &mut candidate.claim_mapping,
            input.claim_mapping,
            "claim_mapping",
        )?;
        apply_required(
            &mut candidate.jwt_capability_ceiling,
            input.jwt_capability_ceiling,
            "jwt_capability_ceiling",
        )?;
        apply_required(
            &mut candidate.management_scope_ceiling,
            input.management_scope_ceiling,
            "management_scope_ceiling",
        )?;
        apply_required(
            &mut candidate.management_organization_ceiling,
            input.management_organization_ceiling,
            "management_organization_ceiling",
        )?;
        apply_required(
            &mut candidate.capability_claim_policy,
            input.capability_claim_policy,
            "capability_claim_policy",
        )?;
        apply_required(
            &mut candidate.jwt_route_ceiling,
            input.jwt_route_ceiling,
            "jwt_route_ceiling",
        )?;
        apply_required(
            &mut candidate.organization_selector,
            input.organization_selector,
            "organization_selector",
        )?;
        apply_optional(
            &mut candidate.provisioning_policy_id,
            input.provisioning_policy_id,
        );
        apply_optional(&mut candidate.browser_login, input.browser_login);
        apply_required(
            &mut candidate.clock_skew_seconds,
            input.clock_skew_seconds,
            "clock_skew_seconds",
        )?;
        apply_required(
            &mut candidate.key_cache_policy,
            input.key_cache_policy,
            "key_cache_policy",
        )?;
        validate_issuer_input(&candidate)?;
        if let Some(profile) = &candidate.browser_login {
            self.validate_identity_endpoint_resolution(&profile.authorization_endpoint)
                .await?;
            self.validate_identity_endpoint_resolution(&profile.token_endpoint)
                .await?;
        }
        let browser_login_changed = candidate.browser_login != current.browser_login;
        if browser_login_changed {
            self.authorize(
                identity,
                &[
                    ManagementScope::Write,
                    ManagementScope::Authority,
                    ManagementScope::Secrets,
                ],
                AuthorizationTarget::System {
                    capability: Capability::ManageIdentity,
                },
            )?;
        }
        let replacement_jwks = if refresh_material {
            Some(
                self.fetch_and_validate_jwks(&candidate.jwks_source, &candidate)
                    .await?,
            )
        } else {
            None
        };

        let mut transaction = self.store.begin().await?;
        let locked = sqlx::query(
            "SELECT etag_token, policy_version FROM external_identity_issuers
             WHERE id=$1 FOR UPDATE",
        )
        .bind(issuer_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        let locked_etag = EntityTag::for_resource(
            "external_identity_issuer",
            issuer_id.as_uuid(),
            locked.try_get("etag_token")?,
        );
        require_if_match(if_match, &locked_etag)?;
        let new_etag_token = Uuid::now_v7();
        let material_id = replacement_jwks.as_ref().map(|_| Uuid::now_v7());
        if browser_login_changed {
            sqlx::query(
                "DELETE FROM protected_secret_versions
                 WHERE owner_kind='identity_issuer' AND owner_id=$1
                   AND field_purpose='oidc_client_secret'",
            )
            .bind(issuer_id.as_uuid())
            .execute(&mut *transaction)
            .await?;
        }
        if let (Some(jwks), Some(material_id)) = (&replacement_jwks, material_id) {
            let next_version = sqlx::query_scalar::<_, i64>(
                "SELECT COALESCE(max(version),0)+1 FROM issuer_verifier_material_versions
                 WHERE issuer_id=$1",
            )
            .bind(issuer_id.as_uuid())
            .fetch_one(&mut *transaction)
            .await?;
            insert_verifier_material(
                &mut transaction,
                issuer_id,
                material_id,
                next_version,
                jwks,
                json!({"kind":"issuer_policy_update"}),
                Utc::now()
                    + chrono::Duration::seconds(i64::from(
                        candidate.key_cache_policy.material_acceptance_seconds,
                    )),
            )
            .await?;
        }
        sqlx::query(
            "UPDATE external_identity_issuers SET
                display_name=$2, status=$3, jwks_source=$4,
                current_verifier_material_version_id=COALESCE($5,current_verifier_material_version_id),
                allowed_algorithms=$6, accepted_audiences=$7, subject_claim=$8,
                claim_mapping=$9, jwt_capability_ceiling=$10, management_scope_ceiling=$11,
                management_organization_ceiling=$12, capability_claim_policy=$13,
                jwt_route_ceiling=$14, organization_selector=$15, provisioning_policy_id=$16,
                browser_login=$17, clock_skew_seconds=$18, key_cache_policy=$19,
                policy_version=policy_version+1, etag_token=$20, updated_at=now()
             WHERE id=$1",
        )
        .bind(issuer_id.as_uuid())
        .bind(&candidate.display_name)
        .bind(candidate.status.as_str())
        .bind(to_json(&candidate.jwks_source)?)
        .bind(material_id)
        .bind(to_json(&candidate.allowed_algorithms)?)
        .bind(to_json(&candidate.accepted_audiences)?)
        .bind(&candidate.subject_claim)
        .bind(to_json(&candidate.claim_mapping)?)
        .bind(to_json(&candidate.jwt_capability_ceiling)?)
        .bind(to_json(&candidate.management_scope_ceiling)?)
        .bind(to_json(&candidate.management_organization_ceiling)?)
        .bind(candidate.capability_claim_policy.as_str())
        .bind(to_json(&candidate.jwt_route_ceiling)?)
        .bind(to_json(&candidate.organization_selector)?)
        .bind(
            candidate
                .provisioning_policy_id
                .map(crate::domain::PolicyId::as_uuid),
        )
        .bind(
            candidate
                .browser_login
                .as_ref()
                .map(to_json)
                .transpose()?,
        )
        .bind(i32::try_from(candidate.clock_skew_seconds).map_err(|_| ApplicationError::Internal)?)
        .bind(to_json(&candidate.key_cache_policy)?)
        .bind(new_etag_token)
        .execute(&mut *transaction)
        .await?;
        if !presentation_only {
            super::identity_resources::revoke_external_sessions(&mut transaction, issuer_id, None)
                .await?;
        }
        let result = load_issuer(&mut *transaction, issuer_id).await?;
        self.store
            .commit_command(
                transaction,
                &identity_audit(
                    identity,
                    "external_identity_issuer",
                    issuer_id.to_string(),
                    "identity_issuers.update",
                    if browser_login_changed {
                        &["policy", "browser_login.client_secret"]
                    } else {
                        &["policy"]
                    },
                ),
                Some(&issuer_event(issuer_id, !presentation_only)),
            )
            .await?;
        self.publish_committed_runtime(&identity.request_id, "identity_issuers.update")
            .await;
        Ok(result)
    }

    pub async fn refresh_external_identity_issuer_material(
        &self,
        identity: &RequestIdentity,
        issuer_id: IssuerId,
    ) -> Result<(), ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Write, ManagementScope::Authority],
            AuthorizationTarget::System {
                capability: Capability::ManageIdentity,
            },
        )?;
        self.refresh_issuer_material(issuer_id, Some(identity), "administrator")
            .await
    }

    pub fn authenticate_external_jwt(
        &self,
        raw_token: &str,
        request_id: String,
    ) -> Result<RequestIdentity, ApplicationError> {
        self.verify_external_jwt(raw_token, request_id)
            .map(|(identity, _claims)| identity)
    }

    pub(crate) fn verify_external_jwt(
        &self,
        raw_token: &str,
        request_id: String,
    ) -> Result<(RequestIdentity, Value), ApplicationError> {
        let generation = self.security_generation()?;
        self.verify_external_jwt_in_generation(raw_token, request_id, generation)
    }

    pub(crate) fn verify_external_jwt_in_generation(
        &self,
        raw_token: &str,
        request_id: String,
        generation: Arc<RuntimeGeneration>,
    ) -> Result<(RequestIdentity, Value), ApplicationError> {
        let (issuer_id, subject, claims) =
            self.verify_external_jwt_evidence(raw_token, &generation)?;
        let issuer = generation
            .snapshot
            .identity
            .external_issuers_by_id
            .get(&issuer_id)
            .ok_or(ApplicationError::InvalidCredential)?;
        let user_id = generation
            .snapshot
            .identity
            .external_bindings
            .get(&(issuer_id, subject.clone()))
            .copied()
            .ok_or(ApplicationError::InvalidCredential)?;
        if !generation
            .snapshot
            .identity
            .active_users
            .get(&user_id)
            .copied()
            .unwrap_or(false)
        {
            return Err(ApplicationError::CredentialInactive);
        }
        let (scopes, capabilities, organizations) = derive_management_ceiling(issuer, &claims)?;
        if !issuer.jwt_capability_ceiling.contains("management:access")
            || scopes.iter().next().is_none()
        {
            return Err(ApplicationError::Forbidden);
        }
        let (effective_system_administrator, effective_organization_capabilities) = self
            .external_local_authority(
                &generation,
                user_id,
                &capabilities,
                organizations.as_deref(),
            );
        Ok((
            RequestIdentity {
                principal: AuthenticatedPrincipal {
                    principal: Principal::LocalUser { user_id },
                    authentication_method: AuthenticationMethod::ExternalJwt,
                    effective_management_scopes: scopes,
                    credential_capability_ceiling: capabilities,
                    effective_system_administrator,
                    effective_organization_capabilities,
                    resource_scope: ResourceScope::Deployment,
                    session_id: None,
                    accepted_key_version_id: None,
                    external_issuer_id: Some(issuer.id),
                    external_subject: Some(subject),
                    management_organization_ceiling: organizations,
                },
                generation,
                request_id,
                csrf_validated: true,
            },
            claims,
        ))
    }

    pub(crate) fn validate_external_management_evidence(
        &self,
        issuer: &ExternalIssuerSnapshot,
        claims: &Value,
    ) -> Result<(), ApplicationError> {
        let (scopes, _, _) = derive_management_ceiling(issuer, claims)?;
        if !issuer.jwt_capability_ceiling.contains("management:access")
            || scopes.iter().next().is_none()
        {
            return Err(ApplicationError::Forbidden);
        }
        Ok(())
    }

    pub(crate) fn verify_external_jwt_evidence(
        &self,
        raw_token: &str,
        generation: &RuntimeGeneration,
    ) -> Result<(IssuerId, String, Value), ApplicationError> {
        if raw_token.len() > MAX_UNQUALIFIED_JWT_BYTES {
            return Err(ApplicationError::InvalidCredential);
        }
        let unverified = unverified_claims(raw_token)?;
        let issuer_value = unverified
            .get("iss")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(ApplicationError::InvalidCredential)?;
        let issuer = generation
            .snapshot
            .identity
            .external_issuers_by_issuer
            .get(issuer_value)
            .filter(|issuer| issuer.active)
            .ok_or(ApplicationError::InvalidCredential)?;
        if raw_token.len()
            > usize::try_from(issuer.key_cache_policy.max_token_bytes)
                .unwrap_or(MAX_UNQUALIFIED_JWT_BYTES)
        {
            return Err(ApplicationError::InvalidCredential);
        }
        let header = decode_header(raw_token).map_err(|_| ApplicationError::InvalidCredential)?;
        if !issuer.allowed_algorithms.contains(&header.alg) {
            return Err(ApplicationError::InvalidCredential);
        }
        let kid = header
            .kid
            .as_deref()
            .filter(|kid| !kid.is_empty() && kid.len() <= 256)
            .ok_or(ApplicationError::InvalidCredential)?;
        let Some(material) = issuer.verifier_material.as_ref().filter(|material| {
            matches!(issuer.jwks_source, JwksSource::Static { .. })
                || material.accepted_until > Utc::now()
        }) else {
            self.schedule_issuer_refresh(issuer.id, "material_unavailable");
            return Err(ApplicationError::InvalidCredential);
        };
        let Some(jwk) = material.jwks.find(kid) else {
            self.schedule_issuer_refresh(issuer.id, "unknown_kid");
            return Err(ApplicationError::InvalidCredential);
        };
        let key = DecodingKey::from_jwk(jwk).map_err(|_| ApplicationError::InvalidCredential)?;
        let mut validation = Validation::new(header.alg);
        validation.algorithms = issuer.allowed_algorithms.clone();
        validation.leeway = u64::from(issuer.clock_skew_seconds);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.validate_aud = true;
        validation.required_spec_claims = ["exp", "iss", "aud"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        validation.set_issuer(&[issuer.issuer.as_str()]);
        validation.set_audience(
            &issuer
                .accepted_audiences
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        let claims = decode::<Value>(raw_token, &key, &validation)
            .map_err(|_| ApplicationError::InvalidCredential)?
            .claims;
        let subject = claim_string(&claims, &issuer.subject_claim)?;
        if subject.len() > 512 {
            return Err(ApplicationError::InvalidCredential);
        }
        Ok((issuer.id, subject, claims))
    }

    pub fn start_identity_refresh_controller(self: &Arc<Self>) {
        let application = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut ticks = 0_u32;
            loop {
                interval.tick().await;
                let Some(application) = application.upgrade() else {
                    break;
                };
                application.schedule_due_issuer_refreshes();
                ticks = ticks.wrapping_add(1);
                if ticks.is_multiple_of(20) {
                    if let Err(error) = application.cleanup_expired_oidc_login_states().await {
                        tracing::warn!(error = %error, "expired OIDC login-state cleanup failed");
                    }
                    if let Err(error) = application.cleanup_expired_idempotency_records().await {
                        tracing::warn!(error = %error, "expired idempotency-record cleanup failed");
                    }
                }
            }
        });
    }

    fn schedule_due_issuer_refreshes(&self) {
        let now = Utc::now();
        for issuer in self
            .runtime
            .capture()
            .snapshot
            .identity
            .external_issuers_by_id
            .values()
        {
            if !issuer.active || !matches!(issuer.jwks_source, JwksSource::Https { .. }) {
                continue;
            }
            let refresh_interval = chrono::Duration::seconds(i64::from(
                issuer.key_cache_policy.refresh_interval_seconds,
            ));
            let due = issuer
                .verifier_material
                .as_ref()
                .is_none_or(|material| material.fetched_at + refresh_interval <= now);
            if due {
                self.schedule_issuer_refresh(issuer.id, "periodic");
            }
        }
    }

    fn schedule_issuer_refresh(&self, issuer_id: IssuerId, reason: &'static str) {
        let generation = self.runtime.capture();
        let Some(issuer) = generation
            .snapshot
            .identity
            .external_issuers_by_id
            .get(&issuer_id)
        else {
            return;
        };
        if !matches!(issuer.jwks_source, JwksSource::Https { .. }) {
            return;
        }
        let Ok(permit) = Arc::clone(&self.issuer_refresh_permits).try_acquire_owned() else {
            return;
        };
        let now = std::time::Instant::now();
        let gate_seconds = if reason == "periodic" {
            issuer.key_cache_policy.refresh_interval_seconds
        } else {
            issuer.key_cache_policy.refresh_interval_seconds.min(300)
        }
        .max(30);
        let Ok(mut schedule) = self.issuer_refresh_schedule.lock() else {
            tracing::error!("issuer refresh schedule lock was poisoned");
            return;
        };
        if schedule.in_flight.contains(&issuer_id)
            || schedule
                .next_allowed
                .get(&issuer_id)
                .is_some_and(|next_allowed| *next_allowed > now)
        {
            return;
        }
        schedule.in_flight.insert(issuer_id);
        schedule.next_allowed.insert(
            issuer_id,
            now + std::time::Duration::from_secs(u64::from(gate_seconds)),
        );
        drop(schedule);

        let application = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = application
                .refresh_issuer_material(issuer_id, None, reason)
                .await
            {
                tracing::warn!(issuer_id = %issuer_id, reason, error = %error, "issuer material refresh failed");
            }
            if let Ok(mut schedule) = application.issuer_refresh_schedule.lock() {
                schedule.in_flight.remove(&issuer_id);
            }
        });
    }

    async fn refresh_issuer_material(
        &self,
        issuer_id: IssuerId,
        actor: Option<&RequestIdentity>,
        reason: &str,
    ) -> Result<(), ApplicationError> {
        let lease_fencing_token = if actor.is_none() {
            let Some(fencing_token) = self.acquire_refresh_lease(issuer_id).await? else {
                return Ok(());
            };
            Some(fencing_token)
        } else {
            None
        };
        let snapshot = self
            .runtime
            .capture()
            .snapshot
            .identity
            .external_issuers_by_id
            .get(&issuer_id)
            .cloned()
            .ok_or(ApplicationError::NotFound)?;
        let input = issuer_snapshot_as_validation_input(&snapshot)?;
        let jwks = self
            .fetch_and_validate_jwks(&snapshot.jwks_source, &input)
            .await?;
        let now = Utc::now();
        let fetched_jwks = canonical_jwks(&jwks)?;
        let refresh_interval = chrono::Duration::seconds(i64::from(
            snapshot.key_cache_policy.refresh_interval_seconds,
        ));
        if snapshot.verifier_material.as_ref().is_some_and(|material| {
            canonical_jwks(&material.jwks).ok().as_ref() == Some(&fetched_jwks)
                && material.accepted_until > now + refresh_interval * 2
        }) {
            return Ok(());
        }
        let starting_material_id = snapshot
            .verifier_material
            .as_ref()
            .map(|material| material.id);
        let mut transaction = self.store.begin().await?;
        if let Some(fencing_token) = lease_fencing_token {
            let lease = sqlx::query(
                "SELECT fencing_token, lease_expires_at > now() AS valid
                 FROM worker_leases
                 WHERE worker_kind='jwks_refresh' AND item_id=$1
                 FOR UPDATE",
            )
            .bind(issuer_id.to_string())
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or_else(|| ApplicationError::Conflict("JWKS refresh lease was lost".to_owned()))?;
            if lease.try_get::<i64, _>("fencing_token")? != fencing_token
                || !lease.try_get::<bool, _>("valid")?
            {
                return Err(ApplicationError::Conflict(
                    "JWKS refresh lease was lost".to_owned(),
                ));
            }
        }
        let row = sqlx::query(
            "SELECT policy_version, current_verifier_material_version_id
             FROM external_identity_issuers
             WHERE id=$1 FOR UPDATE",
        )
        .bind(issuer_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        if row.try_get::<i64, _>("policy_version")? != snapshot.policy_version
            || row.try_get::<Option<Uuid>, _>("current_verifier_material_version_id")?
                != starting_material_id
        {
            return Err(ApplicationError::Conflict(
                "issuer policy or verifier material changed during refresh".to_owned(),
            ));
        }
        let next_version = sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(max(version),0)+1 FROM issuer_verifier_material_versions
             WHERE issuer_id=$1",
        )
        .bind(issuer_id.as_uuid())
        .fetch_one(&mut *transaction)
        .await?;
        let material_id = Uuid::now_v7();
        let accepted_until = Utc::now()
            + chrono::Duration::seconds(i64::from(
                snapshot.key_cache_policy.material_acceptance_seconds,
            ));
        insert_verifier_material(
            &mut transaction,
            issuer_id,
            material_id,
            next_version,
            &jwks,
            json!({"kind":"refresh", "reason":reason}),
            accepted_until,
        )
        .await?;
        sqlx::query(
            "UPDATE external_identity_issuers
             SET current_verifier_material_version_id=$2, updated_at=now()
             WHERE id=$1",
        )
        .bind(issuer_id.as_uuid())
        .bind(material_id)
        .execute(&mut *transaction)
        .await?;
        let audit = AuditRecord {
            actor: actor.map(|identity| Actor::from(&identity.principal)),
            authentication_evidence: actor.map_or_else(
                || json!({"method":"worker"}),
                |identity| json!({"method":identity.principal.authentication_method}),
            ),
            organization_id: None,
            target_resource_kind: "issuer_verifier_material".to_owned(),
            target_resource_id: Some(material_id.to_string()),
            operation_id: "identity_issuers.verifier_material.refresh".to_owned(),
            outcome: "accepted",
            request_id: actor.map_or_else(
                || format!("worker-{}", Uuid::now_v7()),
                |identity| identity.request_id.clone(),
            ),
            changed_fields: vec!["current_verifier_material_version_id".to_owned()],
            safe_details: json!({"issuer_id":issuer_id, "reason":reason, "key_count":jwks.keys.len()}),
        };
        self.store
            .commit_command(transaction, &audit, Some(&issuer_event(issuer_id, true)))
            .await?;
        self.publish_committed_runtime(
            &audit.request_id,
            "identity_issuers.verifier_material.refresh",
        )
        .await;
        Ok(())
    }

    async fn acquire_refresh_lease(
        &self,
        issuer_id: IssuerId,
    ) -> Result<Option<i64>, ApplicationError> {
        let fencing_token = sqlx::query_scalar::<_, i64>(
            "INSERT INTO worker_leases(
                worker_kind, item_id, fencing_token, owner, lease_expires_at
             ) VALUES ('jwks_refresh',$1,1,$2,now()+interval '30 seconds')
             ON CONFLICT(worker_kind,item_id) DO UPDATE SET
                fencing_token=worker_leases.fencing_token+1,
                owner=EXCLUDED.owner,
                lease_expires_at=EXCLUDED.lease_expires_at,
                attempt=worker_leases.attempt+1
             WHERE worker_leases.lease_expires_at <= now()
             RETURNING fencing_token",
        )
        .bind(issuer_id.to_string())
        .bind(format!("node-{}", std::process::id()))
        .fetch_optional(self.store.pool())
        .await?;
        Ok(fencing_token)
    }

    async fn fetch_and_validate_jwks(
        &self,
        source: &JwksSource,
        input: &CreateExternalIdentityIssuer,
    ) -> Result<JwkSet, ApplicationError> {
        let jwks = match source {
            JwksSource::Static { jwks } => serde_json::from_value::<JwkSet>(jwks.clone())
                .map_err(|_| ApplicationError::Validation("invalid static JWKS".to_owned()))?,
            JwksSource::Https { uri } => {
                if uri.scheme() != "https" {
                    return Err(ApplicationError::Validation(
                        "remote JWKS URI must use HTTPS".to_owned(),
                    ));
                }
                let client = self.identity_http_client(uri).await?;
                let response = client
                    .get(uri.clone())
                    .header(reqwest::header::ACCEPT, "application/json")
                    .send()
                    .await
                    .map_err(|_| ApplicationError::DependencyUnavailable)?;
                if !response.status().is_success() {
                    return Err(ApplicationError::DependencyUnavailable);
                }
                let bytes = read_bounded_response(response, MAX_JWKS_BYTES).await?;
                serde_json::from_slice::<JwkSet>(&bytes)
                    .map_err(|_| ApplicationError::DependencyUnavailable)?
            }
        };
        validate_jwks(
            &jwks,
            &input.allowed_algorithms,
            input.key_cache_policy.max_keys,
        )?;
        Ok(jwks)
    }
}

const ISSUER_SELECT: &str =
    "SELECT i.id, i.name, i.display_name, i.issuer, i.status, i.jwks_source,
            i.current_verifier_material_version_id, i.allowed_algorithms,
            i.accepted_audiences, i.subject_claim, i.claim_mapping,
            i.jwt_capability_ceiling, i.management_scope_ceiling,
            i.management_organization_ceiling, i.capability_claim_policy,
            i.jwt_route_ceiling, i.organization_selector, i.provisioning_policy_id,
            i.browser_login, i.clock_skew_seconds, i.key_cache_policy, i.policy_version,
            i.etag_token, i.created_at, i.updated_at
     FROM external_identity_issuers i";

async fn load_issuer<'e, E>(
    executor: E,
    issuer_id: IssuerId,
) -> Result<(ExternalIdentityIssuer, EntityTag), ApplicationError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(&format!("{ISSUER_SELECT} WHERE i.id=$1"))
        .bind(issuer_id.as_uuid())
        .fetch_optional(executor)
        .await?
        .ok_or(ApplicationError::NotFound)?;
    let etag = EntityTag::for_resource(
        "external_identity_issuer",
        issuer_id.as_uuid(),
        row.try_get("etag_token")?,
    );
    Ok((issuer_from_row(&row)?, etag))
}

fn issuer_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<ExternalIdentityIssuer, ApplicationError> {
    let status = match row.try_get::<String, _>("status")?.as_str() {
        "active" => IssuerStatus::Active,
        "disabled" => IssuerStatus::Disabled,
        _ => return Err(ApplicationError::Internal),
    };
    Ok(ExternalIdentityIssuer {
        id: IssuerId::from_uuid(row.try_get("id")?),
        name: row.try_get("name")?,
        display_name: row.try_get("display_name")?,
        issuer: row.try_get("issuer")?,
        status,
        jwks_source: from_json(row.try_get("jwks_source")?)?,
        current_verifier_material_version_id: row
            .try_get::<Option<Uuid>, _>("current_verifier_material_version_id")?
            .map(crate::domain::MaterialVersionId::from_uuid),
        allowed_algorithms: from_json(row.try_get("allowed_algorithms")?)?,
        accepted_audiences: from_json(row.try_get("accepted_audiences")?)?,
        subject_claim: row.try_get("subject_claim")?,
        claim_mapping: from_json(row.try_get("claim_mapping")?)?,
        jwt_capability_ceiling: from_json(row.try_get("jwt_capability_ceiling")?)?,
        management_scope_ceiling: from_json(row.try_get("management_scope_ceiling")?)?,
        management_organization_ceiling: from_json(
            row.try_get("management_organization_ceiling")?,
        )?,
        capability_claim_policy: serde_json::from_value(Value::String(
            row.try_get("capability_claim_policy")?,
        ))
        .map_err(|_| ApplicationError::Internal)?,
        jwt_route_ceiling: from_json(row.try_get("jwt_route_ceiling")?)?,
        organization_selector: from_json(row.try_get("organization_selector")?)?,
        provisioning_policy_id: row
            .try_get::<Option<Uuid>, _>("provisioning_policy_id")?
            .map(crate::domain::PolicyId::from_uuid),
        browser_login: row
            .try_get::<Option<Value>, _>("browser_login")?
            .map(from_json)
            .transpose()?,
        clock_skew_seconds: u32::try_from(row.try_get::<i32, _>("clock_skew_seconds")?)
            .map_err(|_| ApplicationError::Internal)?,
        key_cache_policy: from_json(row.try_get("key_cache_policy")?)?,
        policy_version: row.try_get("policy_version")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn validate_issuer_input(input: &CreateExternalIdentityIssuer) -> Result<(), ApplicationError> {
    if input.name.is_empty()
        || input.name.len() > 63
        || !input.name.bytes().enumerate().all(|(index, value)| {
            value.is_ascii_lowercase()
                || value.is_ascii_digit()
                || (index > 0 && matches!(value, b'_' | b'-'))
        })
    {
        return Err(ApplicationError::Validation(
            "issuer name must match [a-z][a-z0-9_-]{0,62}".to_owned(),
        ));
    }
    if input.display_name.trim().is_empty() || input.display_name.len() > 160 {
        return Err(ApplicationError::Validation(
            "display_name must contain 1 to 160 characters".to_owned(),
        ));
    }
    let issuer_url = url::Url::parse(&input.issuer)
        .map_err(|_| ApplicationError::Validation("issuer must be a valid URL".to_owned()))?;
    if issuer_url.scheme() != "https" || issuer_url.fragment().is_some() {
        return Err(ApplicationError::Validation(
            "issuer must be an HTTPS URL without a fragment".to_owned(),
        ));
    }
    parse_allowed_algorithms(&input.allowed_algorithms)?;
    if input.accepted_audiences.is_empty()
        || input
            .accepted_audiences
            .iter()
            .any(|audience| audience.is_empty() || audience.len() > 512)
    {
        return Err(ApplicationError::Validation(
            "at least one bounded audience is required".to_owned(),
        ));
    }
    validate_claim_name(&input.subject_claim)?;
    validate_claim_mapping(&input.claim_mapping)?;
    if input.clock_skew_seconds > 300 {
        return Err(ApplicationError::Validation(
            "clock_skew_seconds must not exceed 300".to_owned(),
        ));
    }
    if !(60..=86_400).contains(&input.key_cache_policy.refresh_interval_seconds)
        || !(300..=604_800).contains(&input.key_cache_policy.material_acceptance_seconds)
        || !(1..=128).contains(&input.key_cache_policy.max_keys)
        || !(1024..=65_536).contains(&input.key_cache_policy.max_token_bytes)
    {
        return Err(ApplicationError::Validation(
            "key_cache_policy is outside supported bounds".to_owned(),
        ));
    }
    let management_enabled = input.jwt_capability_ceiling.contains("management:access");
    if management_enabled
        && (input.management_scope_ceiling.iter().next().is_none()
            || matches!(
                input.management_organization_ceiling,
                ManagementOrganizationCeiling::None
            ))
    {
        return Err(ApplicationError::Validation(
            "management access requires explicit scope and organization ceilings".to_owned(),
        ));
    }
    if !management_enabled && input.management_scope_ceiling.iter().next().is_some() {
        return Err(ApplicationError::Validation(
            "management scopes require management:access".to_owned(),
        ));
    }
    if let ManagementOrganizationCeiling::Organizations { organization_ids } =
        &input.management_organization_ceiling
        && organization_ids.is_empty()
    {
        return Err(ApplicationError::Validation(
            "organization ceiling cannot contain an empty exact set".to_owned(),
        ));
    }
    if input.capability_claim_policy == CapabilityClaimPolicy::RequiredNarrowing
        && input.claim_mapping.management_scopes_claim.is_none()
        && input.claim_mapping.management_capabilities_claim.is_none()
        && input.claim_mapping.organizations_claim.is_none()
    {
        return Err(ApplicationError::Validation(
            "required claim narrowing needs at least one typed claim mapping".to_owned(),
        ));
    }
    if let Some(profile) = &input.browser_login {
        if !management_enabled
            || profile.authorization_endpoint.scheme() != "https"
            || profile.token_endpoint.scheme() != "https"
            || profile.client_id.is_empty()
            || profile.client_id.len() > 512
            || !profile.scopes.contains("openid")
            || profile.scopes.len() > 32
            || !input.accepted_audiences.contains(&profile.client_id)
        {
            return Err(ApplicationError::Validation(
                "browser login profile is invalid".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_claim_mapping(mapping: &ClaimMapping) -> Result<(), ApplicationError> {
    for claim in [
        mapping.management_scopes_claim.as_deref(),
        mapping.management_capabilities_claim.as_deref(),
        mapping.organizations_claim.as_deref(),
        mapping.display_name_claim.as_deref(),
        mapping.email_claim.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_claim_name(claim)?;
    }
    Ok(())
}

fn validate_claim_name(value: &str) -> Result<(), ApplicationError> {
    let valid = if value.starts_with('/') {
        value.split('/').skip(1).all(|segment| {
            !segment.is_empty()
                && segment.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b'_' | b'-' | b'.')
                        || byte == b'~'
                })
                && !segment
                    .as_bytes()
                    .windows(2)
                    .any(|pair| pair[0] == b'~' && !matches!(pair[1], b'0' | b'1'))
                && !segment.ends_with('~')
        })
    } else {
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    };
    if value.is_empty() || value.len() > 128 || !valid {
        return Err(ApplicationError::Validation(
            "claim names must be a top-level literal or an RFC 6901 JSON Pointer".to_owned(),
        ));
    }
    Ok(())
}

fn parse_allowed_algorithms(values: &[String]) -> Result<Vec<Algorithm>, ApplicationError> {
    if values.is_empty() {
        return Err(ApplicationError::Validation(
            "allowed_algorithms cannot be empty".to_owned(),
        ));
    }
    let mut algorithms = Vec::with_capacity(values.len());
    for value in values {
        let algorithm = Algorithm::from_str(value).map_err(|_| {
            ApplicationError::Validation(format!("unsupported JWT algorithm: {value}"))
        })?;
        if matches!(
            algorithm,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        ) {
            return Err(ApplicationError::Validation(
                "symmetric JWT algorithms are forbidden".to_owned(),
            ));
        }
        if algorithms.contains(&algorithm) {
            return Err(ApplicationError::Validation(
                "allowed_algorithms contains duplicates".to_owned(),
            ));
        }
        algorithms.push(algorithm);
    }
    Ok(algorithms)
}

fn canonical_jwks(jwks: &JwkSet) -> Result<BTreeMap<String, Value>, ApplicationError> {
    jwks.keys
        .iter()
        .map(|key| {
            let kid = key
                .common
                .key_id
                .clone()
                .ok_or(ApplicationError::Internal)?;
            let value = serde_json::to_value(key).map_err(|_| ApplicationError::Internal)?;
            Ok((kid, value))
        })
        .collect()
}

fn validate_jwks(
    jwks: &JwkSet,
    allowed_algorithms: &[String],
    max_keys: u16,
) -> Result<(), ApplicationError> {
    if jwks.keys.is_empty() || jwks.keys.len() > usize::from(max_keys) {
        return Err(ApplicationError::Validation(
            "JWKS key count is outside the configured bound".to_owned(),
        ));
    }
    let allowed = parse_allowed_algorithms(allowed_algorithms)?;
    let mut kids = BTreeSet::new();
    for jwk in &jwks.keys {
        if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
            return Err(ApplicationError::Validation(
                "symmetric JWK values are forbidden".to_owned(),
            ));
        }
        let kid = jwk
            .common
            .key_id
            .as_deref()
            .filter(|kid| !kid.is_empty() && kid.len() <= 256)
            .ok_or_else(|| {
                ApplicationError::Validation("every JWK requires a bounded kid".to_owned())
            })?;
        if !kids.insert(kid) {
            return Err(ApplicationError::Validation(
                "JWK kid values must be unique".to_owned(),
            ));
        }
        DecodingKey::from_jwk(jwk)
            .map_err(|_| ApplicationError::Validation("unsupported public JWK".to_owned()))?;
        if let Some(key_algorithm) = &jwk.common.key_algorithm {
            let key_algorithm_name = serde_json::to_value(key_algorithm)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or_else(|| {
                    ApplicationError::Validation("unsupported JWK algorithm".to_owned())
                })?;
            let key_algorithm = Algorithm::from_str(&key_algorithm_name).map_err(|_| {
                ApplicationError::Validation("unsupported JWK algorithm".to_owned())
            })?;
            if !allowed.contains(&key_algorithm) {
                return Err(ApplicationError::Validation(
                    "JWK algorithm is outside the issuer allowlist".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn unverified_claims(token: &str) -> Result<Value, ApplicationError> {
    let mut parts = token.split('.');
    let _header = parts.next().ok_or(ApplicationError::InvalidCredential)?;
    let payload = parts.next().ok_or(ApplicationError::InvalidCredential)?;
    let _signature = parts.next().ok_or(ApplicationError::InvalidCredential)?;
    if parts.next().is_some() || payload.contains('=') {
        return Err(ApplicationError::InvalidCredential);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| ApplicationError::InvalidCredential)?;
    serde_json::from_slice(&bytes).map_err(|_| ApplicationError::InvalidCredential)
}

fn claim_value<'a>(claims: &'a Value, path: &str) -> Option<&'a Value> {
    if path.starts_with('/') {
        claims.pointer(path)
    } else {
        claims.get(path)
    }
}

fn claim_string(claims: &Value, path: &str) -> Result<String, ApplicationError> {
    claim_value(claims, path)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(ApplicationError::InvalidCredential)
}

fn claim_string_set(
    claims: &Value,
    path: &str,
) -> Result<Option<BTreeSet<String>>, ApplicationError> {
    let Some(value) = claim_value(claims, path) else {
        return Ok(None);
    };
    let array = value
        .as_array()
        .ok_or(ApplicationError::InvalidCredential)?;
    let mut values = BTreeSet::new();
    for value in array {
        let value = value
            .as_str()
            .filter(|value| !value.is_empty() && value.len() <= 512)
            .ok_or(ApplicationError::InvalidCredential)?;
        if !values.insert(value.to_owned()) {
            return Err(ApplicationError::InvalidCredential);
        }
    }
    Ok(Some(values))
}

fn derive_management_ceiling(
    issuer: &ExternalIssuerSnapshot,
    claims: &Value,
) -> Result<
    (
        ManagementScopeSet,
        BTreeSet<Capability>,
        Option<Vec<crate::domain::OrganizationId>>,
    ),
    ApplicationError,
> {
    let mut scopes = issuer.management_scopes.clone();
    let mut capabilities = issuer.management_capabilities.clone();
    let mut organizations = issuer.management_organization_ceiling.clone();
    if issuer.capability_claim_policy != CapabilityClaimPolicy::Ignore {
        if let Some(path) = &issuer.claim_mapping.management_scopes_claim {
            match claim_string_set(claims, path)? {
                Some(values) => {
                    let parsed = values
                        .iter()
                        .map(|value| value.parse::<ManagementScope>())
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| ApplicationError::InvalidCredential)?;
                    let claimed = if parsed.is_empty() {
                        ManagementScopeSet::empty()
                    } else {
                        ManagementScopeSet::new(parsed)
                            .map_err(|_| ApplicationError::InvalidCredential)?
                    };
                    scopes = scopes.intersection(&claimed);
                }
                None if issuer.capability_claim_policy
                    == CapabilityClaimPolicy::RequiredNarrowing =>
                {
                    return Err(ApplicationError::InvalidCredential);
                }
                None => {}
            }
        }
        if let Some(path) = &issuer.claim_mapping.management_capabilities_claim {
            match claim_string_set(claims, path)? {
                Some(values) => {
                    let claimed = values
                        .iter()
                        .map(|value| value.parse::<Capability>())
                        .collect::<Result<BTreeSet<_>, _>>()
                        .map_err(|_| ApplicationError::InvalidCredential)?;
                    capabilities = capabilities.intersection(&claimed).copied().collect();
                }
                None if issuer.capability_claim_policy
                    == CapabilityClaimPolicy::RequiredNarrowing =>
                {
                    return Err(ApplicationError::InvalidCredential);
                }
                None => {}
            }
        }
        if let Some(path) = &issuer.claim_mapping.organizations_claim {
            match claim_string_set(claims, path)? {
                Some(values) => {
                    let claimed = values
                        .iter()
                        .map(|value| value.parse::<crate::domain::OrganizationId>())
                        .collect::<Result<BTreeSet<_>, _>>()
                        .map_err(|_| ApplicationError::InvalidCredential)?;
                    organizations = match organizations {
                        ManagementOrganizationCeiling::AllAuthorized => {
                            ManagementOrganizationCeiling::Organizations {
                                organization_ids: claimed,
                            }
                        }
                        ManagementOrganizationCeiling::Organizations { organization_ids } => {
                            ManagementOrganizationCeiling::Organizations {
                                organization_ids: organization_ids
                                    .intersection(&claimed)
                                    .copied()
                                    .collect(),
                            }
                        }
                        ManagementOrganizationCeiling::None => ManagementOrganizationCeiling::None,
                    };
                }
                None if issuer.capability_claim_policy
                    == CapabilityClaimPolicy::RequiredNarrowing =>
                {
                    return Err(ApplicationError::InvalidCredential);
                }
                None => {}
            }
        }
    }
    Ok((scopes, capabilities, organizations.as_optional_vec()))
}

async fn insert_verifier_material(
    transaction: &mut Transaction<'_, Postgres>,
    issuer_id: IssuerId,
    material_id: Uuid,
    version: i64,
    jwks: &JwkSet,
    source_evidence: Value,
    accepted_until: DateTime<Utc>,
) -> Result<(), ApplicationError> {
    sqlx::query(
        "INSERT INTO issuer_verifier_material_versions(
            id, issuer_id, version, jwks, source_evidence, fetched_at, accepted_until
         ) VALUES ($1,$2,$3,$4,$5,now(),$6)",
    )
    .bind(material_id)
    .bind(issuer_id.as_uuid())
    .bind(version)
    .bind(to_json(jwks)?)
    .bind(source_evidence)
    .bind(accepted_until)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn issuer_snapshot_as_validation_input(
    snapshot: &ExternalIssuerSnapshot,
) -> Result<CreateExternalIdentityIssuer, ApplicationError> {
    Ok(CreateExternalIdentityIssuer {
        name: snapshot.name.clone(),
        display_name: snapshot.name.clone(),
        issuer: snapshot.issuer.clone(),
        status: if snapshot.active {
            IssuerStatus::Active
        } else {
            IssuerStatus::Disabled
        },
        jwks_source: snapshot.jwks_source.clone(),
        allowed_algorithms: snapshot
            .allowed_algorithms
            .iter()
            .map(|value| format!("{value:?}"))
            .collect(),
        accepted_audiences: snapshot.accepted_audiences.clone(),
        subject_claim: snapshot.subject_claim.clone(),
        claim_mapping: snapshot.claim_mapping.clone(),
        jwt_capability_ceiling: snapshot.jwt_capability_ceiling.clone(),
        management_scope_ceiling: snapshot.management_scopes.clone(),
        management_organization_ceiling: snapshot.management_organization_ceiling.clone(),
        capability_claim_policy: snapshot.capability_claim_policy,
        jwt_route_ceiling: crate::domain::JwtRouteCeiling::None,
        organization_selector: crate::domain::OrganizationSelector::None,
        provisioning_policy_id: None,
        browser_login: snapshot.browser_login.clone(),
        clock_skew_seconds: snapshot.clock_skew_seconds,
        key_cache_policy: snapshot.key_cache_policy.clone(),
    })
}

fn identity_audit(
    identity: &RequestIdentity,
    kind: &str,
    id: String,
    operation: &str,
    changed_fields: &[&str],
) -> AuditRecord {
    AuditRecord {
        actor: Some(Actor::from(&identity.principal)),
        authentication_evidence: json!({
            "method":identity.principal.authentication_method,
            "external_issuer_id":identity.principal.external_issuer_id,
            "session_id":identity.principal.session_id,
        }),
        organization_id: None,
        target_resource_kind: kind.to_owned(),
        target_resource_id: Some(id),
        operation_id: operation.to_owned(),
        outcome: "accepted",
        request_id: identity.request_id.clone(),
        changed_fields: changed_fields
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        safe_details: json!({}),
    }
}

fn issuer_event(issuer_id: IssuerId, tightening: bool) -> RuntimeEvent {
    RuntimeEvent {
        event_kind: "external_identity_issuer.changed".to_owned(),
        affected_scope: json!({"issuer_id":issuer_id}),
        security_tightening: tightening,
    }
}

fn apply_required<T>(
    target: &mut T,
    update: super::UpdateField<T>,
    field: &str,
) -> Result<(), ApplicationError> {
    match update {
        super::UpdateField::Omitted => Ok(()),
        super::UpdateField::Null => Err(ApplicationError::Validation(format!(
            "{field} cannot be null"
        ))),
        super::UpdateField::Value(value) => {
            *target = value;
            Ok(())
        }
    }
}

fn apply_optional<T>(target: &mut Option<T>, update: super::UpdateField<T>) {
    match update {
        super::UpdateField::Omitted => {}
        super::UpdateField::Null => *target = None,
        super::UpdateField::Value(value) => *target = Some(value),
    }
}

fn require_if_match(provided: Option<&str>, current: &EntityTag) -> Result<(), ApplicationError> {
    let provided = provided.ok_or(ApplicationError::PreconditionRequired)?;
    if current.matches(provided) {
        Ok(())
    } else {
        Err(ApplicationError::Stale {
            current_etag: Some(current.to_string()),
        })
    }
}

fn to_json<T: serde::Serialize + ?Sized>(value: &T) -> Result<Value, ApplicationError> {
    serde_json::to_value(value).map_err(|_| ApplicationError::Internal)
}

fn from_json<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, ApplicationError> {
    serde_json::from_value(value).map_err(|_| ApplicationError::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        CapabilityClaimPolicy, JwtRouteCeiling, KeyCachePolicy, OrganizationSelector,
    };

    #[test]
    fn unverified_claim_parser_only_selects_candidate_issuer() {
        let payload =
            URL_SAFE_NO_PAD.encode(br#"{"iss":"https://issuer.example","sub":"subject"}"#);
        let token = format!("e30.{payload}.signature");
        let claims = unverified_claims(&token).unwrap();
        assert_eq!(claims["iss"], "https://issuer.example");
        assert!(unverified_claims("not-a-jwt").is_err());
    }

    #[test]
    fn active_management_issuer_requires_explicit_scope_and_organization_ceiling() {
        let input = CreateExternalIdentityIssuer {
            name: "example".to_owned(),
            display_name: "Example".to_owned(),
            issuer: "https://issuer.example".to_owned(),
            status: IssuerStatus::Active,
            jwks_source: JwksSource::Static {
                jwks: json!({"keys":[]}),
            },
            allowed_algorithms: vec!["RS256".to_owned()],
            accepted_audiences: BTreeSet::from(["owlrora".to_owned()]),
            subject_claim: "sub".to_owned(),
            claim_mapping: ClaimMapping::default(),
            jwt_capability_ceiling: BTreeSet::from(["management:access".to_owned()]),
            management_scope_ceiling: ManagementScopeSet::empty(),
            management_organization_ceiling: ManagementOrganizationCeiling::None,
            capability_claim_policy: CapabilityClaimPolicy::Ignore,
            jwt_route_ceiling: JwtRouteCeiling::None,
            organization_selector: OrganizationSelector::None,
            provisioning_policy_id: None,
            browser_login: None,
            clock_skew_seconds: 60,
            key_cache_policy: KeyCachePolicy::default(),
        };
        assert!(validate_issuer_input(&input).is_err());
    }

    #[test]
    fn claim_paths_distinguish_literal_names_from_json_pointers() {
        let claims = json!({
            "profile.name":"literal",
            "profile":{"name":"nested"}
        });
        assert_eq!(
            claim_value(&claims, "profile.name").and_then(Value::as_str),
            Some("literal")
        );
        assert_eq!(
            claim_value(&claims, "/profile/name").and_then(Value::as_str),
            Some("nested")
        );
        assert!(validate_claim_name("profile/name").is_err());
        assert!(validate_claim_name("/profile/name").is_ok());
    }

    #[test]
    fn claim_sets_are_typed_arrays_and_never_space_split() {
        let claims = json!({"scopes":["management:read", "management:write"]});
        assert_eq!(
            claim_string_set(&claims, "scopes").unwrap().unwrap().len(),
            2
        );
        assert!(
            claim_string_set(
                &json!({"scopes":"management:read management:write"}),
                "scopes"
            )
            .is_err()
        );
    }
}
