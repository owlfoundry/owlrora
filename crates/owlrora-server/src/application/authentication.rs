use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rand::RngCore as _;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;
use uuid::Uuid;

use crate::{
    adapters::postgres::AuditRecord,
    domain::{
        Actor, AuthenticatedPrincipal, AuthenticationMethod, Capability, IssuerId,
        ManagementKeyMaterial, ManagementScope, ManagementScopeSet, OrganizationId,
        OrganizationRole, Principal, ResourceScope, SessionId, constant_time_digest_matches,
        management_key_digest, seed_admin_key_version_id,
    },
    runtime::RuntimeGeneration,
};

use super::{
    AllowedOrganization, Application, ApplicationError, AuthorizationTarget, CurrentPrincipal,
    Page, RequestIdentity, SessionCreated, SessionView,
};

const SESSION_COOKIE_PREFIX: &str = "owlrora_session_v1";
const CSRF_PREFIX: &str = "owlrora_csrf_v1";

impl Application {
    pub(crate) fn security_generation(&self) -> Result<Arc<RuntimeGeneration>, ApplicationError> {
        let now = Utc::now();
        let generation = self.runtime.capture();
        let status = self.runtime.status();
        let max_age = chrono::Duration::from_std(self.config.max_security_snapshot_age)
            .map_err(|_| ApplicationError::Internal)?;
        if now.signed_duration_since(status.confirmed_at) > max_age
            || generation
                .snapshot
                .organizations
                .values()
                .filter_map(|organization| organization.pending_tightening_deadline)
                .any(|deadline| deadline <= now)
        {
            return Err(ApplicationError::DependencyUnavailable);
        }
        Ok(generation)
    }

    pub fn authenticate_management_key(
        &self,
        raw_key: &str,
        request_id: String,
    ) -> Result<RequestIdentity, ApplicationError> {
        let material = ManagementKeyMaterial::parse(raw_key)
            .map_err(|_| ApplicationError::InvalidCredential)?;
        let generation = self.security_generation()?;
        let presented_seed_version = seed_admin_key_version_id(&material);
        if self
            .config
            .seed_admin_key_version_id
            .is_some_and(|expected| {
                constant_time_digest_matches(&expected, &presented_seed_version)
            })
        {
            return Ok(RequestIdentity {
                principal: AuthenticatedPrincipal {
                    principal: Principal::SeedAdmin,
                    authentication_method: AuthenticationMethod::ManagementApiKey,
                    effective_management_scopes: ManagementScopeSet::all(),
                    credential_capability_ceiling: Capability::ALL.into_iter().collect(),
                    effective_system_administrator: true,
                    effective_organization_capabilities: BTreeMap::new(),
                    resource_scope: ResourceScope::Deployment,
                    session_id: None,
                    accepted_key_version_id: Some(URL_SAFE_NO_PAD.encode(presented_seed_version)),
                    external_issuer_id: None,
                    external_subject: None,
                    management_organization_ceiling: None,
                },
                generation,
                request_id,
                csrf_validated: true,
            });
        }

        let verifier = generation
            .snapshot
            .identity
            .management_keys
            .get(&material.lookup_text())
            .ok_or(ApplicationError::InvalidCredential)?;
        let digest = management_key_digest(&material);
        let now = Utc::now();
        let accepted_version_id = if constant_time_digest_matches(&digest, &verifier.current_digest)
        {
            verifier.accepted_version_id.clone()
        } else if verifier.overlap_digest.as_ref().is_some_and(|overlap| {
            verifier.overlap_until.is_some_and(|until| until > now)
                && constant_time_digest_matches(&digest, overlap)
        }) {
            verifier
                .overlap_version_id
                .clone()
                .ok_or(ApplicationError::InvalidCredential)?
        } else {
            return Err(ApplicationError::InvalidCredential);
        };
        if !verifier.active || verifier.expires_at.is_some_and(|expiry| expiry <= now) {
            return Err(ApplicationError::CredentialInactive);
        }
        if let ResourceScope::Organization { organization_id } = verifier.resource_scope
            && !generation
                .snapshot
                .identity
                .active_organizations
                .get(&organization_id)
                .copied()
                .unwrap_or(false)
        {
            return Err(ApplicationError::CredentialInactive);
        }
        let principal = match verifier.resource_scope {
            ResourceScope::Deployment => Principal::DeploymentManagementApiKey {
                management_api_key_id: verifier.key_id,
            },
            ResourceScope::Organization { organization_id } => {
                Principal::OrganizationManagementApiKey {
                    organization_id,
                    management_api_key_id: verifier.key_id,
                }
            }
        };
        Ok(RequestIdentity {
            principal: AuthenticatedPrincipal {
                principal: principal.clone(),
                authentication_method: AuthenticationMethod::ManagementApiKey,
                effective_management_scopes: verifier.scopes.clone(),
                credential_capability_ceiling: capabilities_from_value(
                    &verifier.capability_ceiling,
                )?,
                effective_system_administrator: matches!(
                    &principal,
                    Principal::DeploymentManagementApiKey { .. }
                ) && generation
                    .snapshot
                    .identity
                    .system_administrator_keys
                    .get(&verifier.key_id)
                    .copied()
                    .unwrap_or(false),
                effective_organization_capabilities: BTreeMap::new(),
                resource_scope: verifier.resource_scope.clone(),
                session_id: None,
                accepted_key_version_id: Some(accepted_version_id),
                external_issuer_id: None,
                external_subject: None,
                management_organization_ceiling: match verifier.resource_scope {
                    ResourceScope::Deployment => None,
                    ResourceScope::Organization { organization_id } => Some(vec![organization_id]),
                },
            },
            generation,
            request_id,
            csrf_validated: true,
        })
    }

    pub async fn create_key_session(
        &self,
        direct_identity: &RequestIdentity,
    ) -> Result<SessionCreated, ApplicationError> {
        if direct_identity.principal.authentication_method != AuthenticationMethod::ManagementApiKey
        {
            return Err(ApplicationError::InvalidCredential);
        }
        let (raw_session, session_digest) = generate_token(SESSION_COOKIE_PREFIX, b"session")?;
        let (csrf_token, csrf_digest) = generate_token(CSRF_PREFIX, b"csrf")?;
        let session_id = SessionId::new();
        let now = Utc::now();
        let expires_at = now
            + chrono::Duration::from_std(self.config.session_lifetime)
                .map_err(|_| ApplicationError::Internal)?;
        let principal = &direct_identity.principal.principal;
        let management_key_id = match principal {
            Principal::DeploymentManagementApiKey {
                management_api_key_id,
            }
            | Principal::OrganizationManagementApiKey {
                management_api_key_id,
                ..
            } => Some(management_api_key_id.as_uuid()),
            Principal::SeedAdmin => None,
            Principal::LocalUser { .. } | Principal::OrganizationGatewayApiKey { .. } => {
                return Err(ApplicationError::InvalidCredential);
            }
        };
        let captured_capability_ceiling = match principal {
            Principal::SeedAdmin => json!(["system_administration"]),
            Principal::DeploymentManagementApiKey {
                management_api_key_id,
            }
            | Principal::OrganizationManagementApiKey {
                management_api_key_id,
                ..
            } => direct_identity
                .generation
                .snapshot
                .identity
                .management_keys_by_id
                .get(management_api_key_id)
                .map(|key| key.capability_ceiling.clone())
                .ok_or(ApplicationError::CredentialInactive)?,
            Principal::LocalUser { .. } | Principal::OrganizationGatewayApiKey { .. } => {
                return Err(ApplicationError::InvalidCredential);
            }
        };

        let mut transaction = self.store.begin().await?;
        sqlx::query(
            "INSERT INTO web_sessions(
                id, session_digest, csrf_digest, principal, authentication_method,
                management_api_key_id, accepted_key_version_id, captured_management_scopes,
                captured_resource_scope, captured_capability_ceiling,
                captured_system_administrator, captured_organization_capabilities,
                captured_organization_ceiling, status, expires_at
             ) VALUES ($1,$2,$3,$4,'management_api_key_session',$5,$6,$7,$8,$9,$10,$11,$12,'active',$13)",
        )
        .bind(session_id.as_uuid())
        .bind(session_digest.to_vec())
        .bind(csrf_digest.to_vec())
        .bind(serde_json::to_value(principal).map_err(|_| ApplicationError::Internal)?)
        .bind(management_key_id)
        .bind(&direct_identity.principal.accepted_key_version_id)
        .bind(
            serde_json::to_value(&direct_identity.principal.effective_management_scopes)
                .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(
            serde_json::to_value(&direct_identity.principal.resource_scope)
                .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(captured_capability_ceiling)
        .bind(direct_identity.principal.effective_system_administrator)
        .bind(
            serde_json::to_value(&direct_identity.principal.effective_organization_capabilities)
                .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(
            direct_identity
                .principal
                .management_organization_ceiling
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(expires_at)
        .execute(&mut *transaction)
        .await?;
        let actor = Actor::from(&direct_identity.principal);
        self.store
            .commit_command(
                transaction,
                &AuditRecord {
                    actor: Some(actor),
                    authentication_evidence: json!({"method":"management_api_key"}),
                    organization_id: organization_from_scope(
                        &direct_identity.principal.resource_scope,
                    ),
                    target_resource_kind: "web_session".to_owned(),
                    target_resource_id: Some(session_id.to_string()),
                    operation_id: "auth.management_key_session.create".to_owned(),
                    outcome: "accepted",
                    request_id: direct_identity.request_id.clone(),
                    changed_fields: vec!["session".to_owned()],
                    safe_details: json!({}),
                },
                None,
            )
            .await?;
        Ok(SessionCreated {
            session: SessionView {
                id: session_id,
                principal: principal.clone(),
                authentication_method: AuthenticationMethod::ManagementApiKeySession,
                created_at: now,
                expires_at,
                current: true,
            },
            session_cookie: raw_session,
            csrf_token,
        })
    }

    pub(crate) async fn create_external_session(
        &self,
        direct_identity: &RequestIdentity,
    ) -> Result<SessionCreated, ApplicationError> {
        if direct_identity.principal.authentication_method != AuthenticationMethod::ExternalJwt
            || !matches!(
                direct_identity.principal.principal,
                Principal::LocalUser { .. }
            )
        {
            return Err(ApplicationError::InvalidCredential);
        }
        let issuer_id = direct_identity
            .principal
            .external_issuer_id
            .ok_or(ApplicationError::InvalidCredential)?;
        let external_subject = direct_identity
            .principal
            .external_subject
            .as_deref()
            .ok_or(ApplicationError::InvalidCredential)?;
        let (raw_session, session_digest) = generate_token(SESSION_COOKIE_PREFIX, b"session")?;
        let (csrf_token, csrf_digest) = generate_token(CSRF_PREFIX, b"csrf")?;
        let session_id = SessionId::new();
        let now = Utc::now();
        let expires_at = now
            + chrono::Duration::from_std(self.config.session_lifetime)
                .map_err(|_| ApplicationError::Internal)?;
        let mut transaction = self.store.begin().await?;
        sqlx::query(
            "INSERT INTO web_sessions(
                id, session_digest, csrf_digest, principal, authentication_method,
                external_issuer_id, external_subject, captured_management_scopes,
                captured_resource_scope, captured_capability_ceiling,
                captured_system_administrator, captured_organization_capabilities,
                captured_organization_ceiling, status, expires_at
             ) VALUES ($1,$2,$3,$4,'external_session',$5,$6,$7,$8,$9,$10,$11,$12,'active',$13)",
        )
        .bind(session_id.as_uuid())
        .bind(session_digest.to_vec())
        .bind(csrf_digest.to_vec())
        .bind(
            serde_json::to_value(&direct_identity.principal.principal)
                .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(issuer_id.as_uuid())
        .bind(external_subject)
        .bind(
            serde_json::to_value(&direct_identity.principal.effective_management_scopes)
                .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(
            serde_json::to_value(&direct_identity.principal.resource_scope)
                .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(
            serde_json::to_value(&direct_identity.principal.credential_capability_ceiling)
                .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(direct_identity.principal.effective_system_administrator)
        .bind(
            serde_json::to_value(
                &direct_identity
                    .principal
                    .effective_organization_capabilities,
            )
            .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(
            direct_identity
                .principal
                .management_organization_ceiling
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(expires_at)
        .execute(&mut *transaction)
        .await?;
        self.store
            .commit_command(
                transaction,
                &AuditRecord {
                    actor: Some(Actor::from(&direct_identity.principal)),
                    authentication_evidence: json!({"method":"external_jwt", "issuer_id":issuer_id}),
                    organization_id: None,
                    target_resource_kind: "web_session".to_owned(),
                    target_resource_id: Some(session_id.to_string()),
                    operation_id: "auth.external_session.create".to_owned(),
                    outcome: "accepted",
                    request_id: direct_identity.request_id.clone(),
                    changed_fields: vec!["session".to_owned()],
                    safe_details: json!({}),
                },
                None,
            )
            .await?;
        Ok(SessionCreated {
            session: SessionView {
                id: session_id,
                principal: direct_identity.principal.principal.clone(),
                authentication_method: AuthenticationMethod::ExternalSession,
                created_at: now,
                expires_at,
                current: true,
            },
            session_cookie: raw_session,
            csrf_token,
        })
    }

    pub async fn authenticate_session(
        &self,
        raw_session: &str,
        csrf_token: Option<&str>,
        request_id: String,
    ) -> Result<RequestIdentity, ApplicationError> {
        let generation = self.security_generation()?;
        let session_digest =
            parse_and_digest_token(raw_session, SESSION_COOKIE_PREFIX, b"session")?;
        let row = sqlx::query(
            "SELECT id, csrf_digest, principal, authentication_method, management_api_key_id,
                    accepted_key_version_id, external_issuer_id, external_subject,
                    captured_management_scopes, captured_resource_scope, captured_capability_ceiling,
                    captured_system_administrator, captured_organization_capabilities,
                    captured_organization_ceiling, status, expires_at
             FROM web_sessions WHERE session_digest = $1",
        )
        .bind(session_digest.to_vec())
        .fetch_optional(self.store.pool())
        .await?
        .ok_or(ApplicationError::InvalidCredential)?;
        if row.try_get::<String, _>("status")? != "active"
            || row.try_get::<DateTime<Utc>, _>("expires_at")? <= Utc::now()
        {
            return Err(ApplicationError::CredentialInactive);
        }
        let principal: Principal = serde_json::from_value(row.try_get("principal")?)
            .map_err(|_| ApplicationError::Internal)?;
        let captured_scopes: ManagementScopeSet =
            serde_json::from_value(row.try_get("captured_management_scopes")?)
                .map_err(|_| ApplicationError::Internal)?;
        let resource_scope: ResourceScope =
            serde_json::from_value(row.try_get("captured_resource_scope")?)
                .map_err(|_| ApplicationError::Internal)?;
        let accepted_key_version_id: Option<String> = row.try_get("accepted_key_version_id")?;
        let external_issuer_id = row
            .try_get::<Option<Uuid>, _>("external_issuer_id")?
            .map(IssuerId::from_uuid);
        let external_subject: Option<String> = row.try_get("external_subject")?;
        let captured_capabilities =
            capabilities_from_value(&row.try_get::<Value, _>("captured_capability_ceiling")?)?;
        let captured_system_administrator: bool = row.try_get("captured_system_administrator")?;
        let captured_organization_capabilities: BTreeMap<OrganizationId, BTreeSet<Capability>> =
            serde_json::from_value(row.try_get("captured_organization_capabilities")?)
                .map_err(|_| ApplicationError::Internal)?;
        let captured_organizations: Option<Vec<OrganizationId>> = row
            .try_get::<Option<Value>, _>("captured_organization_ceiling")?
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| ApplicationError::Internal)?;

        let (
            effective_scopes,
            effective_capabilities,
            effective_system_administrator,
            effective_organization_capabilities,
            effective_organizations,
        ) = self.validate_session_principal(
            &generation,
            &principal,
            &resource_scope,
            &captured_scopes,
            &captured_capabilities,
            captured_organizations.as_deref(),
            accepted_key_version_id.as_deref(),
            external_issuer_id,
            external_subject.as_deref(),
            captured_system_administrator,
            &captured_organization_capabilities,
        )?;
        let expected_csrf = digest_bytes(b"csrf", csrf_token.unwrap_or_default().as_bytes());
        let stored_csrf = digest_array(row.try_get("csrf_digest")?)?;
        let csrf_validated =
            csrf_token.is_some() && constant_time_digest_matches(&expected_csrf, &stored_csrf);
        let session_id = SessionId::from_uuid(row.try_get("id")?);
        Ok(RequestIdentity {
            principal: AuthenticatedPrincipal {
                principal,
                authentication_method: match row
                    .try_get::<String, _>("authentication_method")?
                    .as_str()
                {
                    "management_api_key_session" => AuthenticationMethod::ManagementApiKeySession,
                    "external_session" => AuthenticationMethod::ExternalSession,
                    _ => return Err(ApplicationError::Internal),
                },
                effective_management_scopes: effective_scopes,
                credential_capability_ceiling: effective_capabilities,
                effective_system_administrator,
                effective_organization_capabilities,
                resource_scope,
                session_id: Some(session_id),
                accepted_key_version_id,
                external_issuer_id,
                external_subject,
                management_organization_ceiling: effective_organizations,
            },
            generation,
            request_id,
            csrf_validated,
        })
    }

    fn validate_session_principal(
        &self,
        generation: &Arc<RuntimeGeneration>,
        principal: &Principal,
        resource_scope: &ResourceScope,
        captured_scopes: &ManagementScopeSet,
        captured_capabilities: &BTreeSet<Capability>,
        captured_organizations: Option<&[OrganizationId]>,
        accepted_key_version_id: Option<&str>,
        external_issuer_id: Option<IssuerId>,
        external_subject: Option<&str>,
        captured_system_administrator: bool,
        captured_organization_capabilities: &BTreeMap<OrganizationId, BTreeSet<Capability>>,
    ) -> Result<
        (
            ManagementScopeSet,
            BTreeSet<Capability>,
            bool,
            BTreeMap<OrganizationId, BTreeSet<Capability>>,
            Option<Vec<OrganizationId>>,
        ),
        ApplicationError,
    > {
        match principal {
            Principal::SeedAdmin => {
                let expected = self
                    .config
                    .seed_admin_key_version_id
                    .map(|value| URL_SAFE_NO_PAD.encode(value));
                if expected.as_deref() != accepted_key_version_id {
                    return Err(ApplicationError::CredentialInactive);
                }
                Ok((
                    captured_scopes.intersection(&ManagementScopeSet::all()),
                    captured_capabilities.clone(),
                    captured_system_administrator,
                    captured_organization_capabilities.clone(),
                    captured_organizations.map(<[OrganizationId]>::to_vec),
                ))
            }
            Principal::DeploymentManagementApiKey {
                management_api_key_id,
            }
            | Principal::OrganizationManagementApiKey {
                management_api_key_id,
                ..
            } => {
                let verifier = generation
                    .snapshot
                    .identity
                    .management_keys_by_id
                    .get(management_api_key_id)
                    .ok_or(ApplicationError::CredentialInactive)?;
                let now = Utc::now();
                if !verifier.active
                    || verifier.expires_at.is_some_and(|expiry| expiry <= now)
                    || &verifier.resource_scope != resource_scope
                {
                    return Err(ApplicationError::CredentialInactive);
                }
                let version_valid = accepted_key_version_id
                    == Some(verifier.accepted_version_id.as_str())
                    || (accepted_key_version_id == verifier.overlap_version_id.as_deref()
                        && verifier.overlap_until.is_some_and(|until| until > now));
                if !version_valid {
                    return Err(ApplicationError::CredentialInactive);
                }
                if let ResourceScope::Organization { organization_id } = resource_scope
                    && !generation
                        .snapshot
                        .identity
                        .active_organizations
                        .get(organization_id)
                        .copied()
                        .unwrap_or(false)
                {
                    return Err(ApplicationError::CredentialInactive);
                }
                let current_capabilities = capabilities_from_value(&verifier.capability_ceiling)?;
                let current_system_administrator =
                    matches!(principal, Principal::DeploymentManagementApiKey { .. })
                        && generation
                            .snapshot
                            .identity
                            .system_administrator_keys
                            .get(management_api_key_id)
                            .copied()
                            .unwrap_or(false);
                Ok((
                    captured_scopes.intersection(&verifier.scopes),
                    captured_capabilities
                        .intersection(&current_capabilities)
                        .copied()
                        .collect(),
                    captured_system_administrator && current_system_administrator,
                    BTreeMap::new(),
                    captured_organizations.map(<[OrganizationId]>::to_vec),
                ))
            }
            Principal::LocalUser { user_id } => {
                if !generation
                    .snapshot
                    .identity
                    .active_users
                    .get(user_id)
                    .copied()
                    .unwrap_or(false)
                {
                    return Err(ApplicationError::CredentialInactive);
                }
                let issuer_id = external_issuer_id.ok_or(ApplicationError::CredentialInactive)?;
                let issuer = generation
                    .snapshot
                    .identity
                    .external_issuers_by_id
                    .get(&issuer_id)
                    .filter(|issuer| issuer.active)
                    .ok_or(ApplicationError::CredentialInactive)?;
                let subject = external_subject.ok_or(ApplicationError::CredentialInactive)?;
                if generation
                    .snapshot
                    .identity
                    .external_bindings
                    .get(&(issuer_id, subject.to_owned()))
                    .copied()
                    != Some(*user_id)
                {
                    return Err(ApplicationError::CredentialInactive);
                }
                let current_organizations =
                    issuer.management_organization_ceiling.as_optional_vec();
                let effective_organizations = intersect_organization_ceilings(
                    captured_organizations,
                    current_organizations.as_deref(),
                );
                let effective_capabilities: BTreeSet<_> = captured_capabilities
                    .intersection(&issuer.management_capabilities)
                    .copied()
                    .collect();
                let (current_system_administrator, current_organization_capabilities) =
                    local_user_authority(
                        generation,
                        *user_id,
                        &effective_capabilities,
                        effective_organizations.as_deref(),
                    );
                Ok((
                    captured_scopes.intersection(&issuer.management_scopes),
                    effective_capabilities,
                    captured_system_administrator && current_system_administrator,
                    intersect_organization_capability_maps(
                        captured_organization_capabilities,
                        &current_organization_capabilities,
                    ),
                    effective_organizations,
                ))
            }
            Principal::OrganizationGatewayApiKey { .. } => Err(ApplicationError::InvalidCredential),
        }
    }

    pub(crate) fn external_local_authority(
        &self,
        generation: &Arc<RuntimeGeneration>,
        user_id: crate::domain::UserId,
        capability_ceiling: &BTreeSet<Capability>,
        organization_ceiling: Option<&[OrganizationId]>,
    ) -> (bool, BTreeMap<OrganizationId, BTreeSet<Capability>>) {
        local_user_authority(
            generation,
            user_id,
            capability_ceiling,
            organization_ceiling,
        )
    }

    pub fn authorize(
        &self,
        identity: &RequestIdentity,
        required_scopes: &[ManagementScope],
        target: AuthorizationTarget,
    ) -> Result<(), ApplicationError> {
        if required_scopes.iter().any(|scope| {
            !identity
                .principal
                .effective_management_scopes
                .contains(*scope)
        }) {
            return Err(ApplicationError::Forbidden);
        }
        let authorized = match target {
            AuthorizationTarget::CurrentPrincipal => true,
            AuthorizationTarget::System { capability } => {
                self.is_system_administrator(identity)
                    && self.principal_capability_allows(identity, capability)
            }
            AuthorizationTarget::Organization {
                organization_id,
                capability,
            } => self.organization_capability_allows(identity, organization_id, capability),
            AuthorizationTarget::Operations { write } => {
                identity
                    .principal
                    .effective_management_scopes
                    .contains(ManagementScope::Operations)
                    && identity
                        .principal
                        .effective_management_scopes
                        .contains(if write {
                            ManagementScope::Write
                        } else {
                            ManagementScope::Read
                        })
                    && self.is_system_administrator(identity)
                    && self.principal_capability_allows(
                        identity,
                        if write {
                            Capability::RecoverOperations
                        } else {
                            Capability::ReadOperations
                        },
                    )
            }
        };
        if authorized {
            Ok(())
        } else {
            Err(ApplicationError::Forbidden)
        }
    }

    pub fn is_system_administrator(&self, identity: &RequestIdentity) -> bool {
        identity.principal.effective_system_administrator
    }

    fn principal_capability_allows(
        &self,
        identity: &RequestIdentity,
        capability: Capability,
    ) -> bool {
        let principal = &identity.principal;
        if !principal
            .credential_capability_ceiling
            .contains(&capability)
        {
            return false;
        }
        match principal.principal {
            Principal::SeedAdmin | Principal::LocalUser { .. } => true,
            Principal::DeploymentManagementApiKey {
                management_api_key_id,
            }
            | Principal::OrganizationManagementApiKey {
                management_api_key_id,
                ..
            } => identity
                .generation
                .snapshot
                .identity
                .management_keys_by_id
                .get(&management_api_key_id)
                .is_some_and(|key| value_has_capability(&key.capability_ceiling, capability)),
            Principal::OrganizationGatewayApiKey { .. } => false,
        }
    }

    fn organization_capability_allows(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        capability: Capability,
    ) -> bool {
        let principal = &identity.principal;
        let snapshot = &identity.generation.snapshot.identity;
        if !snapshot
            .active_organizations
            .get(&organization_id)
            .copied()
            .unwrap_or(false)
        {
            return false;
        }
        if self.is_system_administrator(identity)
            && principal_scope_allows_organization(principal, organization_id)
        {
            return self.principal_capability_allows(identity, capability);
        }
        match principal.principal {
            Principal::LocalUser { .. } => {
                principal_scope_allows_organization(principal, organization_id)
                    && principal
                        .effective_organization_capabilities
                        .get(&organization_id)
                        .is_some_and(|capabilities| capabilities.contains(&capability))
            }
            Principal::OrganizationManagementApiKey {
                organization_id: bound,
                ..
            } if bound == organization_id => self.principal_capability_allows(identity, capability),
            _ => false,
        }
    }

    pub async fn current_principal(
        &self,
        identity: &RequestIdentity,
    ) -> Result<CurrentPrincipal, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read],
            AuthorizationTarget::CurrentPrincipal,
        )?;
        let system_administrator = self.is_system_administrator(identity);
        let allowed_organizations = if matches!(
            identity.principal.principal,
            Principal::OrganizationManagementApiKey { .. }
        ) {
            self.list_allowed_organizations(identity, None, Some(1))
                .await?
                .items
        } else {
            Vec::new()
        };
        let capabilities = if system_administrator {
            Capability::ALL
                .into_iter()
                .filter(|capability| self.principal_capability_allows(identity, *capability))
                .map(|capability| capability.as_str().to_owned())
                .collect()
        } else {
            Vec::new()
        };
        Ok(CurrentPrincipal {
            principal: identity.principal.principal.clone(),
            authentication_method: identity.principal.authentication_method,
            effective_management_scopes: identity.principal.effective_management_scopes.clone(),
            resource_scope: identity.principal.resource_scope.clone(),
            system_administrator,
            allowed_organizations,
            capabilities,
        })
    }

    pub async fn list_allowed_organizations(
        &self,
        identity: &RequestIdentity,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<AllowedOrganization>, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read],
            AuthorizationTarget::CurrentPrincipal,
        )?;
        let family = "me_organizations";
        let (cursor, limit) = super::resources::page_parameters(family, cursor, limit)?;
        let system_administrator = self.is_system_administrator(identity);
        let rows = match identity.principal.principal {
            Principal::OrganizationManagementApiKey {
                organization_id, ..
            } => {
                sqlx::query(
                    "SELECT id, name, NULL::text AS role,
                            'organization_key'::text AS access_reason,
                            NULL::jsonb AS api_key_policy,
                            0::bigint AS member_self_service_active_keys,
                            0::bigint AS all_active_management_keys
                     FROM organizations
                     WHERE id = $1 AND status = 'active'
                       AND ($2::uuid IS NULL OR id > $2)
                     ORDER BY id LIMIT $3",
                )
                .bind(organization_id.as_uuid())
                .bind(cursor)
                .bind(i64::from(limit) + 1)
                .fetch_all(self.store.pool())
                .await?
            }
            Principal::LocalUser { user_id } => {
                let allowed_ids = identity
                    .principal
                    .effective_organization_capabilities
                    .keys()
                    .map(|id| id.as_uuid())
                    .collect::<Vec<_>>();
                let scoped_organization = match identity.principal.resource_scope {
                    ResourceScope::Organization { organization_id } => {
                        Some(organization_id.as_uuid())
                    }
                    ResourceScope::Deployment => None,
                };
                sqlx::query(
                    "SELECT o.id, o.name, m.role, 'membership'::text AS access_reason,
                            p.policy AS api_key_policy,
                            (SELECT count(*) FROM management_api_keys k
                             WHERE k.organization_id=o.id AND k.status='active'
                               AND (k.expires_at IS NULL OR k.expires_at > now())
                               AND k.issuance_policy_class='member_self_service')
                                AS member_self_service_active_keys,
                            (SELECT count(*) FROM management_api_keys k
                             WHERE k.organization_id=o.id AND k.status='active'
                               AND (k.expires_at IS NULL OR k.expires_at > now()))
                                AS all_active_management_keys
                     FROM memberships m
                     JOIN organizations o ON o.id = m.organization_id
                     JOIN organization_api_key_policies p ON p.organization_id=o.id
                     WHERE m.user_id = $1 AND m.status = 'active' AND o.status = 'active'
                       AND ($2 OR o.id = ANY($3::uuid[]))
                       AND ($4::uuid IS NULL OR o.id = $4)
                       AND ($5::uuid IS NULL OR o.id > $5)
                     ORDER BY o.id LIMIT $6",
                )
                .bind(user_id.as_uuid())
                .bind(system_administrator)
                .bind(allowed_ids)
                .bind(scoped_organization)
                .bind(cursor)
                .bind(i64::from(limit) + 1)
                .fetch_all(self.store.pool())
                .await?
            }
            _ => Vec::new(),
        };
        let mut page =
            super::resources::page_from_rows(rows, limit, family, allowed_organization_from_row)?;
        for organization in &mut page.items {
            organization.capabilities =
                self.organization_capability_names(identity, organization.organization_id);
        }
        Ok(page)
    }

    fn organization_capability_names(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
    ) -> Vec<String> {
        Capability::ALL
            .into_iter()
            .filter(|capability| {
                self.organization_capability_allows(identity, organization_id, *capability)
            })
            .map(|capability| capability.as_str().to_owned())
            .collect()
    }

    pub async fn logout(&self, identity: &RequestIdentity) -> Result<(), ApplicationError> {
        let session_id = identity
            .principal
            .session_id
            .ok_or(ApplicationError::InvalidCredential)?;
        let mut transaction = self.store.begin().await?;
        let changed = sqlx::query(
            "UPDATE web_sessions SET status = 'revoked', revoked_at = now()
             WHERE id = $1 AND status = 'active'",
        )
        .bind(session_id.as_uuid())
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed == 0 {
            return Err(ApplicationError::CredentialInactive);
        }
        self.store
            .commit_command(
                transaction,
                &AuditRecord {
                    actor: Some(Actor::from(&identity.principal)),
                    authentication_evidence: json!({"method":"session"}),
                    organization_id: organization_from_scope(&identity.principal.resource_scope),
                    target_resource_kind: "web_session".to_owned(),
                    target_resource_id: Some(session_id.to_string()),
                    operation_id: "session.logout".to_owned(),
                    outcome: "accepted",
                    request_id: identity.request_id.clone(),
                    changed_fields: vec!["status".to_owned()],
                    safe_details: json!({}),
                },
                None,
            )
            .await?;
        Ok(())
    }
}

fn generate_token(prefix: &str, domain: &[u8]) -> Result<(String, [u8; 32]), ApplicationError> {
    let mut random = [0_u8; 32];
    rand::rng().fill_bytes(&mut random);
    let raw = format!("{prefix}.{}", URL_SAFE_NO_PAD.encode(random));
    let digest = digest_bytes(domain, raw.as_bytes());
    Ok((raw, digest))
}

fn parse_and_digest_token(
    raw: &str,
    prefix: &str,
    domain: &[u8],
) -> Result<[u8; 32], ApplicationError> {
    let (actual_prefix, encoded) = raw
        .split_once('.')
        .ok_or(ApplicationError::InvalidCredential)?;
    if actual_prefix != prefix || encoded.contains('=') {
        return Err(ApplicationError::InvalidCredential);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ApplicationError::InvalidCredential)?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(bytes) != encoded {
        return Err(ApplicationError::InvalidCredential);
    }
    Ok(digest_bytes(domain, raw.as_bytes()))
}

fn digest_bytes(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"owlrora/nonrecoverable/v1\0");
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    digest.update(bytes);
    digest.finalize().into()
}

fn digest_array(value: Vec<u8>) -> Result<[u8; 32], ApplicationError> {
    value.try_into().map_err(|_| ApplicationError::Internal)
}

fn intersect_organization_ceilings(
    captured: Option<&[OrganizationId]>,
    current: Option<&[OrganizationId]>,
) -> Option<Vec<OrganizationId>> {
    match (captured, current) {
        (None, None) => None,
        (Some(values), None) | (None, Some(values)) => Some(values.to_vec()),
        (Some(captured), Some(current)) => Some(
            captured
                .iter()
                .copied()
                .filter(|organization_id| current.contains(organization_id))
                .collect(),
        ),
    }
}

fn local_user_authority(
    generation: &RuntimeGeneration,
    user_id: crate::domain::UserId,
    capability_ceiling: &BTreeSet<Capability>,
    organization_ceiling: Option<&[OrganizationId]>,
) -> (bool, BTreeMap<OrganizationId, BTreeSet<Capability>>) {
    let snapshot = &generation.snapshot.identity;
    let system_administrator = capability_ceiling.contains(&Capability::SystemAdministration)
        && snapshot
            .system_administrator_users
            .get(&user_id)
            .copied()
            .unwrap_or(false);
    let organization_capabilities = snapshot
        .memberships
        .iter()
        .filter_map(|(&(organization_id, member_user_id), membership)| {
            if member_user_id != user_id
                || !snapshot
                    .active_organizations
                    .get(&organization_id)
                    .copied()
                    .unwrap_or(false)
                || organization_ceiling.is_some_and(|ceiling| !ceiling.contains(&organization_id))
            {
                return None;
            }
            let capabilities = capability_ceiling
                .iter()
                .copied()
                .filter(|capability| role_allows(membership.role, *capability))
                .collect::<BTreeSet<_>>();
            (!capabilities.is_empty()).then_some((organization_id, capabilities))
        })
        .collect();
    (system_administrator, organization_capabilities)
}

fn intersect_organization_capability_maps(
    captured: &BTreeMap<OrganizationId, BTreeSet<Capability>>,
    current: &BTreeMap<OrganizationId, BTreeSet<Capability>>,
) -> BTreeMap<OrganizationId, BTreeSet<Capability>> {
    captured
        .iter()
        .filter_map(|(organization_id, captured_capabilities)| {
            let current_capabilities = current.get(organization_id)?;
            let capabilities = captured_capabilities
                .intersection(current_capabilities)
                .copied()
                .collect::<BTreeSet<_>>();
            (!capabilities.is_empty()).then_some((*organization_id, capabilities))
        })
        .collect()
}

fn organization_from_scope(scope: &ResourceScope) -> Option<OrganizationId> {
    match scope {
        ResourceScope::Deployment => None,
        ResourceScope::Organization { organization_id } => Some(*organization_id),
    }
}

fn principal_scope_allows_organization(
    principal: &AuthenticatedPrincipal,
    organization_id: OrganizationId,
) -> bool {
    match &principal.resource_scope {
        ResourceScope::Deployment => principal
            .management_organization_ceiling
            .as_ref()
            .is_none_or(|ceiling| ceiling.contains(&organization_id)),
        ResourceScope::Organization {
            organization_id: bound,
        } => *bound == organization_id,
    }
}

fn value_has_capability(value: &Value, capability: Capability) -> bool {
    value.as_array().is_some_and(|items| {
        items.iter().any(|item| {
            item.as_str() == Some(capability.as_str())
                || item.as_str() == Some("system_administration")
        })
    })
}

fn capabilities_from_value(value: &Value) -> Result<BTreeSet<Capability>, ApplicationError> {
    let values = value.as_array().ok_or(ApplicationError::Internal)?;
    let mut capabilities = BTreeSet::new();
    for value in values {
        let name = value.as_str().ok_or(ApplicationError::Internal)?;
        if name == "system_administration" {
            capabilities.extend(Capability::ALL);
        } else {
            capabilities.insert(
                name.parse::<Capability>()
                    .map_err(|_| ApplicationError::Internal)?,
            );
        }
    }
    Ok(capabilities)
}

fn role_allows(role: OrganizationRole, capability: Capability) -> bool {
    let owner_only = matches!(capability, Capability::ManageOwners);
    if owner_only {
        return role == OrganizationRole::Owner;
    }
    let administrative = matches!(
        capability,
        Capability::UpdateOrganization
            | Capability::ManageMembers
            | Capability::CreateManagementKeys
            | Capability::ManageManagementKeys
            | Capability::UpdateApiKeyPolicy
            | Capability::CreateGatewayKeys
            | Capability::ManageGatewayKeys
            | Capability::ManageByok
            | Capability::ConfigureRoutes
            | Capability::ConfigureBudgets
    );
    if administrative {
        return matches!(role, OrganizationRole::Owner | OrganizationRole::Admin);
    }
    matches!(
        capability,
        Capability::ReadOrganization
            | Capability::ReadMembers
            | Capability::ReadManagementKeys
            | Capability::ReadGatewayKeys
            | Capability::ReadUsage
            | Capability::ReadAudit
    )
}

fn allowed_organization_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<AllowedOrganization, ApplicationError> {
    let role = row
        .try_get::<Option<String>, _>("role")?
        .as_deref()
        .map(parse_role)
        .transpose()?;
    let management_key_self_service = if role == Some(OrganizationRole::Member) {
        let policy = row
            .try_get::<Option<Value>, _>("api_key_policy")?
            .ok_or(ApplicationError::Internal)?;
        let active_keys = u64::try_from(row.try_get::<i64, _>("member_self_service_active_keys")?)
            .map_err(|_| ApplicationError::Internal)?;
        let all_active_keys = u64::try_from(row.try_get::<i64, _>("all_active_management_keys")?)
            .map_err(|_| ApplicationError::Internal)?;
        Some(
            super::key_management::management_key_self_service_eligibility(
                &policy,
                active_keys,
                all_active_keys,
            )?,
        )
    } else {
        None
    };
    Ok(AllowedOrganization {
        organization_id: OrganizationId::from_uuid(row.try_get("id")?),
        name: row.try_get("name")?,
        access_reason: row.try_get("access_reason")?,
        role,
        capabilities: Vec::new(),
        management_key_self_service,
    })
}

fn parse_role(value: &str) -> Result<OrganizationRole, ApplicationError> {
    match value {
        "owner" => Ok(OrganizationRole::Owner),
        "admin" => Ok(OrganizationRole::Admin),
        "member" => Ok(OrganizationRole::Member),
        _ => Err(ApplicationError::Internal),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_session_tokens_are_canonical_and_domain_separated() {
        let (raw, digest) = generate_token(SESSION_COOKIE_PREFIX, b"session").unwrap();
        assert_eq!(
            parse_and_digest_token(&raw, SESSION_COOKIE_PREFIX, b"session").unwrap(),
            digest
        );
        assert_ne!(digest, digest_bytes(b"csrf", raw.as_bytes()));
        assert!(parse_and_digest_token("invalid", SESSION_COOKIE_PREFIX, b"session").is_err());
    }

    #[test]
    fn role_capabilities_preserve_owner_boundary() {
        assert!(role_allows(
            OrganizationRole::Owner,
            Capability::ManageOwners
        ));
        assert!(!role_allows(
            OrganizationRole::Admin,
            Capability::ManageOwners
        ));
        assert!(role_allows(
            OrganizationRole::Member,
            Capability::ReadOrganization
        ));
    }
}
