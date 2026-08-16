use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Executor, Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::{
    adapters::postgres::{AuditRecord, RuntimeEvent},
    domain::{
        Actor, BudgetMode, Capability, KeyId, LlmScopeSet, ManagementScope, ManagementScopeSet,
        MaterialVersionId, OrganizationId, OrganizationRole, Principal, ResourceScope, RouteId,
        generate_management_key, management_key_digest,
    },
};

use super::{
    AdministratorGrant, Application, ApplicationError, AuthorizationTarget, CreateManagementApiKey,
    DeploymentManagementKeyPolicy, EntityTag, GrantAdministrator, KeyStatus, ManagementApiKey,
    ManagementKeySelfServiceEligibility, OneTimeManagementApiKey, OrganizationApiKeyPolicy, Page,
    RequestIdentity, RotateManagementApiKey, UpdateDeploymentManagementKeyPolicy, UpdateField,
    UpdateManagementApiKey, UpdateOrganizationApiKeyPolicy,
};

impl Application {
    pub async fn list_management_keys(
        &self,
        identity: &RequestIdentity,
        scope: ResourceScope,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<ManagementApiKey>, ApplicationError> {
        authorize_key_scope(
            self,
            identity,
            &scope,
            false,
            Capability::ReadManagementKeys,
        )?;
        let family = match &scope {
            ResourceScope::Deployment => "management_keys:deployment".to_owned(),
            ResourceScope::Organization { organization_id } => {
                format!("management_keys:organization:{organization_id}")
            }
        };
        let (cursor, limit) = super::resources::page_parameters(&family, cursor, limit)?;
        let (_, organization_id) = scope_columns(&scope);
        let rows = sqlx::query(KEY_LIST_QUERY)
            .bind(organization_id)
            .bind(cursor)
            .bind(i64::from(limit) + 1)
            .fetch_all(self.store.pool())
            .await?;
        super::resources::page_from_rows(rows, limit, &family, key_from_row)
    }

    pub async fn get_management_key(
        &self,
        identity: &RequestIdentity,
        scope: ResourceScope,
        key_id: KeyId,
    ) -> Result<(ManagementApiKey, EntityTag), ApplicationError> {
        authorize_key_scope(
            self,
            identity,
            &scope,
            false,
            Capability::ReadManagementKeys,
        )?;
        load_key(self.store.pool(), &scope, key_id).await
    }

    pub async fn create_management_key(
        &self,
        identity: &RequestIdentity,
        scope: ResourceScope,
        input: CreateManagementApiKey,
    ) -> Result<(OneTimeManagementApiKey, EntityTag), ApplicationError> {
        let member_self_service_candidate = match (&scope, &identity.principal.principal) {
            (ResourceScope::Organization { organization_id }, Principal::LocalUser { user_id }) => {
                !identity.principal.effective_system_administrator
                    && identity
                        .generation
                        .snapshot
                        .identity
                        .memberships
                        .get(&(*organization_id, *user_id))
                        .is_some_and(|membership| membership.role == OrganizationRole::Member)
            }
            _ => false,
        };
        authorize_key_scope(
            self,
            identity,
            &scope,
            true,
            if matches!(scope, ResourceScope::Deployment) {
                Capability::ManageSystemKeys
            } else if member_self_service_candidate {
                Capability::ReadOrganization
            } else {
                Capability::CreateManagementKeys
            },
        )?;
        self.authorize(
            identity,
            &[ManagementScope::Secrets, ManagementScope::Authority],
            AuthorizationTarget::CurrentPrincipal,
        )?;
        validate_key_name(&input.name)?;
        validate_requested_scopes(&scope, &input.scopes)?;
        let capabilities = validate_capability_ceiling(&input.capability_ceiling)?;
        ensure_target_dominance(identity, &scope, &input.scopes, &capabilities, None)?;
        if input.expires_at.is_some_and(|expiry| expiry <= Utc::now()) {
            return Err(ApplicationError::Validation(
                "expires_at must be in the future".to_owned(),
            ));
        }
        let issuance_policy_class = if member_self_service_candidate {
            "member_self_service".to_owned()
        } else {
            "standard".to_owned()
        };
        let issued_at = Utc::now();
        let key_id = KeyId::new();
        let version_id = MaterialVersionId::new();
        let material = generate_management_key();
        let raw_key = material.expose_once();
        let lookup = material.lookup_text();
        let digest = management_key_digest(&material);
        let prefix = safe_key_prefix(&lookup);
        let actor = serde_json::to_value(Actor::from(&identity.principal))
            .map_err(|_| ApplicationError::Internal)?;
        let (scope_kind, organization_id) = scope_columns(&scope);
        let mut transaction = self.store.begin().await?;
        lock_scope(&mut transaction, &scope).await?;
        let policy = load_policy_for_update(&mut transaction, &scope).await?;
        if issuance_policy_class == "member_self_service"
            && policy["member_self_service"]["management_key_creation"] != true
        {
            return Err(ApplicationError::Forbidden);
        }
        validate_destination_policy(
            &scope,
            &policy,
            &issuance_policy_class,
            &input.scopes,
            &capabilities,
            input.expires_at,
            issued_at,
        )?;
        enforce_active_key_limit(&mut transaction, &scope, &policy, &issuance_policy_class).await?;
        let expires_at =
            effective_key_expiry(&policy, &issuance_policy_class, input.expires_at, issued_at)?;
        sqlx::query(
            "INSERT INTO management_api_keys(
                id, resource_scope_kind, organization_id, issuance_policy_class,
                created_by_principal, name, key_prefix, lookup_id, scopes,
                capability_ceiling, status, expires_at, etag_token, created_at, updated_at
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'active',$11,$12,$13,$13)",
        )
        .bind(key_id.as_uuid())
        .bind(scope_kind)
        .bind(organization_id)
        .bind(&issuance_policy_class)
        .bind(actor)
        .bind(input.name.trim())
        .bind(prefix)
        .bind(&lookup)
        .bind(scopes_value(&input.scopes))
        .bind(&input.capability_ceiling)
        .bind(expires_at)
        .bind(Uuid::now_v7())
        .bind(issued_at)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO management_api_key_secret_versions(
                id, management_api_key_id, lookup_id, secret_digest, state
             ) VALUES ($1,$2,$3,$4,'current')",
        )
        .bind(version_id.as_uuid())
        .bind(key_id.as_uuid())
        .bind(lookup)
        .bind(digest.to_vec())
        .execute(&mut *transaction)
        .await?;
        let (management_api_key, etag) = load_key(&mut *transaction, &scope, key_id).await?;
        self.store
            .commit_command(
                transaction,
                &key_audit(
                    identity,
                    &scope,
                    key_id,
                    "management_api_keys.create",
                    &["name", "scopes", "capability_ceiling", "expires_at"],
                ),
                Some(&key_event(&scope, key_id, false)),
            )
            .await?;
        if let Err(error) = self.runtime.refresh_now().await {
            tracing::error!(
                request_id = %identity.request_id,
                key_id = %key_id,
                %error,
                "management key committed with publication pending"
            );
        }
        Ok((
            OneTimeManagementApiKey {
                management_api_key,
                key: raw_key,
            },
            etag,
        ))
    }

    pub async fn update_management_key(
        &self,
        identity: &RequestIdentity,
        scope: ResourceScope,
        key_id: KeyId,
        if_match: Option<&str>,
        input: UpdateManagementApiKey,
    ) -> Result<(ManagementApiKey, EntityTag), ApplicationError> {
        authorize_key_scope(
            self,
            identity,
            &scope,
            true,
            if matches!(scope, ResourceScope::Deployment) {
                Capability::ManageSystemKeys
            } else {
                Capability::ManageManagementKeys
            },
        )?;
        self.authorize(
            identity,
            &[ManagementScope::Authority],
            AuthorizationTarget::CurrentPrincipal,
        )?;
        if input.name.is_omitted()
            && input.scopes.is_omitted()
            && input.capability_ceiling.is_omitted()
            && input.status.is_omitted()
            && input.expires_at.is_omitted()
        {
            return Err(ApplicationError::Validation(
                "at least one update field is required".to_owned(),
            ));
        }
        let mut transaction = self.store.begin().await?;
        lock_scope(&mut transaction, &scope).await?;
        let policy = load_policy_for_update(&mut transaction, &scope).await?;
        let row = load_key_for_update(&mut transaction, &scope, key_id).await?;
        let current_etag = EntityTag::for_resource(
            "management_api_key",
            key_id.as_uuid(),
            row.try_get("etag_token")?,
        );
        require_if_match(if_match, &current_etag)?;
        let current_scopes = scopes_from_value(row.try_get("scopes")?)?;
        let current_capabilities: Value = row.try_get("capability_ceiling")?;
        let current_capability_names = validate_capability_ceiling(&current_capabilities)?;
        let current_status: String = row.try_get("status")?;
        let current_expiry: Option<DateTime<Utc>> = row.try_get("expires_at")?;
        let issued_at: DateTime<Utc> = row.try_get("created_at")?;
        let mut name: String = row.try_get("name")?;
        let mut scopes = current_scopes.clone();
        let mut capability_value = current_capabilities;
        let mut capability_names = current_capability_names.clone();
        let mut status = current_status.clone();
        let mut expires_at = current_expiry;
        let mut changed = Vec::new();
        match input.name {
            UpdateField::Omitted => {}
            UpdateField::Null => {
                return Err(ApplicationError::Validation(
                    "name cannot be null".to_owned(),
                ));
            }
            UpdateField::Value(value) => {
                validate_key_name(&value)?;
                name = value.trim().to_owned();
                changed.push("name");
            }
        }
        match input.scopes {
            UpdateField::Omitted => {}
            UpdateField::Null => {
                return Err(ApplicationError::Validation(
                    "scopes cannot be null".to_owned(),
                ));
            }
            UpdateField::Value(value) => {
                validate_requested_scopes(&scope, &value)?;
                scopes = value;
                changed.push("scopes");
            }
        }
        match input.capability_ceiling {
            UpdateField::Omitted => {}
            UpdateField::Null => {
                return Err(ApplicationError::Validation(
                    "capability_ceiling cannot be null".to_owned(),
                ));
            }
            UpdateField::Value(value) => {
                capability_names = validate_capability_ceiling(&value)?;
                capability_value = value;
                changed.push("capability_ceiling");
            }
        }
        match input.status {
            UpdateField::Omitted => {}
            UpdateField::Null => {
                return Err(ApplicationError::Validation(
                    "status cannot be null".to_owned(),
                ));
            }
            UpdateField::Value(value) => {
                if current_status == "revoked" && value != KeyStatus::Revoked {
                    return Err(ApplicationError::Conflict(
                        "a revoked key cannot be reactivated".to_owned(),
                    ));
                }
                status = value.as_str().to_owned();
                changed.push("status");
            }
        }
        match input.expires_at {
            UpdateField::Omitted => {}
            UpdateField::Null => {
                expires_at = None;
                changed.push("expires_at");
            }
            UpdateField::Value(value) => {
                if value <= Utc::now() {
                    return Err(ApplicationError::Validation(
                        "expires_at must be in the future".to_owned(),
                    ));
                }
                expires_at = Some(value);
                changed.push("expires_at");
            }
        }
        let authority_increase = !current_scopes.is_superset(&scopes)
            || !current_capability_names.is_superset(&capability_names)
            || (current_status != "active" && status == "active")
            || expiry_extended(current_expiry, expires_at);
        if authority_increase {
            ensure_target_dominance(identity, &scope, &scopes, &capability_names, Some(key_id))?;
        }
        let issuance_policy_class: String = row.try_get("issuance_policy_class")?;
        validate_destination_policy(
            &scope,
            &policy,
            &issuance_policy_class,
            &scopes,
            &capability_names,
            expires_at,
            issued_at,
        )?;
        expires_at = effective_key_expiry(&policy, &issuance_policy_class, expires_at, issued_at)?;
        let now = Utc::now();
        let current_available =
            current_status == "active" && current_expiry.is_none_or(|expiry| expiry > now);
        let candidate_available =
            status == "active" && expires_at.is_none_or(|expiry| expiry > now);
        if !current_available && candidate_available {
            enforce_active_key_limit(&mut transaction, &scope, &policy, &issuance_policy_class)
                .await?;
        }
        sqlx::query(
            "UPDATE management_api_keys SET name=$2, scopes=$3, capability_ceiling=$4,
                    status=$5, expires_at=$6, etag_token=$7, updated_at=now()
             WHERE id=$1",
        )
        .bind(key_id.as_uuid())
        .bind(name)
        .bind(scopes_value(&scopes))
        .bind(capability_value)
        .bind(&status)
        .bind(expires_at)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let security_tightening = (current_scopes != scopes && current_scopes.is_superset(&scopes))
            || (current_capability_names != capability_names
                && current_capability_names.is_superset(&capability_names))
            || (current_status == "active" && status != "active")
            || expiry_shortened(current_expiry, expires_at);
        let authority_changed = current_scopes != scopes
            || current_capability_names != capability_names
            || current_status != status
            || current_expiry != expires_at;
        if authority_changed {
            revoke_key_sessions(&mut transaction, key_id).await?;
        }
        let result = load_key(&mut *transaction, &scope, key_id).await?;
        self.store
            .commit_command(
                transaction,
                &key_audit(
                    identity,
                    &scope,
                    key_id,
                    "management_api_keys.update",
                    &changed,
                ),
                Some(&key_event(&scope, key_id, security_tightening)),
            )
            .await?;
        self.publish_committed_runtime(&identity.request_id, "management_api_keys.update")
            .await;
        Ok(result)
    }

    pub async fn rotate_management_key(
        &self,
        identity: &RequestIdentity,
        scope: ResourceScope,
        key_id: KeyId,
        input: RotateManagementApiKey,
    ) -> Result<(OneTimeManagementApiKey, EntityTag), ApplicationError> {
        authorize_key_scope(
            self,
            identity,
            &scope,
            true,
            if matches!(scope, ResourceScope::Deployment) {
                Capability::ManageSystemKeys
            } else {
                Capability::ManageManagementKeys
            },
        )?;
        self.authorize(
            identity,
            &[ManagementScope::Secrets],
            AuthorizationTarget::CurrentPrincipal,
        )?;
        let mut transaction = self.store.begin().await?;
        lock_scope(&mut transaction, &scope).await?;
        let policy = load_policy_for_update(&mut transaction, &scope).await?;
        let row = load_key_for_update(&mut transaction, &scope, key_id).await?;
        if row.try_get::<String, _>("status")? != "active" {
            return Err(ApplicationError::Conflict(
                "only an active key can be rotated".to_owned(),
            ));
        }
        let scopes = scopes_from_value(row.try_get("scopes")?)?;
        let capability_value: Value = row.try_get("capability_ceiling")?;
        let capabilities = validate_capability_ceiling(&capability_value)?;
        ensure_target_dominance(identity, &scope, &scopes, &capabilities, Some(key_id))?;
        let issuance_policy_class: String = row.try_get("issuance_policy_class")?;
        let max_overlap = policy_max_overlap(&policy, &issuance_policy_class)?;
        if input.overlap_seconds > max_overlap {
            return Err(ApplicationError::Validation(format!(
                "overlap_seconds exceeds the policy maximum of {max_overlap}"
            )));
        }
        let material = generate_management_key();
        let raw_key = material.expose_once();
        let lookup = material.lookup_text();
        let digest = management_key_digest(&material);
        let version_id = MaterialVersionId::new();
        let retired_overlap = sqlx::query(
            "UPDATE management_api_key_secret_versions
             SET state='retired', retired_at=now(), overlap_started_at=NULL, overlap_until=NULL
             WHERE management_api_key_id=$1 AND state='overlap'",
        )
        .bind(key_id.as_uuid())
        .execute(&mut *transaction)
        .await?
        .rows_affected()
            > 0;
        if input.overlap_seconds == 0 {
            sqlx::query(
                "UPDATE management_api_key_secret_versions
                 SET state='retired', retired_at=now(), overlap_started_at=NULL, overlap_until=NULL
                 WHERE management_api_key_id=$1 AND state='current'",
            )
            .bind(key_id.as_uuid())
            .execute(&mut *transaction)
            .await?;
        } else {
            let overlap_started_at = Utc::now();
            let overlap_until =
                overlap_started_at + Duration::seconds(i64::from(input.overlap_seconds));
            sqlx::query(
                "UPDATE management_api_key_secret_versions
                 SET state='overlap', overlap_started_at=$2, overlap_until=$3
                 WHERE management_api_key_id=$1 AND state='current'",
            )
            .bind(key_id.as_uuid())
            .bind(overlap_started_at)
            .bind(overlap_until)
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "INSERT INTO management_api_key_secret_versions(
                id, management_api_key_id, lookup_id, secret_digest, state
             ) VALUES ($1,$2,$3,$4,'current')",
        )
        .bind(version_id.as_uuid())
        .bind(key_id.as_uuid())
        .bind(&lookup)
        .bind(digest.to_vec())
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE management_api_keys SET lookup_id=$2, key_prefix=$3,
                    etag_token=$4, updated_at=now() WHERE id=$1",
        )
        .bind(key_id.as_uuid())
        .bind(&lookup)
        .bind(safe_key_prefix(&lookup))
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let (management_api_key, etag) = load_key(&mut *transaction, &scope, key_id).await?;
        self.store
            .commit_command(
                transaction,
                &key_audit(
                    identity,
                    &scope,
                    key_id,
                    "management_api_keys.rotate",
                    &["secret_version", "overlap_until"],
                ),
                Some(&key_event(
                    &scope,
                    key_id,
                    input.overlap_seconds == 0 || retired_overlap,
                )),
            )
            .await?;
        if let Err(error) = self.runtime.refresh_now().await {
            tracing::error!(
                request_id = %identity.request_id,
                key_id = %key_id,
                %error,
                "management key rotation committed with publication pending"
            );
        }
        Ok((
            OneTimeManagementApiKey {
                management_api_key,
                key: raw_key,
            },
            etag,
        ))
    }

    pub async fn get_deployment_management_key_policy(
        &self,
        identity: &RequestIdentity,
    ) -> Result<(DeploymentManagementKeyPolicy, EntityTag), ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read],
            AuthorizationTarget::System {
                capability: Capability::ManageSystemKeys,
            },
        )?;
        load_deployment_policy(self.store.pool(), self.store.installation_id()).await
    }

    pub async fn update_deployment_management_key_policy(
        &self,
        identity: &RequestIdentity,
        if_match: Option<&str>,
        input: UpdateDeploymentManagementKeyPolicy,
    ) -> Result<(DeploymentManagementKeyPolicy, EntityTag), ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Write, ManagementScope::Authority],
            AuthorizationTarget::System {
                capability: Capability::ManageSystemKeys,
            },
        )?;
        let UpdateField::Value(policy) = input.policy else {
            return Err(ApplicationError::Validation(
                "policy must be provided and cannot be null".to_owned(),
            ));
        };
        validate_deployment_policy_shape(&policy)?;
        let mut transaction = self.store.begin().await?;
        let row = sqlx::query(
            "SELECT policy, etag_token FROM deployment_management_key_policy
             WHERE singleton=true FOR UPDATE",
        )
        .fetch_one(&mut *transaction)
        .await?;
        let current = EntityTag::for_resource(
            "deployment_management_key_policy",
            self.store.installation_id(),
            row.try_get("etag_token")?,
        );
        require_if_match(if_match, &current)?;
        let current_policy: Value = row.try_get("policy")?;
        ensure_policy_expansion_dominance(
            identity,
            &ResourceScope::Deployment,
            &current_policy,
            &policy,
        )?;
        clamp_keys_to_policy(&mut transaction, &ResourceScope::Deployment, &policy).await?;
        ensure_active_key_counts_fit_policy(&mut transaction, &ResourceScope::Deployment, &policy)
            .await?;
        sqlx::query(
            "UPDATE deployment_management_key_policy
             SET policy=$1, etag_token=$2, updated_at=now() WHERE singleton=true",
        )
        .bind(policy)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let result =
            load_deployment_policy(&mut *transaction, self.store.installation_id()).await?;
        self.store
            .commit_command(
                transaction,
                &AuditRecord {
                    actor: Some(Actor::from(&identity.principal)),
                    authentication_evidence: json!({"method": identity.principal.authentication_method}),
                    organization_id: None,
                    target_resource_kind: "deployment_management_key_policy".to_owned(),
                    target_resource_id: None,
                    operation_id: "system.management_api_key_policy.update".to_owned(),
                    outcome: "accepted",
                    request_id: identity.request_id.clone(),
                    changed_fields: vec!["policy".to_owned()],
                    safe_details: json!({}),
                },
                Some(&RuntimeEvent {
                    event_kind: "deployment_management_key_policy.changed".to_owned(),
                    affected_scope: json!({"scope":"deployment"}),
                    security_tightening: true,
                }),
            )
            .await?;
        self.publish_committed_runtime(&identity.request_id, "system.management_key_policy.update")
            .await;
        Ok(result)
    }

    pub async fn get_organization_api_key_policy(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
    ) -> Result<(OrganizationApiKeyPolicy, EntityTag), ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read],
            AuthorizationTarget::Organization {
                organization_id,
                capability: Capability::ReadManagementKeys,
            },
        )?;
        load_organization_policy(self.store.pool(), organization_id).await
    }

    pub async fn update_organization_api_key_policy(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        if_match: Option<&str>,
        input: UpdateOrganizationApiKeyPolicy,
    ) -> Result<(OrganizationApiKeyPolicy, EntityTag), ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Write, ManagementScope::Authority],
            AuthorizationTarget::Organization {
                organization_id,
                capability: Capability::UpdateApiKeyPolicy,
            },
        )?;
        let UpdateField::Value(policy) = input.policy else {
            return Err(ApplicationError::Validation(
                "policy must be provided and cannot be null".to_owned(),
            ));
        };
        validate_policy_shape(&policy)?;
        let mut transaction = self.store.begin().await?;
        let scope = ResourceScope::Organization { organization_id };
        lock_scope(&mut transaction, &scope).await?;
        let row = sqlx::query(
            "SELECT policy, etag_token FROM organization_api_key_policies
             WHERE organization_id=$1 FOR UPDATE",
        )
        .bind(organization_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        let current = EntityTag::for_resource(
            "organization_api_key_policy",
            organization_id.as_uuid(),
            row.try_get("etag_token")?,
        );
        require_if_match(if_match, &current)?;
        let current_policy: Value = row.try_get("policy")?;
        ensure_policy_expansion_dominance(identity, &scope, &current_policy, &policy)?;
        clamp_keys_to_policy(&mut transaction, &scope, &policy).await?;
        clamp_gateway_keys_to_policy(&mut transaction, organization_id, &policy).await?;
        ensure_active_key_counts_fit_policy(&mut transaction, &scope, &policy).await?;
        ensure_gateway_policies_fit_policy(&mut transaction, organization_id, &policy).await?;
        sqlx::query(
            "UPDATE organization_api_key_policies
             SET policy=$2, etag_token=$3, updated_at=now() WHERE organization_id=$1",
        )
        .bind(organization_id.as_uuid())
        .bind(policy)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let result = load_organization_policy(&mut *transaction, organization_id).await?;
        self.store
            .commit_command(
                transaction,
                &AuditRecord {
                    actor: Some(Actor::from(&identity.principal)),
                    authentication_evidence: json!({"method": identity.principal.authentication_method}),
                    organization_id: Some(organization_id),
                    target_resource_kind: "organization_api_key_policy".to_owned(),
                    target_resource_id: Some(organization_id.to_string()),
                    operation_id: "organizations.api_key_policy.update".to_owned(),
                    outcome: "accepted",
                    request_id: identity.request_id.clone(),
                    changed_fields: vec!["policy".to_owned()],
                    safe_details: json!({}),
                },
                Some(&RuntimeEvent {
                    event_kind: "organization_api_key_policy.changed".to_owned(),
                    affected_scope: json!({"organization_id":organization_id}),
                    security_tightening: true,
                }),
            )
            .await?;
        self.publish_committed_runtime(&identity.request_id, "organization.api_key_policy.update")
            .await;
        Ok(result)
    }

    pub async fn list_administrators(
        &self,
        identity: &RequestIdentity,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<AdministratorGrant>, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read],
            AuthorizationTarget::System {
                capability: Capability::ManageAdministrators,
            },
        )?;
        let limit = limit.unwrap_or(50);
        if !(1..=100).contains(&limit) {
            return Err(ApplicationError::Validation(
                "limit must be between 1 and 100".to_owned(),
            ));
        }
        let cursor = cursor.map(decode_administrator_cursor).transpose()?;
        let include_seed = cursor.is_none();
        let database_limit = usize::try_from(limit).map_err(|_| ApplicationError::Internal)?
            - usize::from(include_seed);
        let rows = sqlx::query(
            "SELECT id, subject_kind, user_id, management_api_key_id, status, created_at
             FROM system_administrator_grants
             WHERE status='active'
               AND ($1::timestamptz IS NULL OR (created_at, id) < ($1, $2))
             ORDER BY created_at DESC, id DESC LIMIT $3",
        )
        .bind(cursor.as_ref().and_then(|value| value.created_at))
        .bind(cursor.as_ref().and_then(|value| value.id))
        .bind(i64::try_from(database_limit + 1).map_err(|_| ApplicationError::Internal)?)
        .fetch_all(self.store.pool())
        .await?;
        let has_more = rows.len() > database_limit;
        let mut rows = rows;
        rows.truncate(database_limit);
        let mut grants = Vec::with_capacity(usize::try_from(limit).unwrap_or(0));
        if include_seed {
            grants.push(AdministratorGrant {
                id: None,
                subject_kind: "seed_admin".to_owned(),
                subject_id: "seed_admin".to_owned(),
                status: "active".to_owned(),
                built_in: true,
                created_at: None,
            });
        }
        for row in &rows {
            let subject_kind: String = row.try_get("subject_kind")?;
            let subject_id = if subject_kind == "local_user" {
                row.try_get::<Uuid, _>("user_id")?.to_string()
            } else {
                row.try_get::<Uuid, _>("management_api_key_id")?.to_string()
            };
            grants.push(AdministratorGrant {
                id: Some(row.try_get::<Uuid, _>("id")?.to_string()),
                subject_kind,
                subject_id,
                status: row.try_get("status")?,
                built_in: false,
                created_at: Some(row.try_get("created_at")?),
            });
        }
        let next_cursor = if has_more {
            let (created_at, id) = if let Some(row) = rows.last() {
                (Some(row.try_get("created_at")?), Some(row.try_get("id")?))
            } else {
                (None, None)
            };
            Some(encode_administrator_cursor(&AdministratorCursor {
                created_at,
                id,
            })?)
        } else {
            None
        };
        Ok(Page {
            items: grants,
            next_cursor,
        })
    }

    pub async fn grant_administrator(
        &self,
        identity: &RequestIdentity,
        input: GrantAdministrator,
    ) -> Result<(), ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Write, ManagementScope::Authority],
            AuthorizationTarget::System {
                capability: Capability::ManageAdministrators,
            },
        )?;
        let subject_id = Uuid::parse_str(&input.subject_id)
            .map_err(|_| ApplicationError::Validation("invalid subject_id".to_owned()))?;
        let mut transaction = self.store.begin().await?;
        let grant_id = Uuid::now_v7();
        match input.subject_kind.as_str() {
            "local_user" => {
                let status = sqlx::query_scalar::<_, String>(
                    "SELECT status FROM users WHERE id=$1 FOR UPDATE",
                )
                .bind(subject_id)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(ApplicationError::Validation(
                    "user does not exist".to_owned(),
                ))?;
                if status != "active" {
                    return Err(ApplicationError::Conflict(
                        "administrator subject must be active".to_owned(),
                    ));
                }
                sqlx::query(
                    "INSERT INTO system_administrator_grants(
                        id, subject_kind, user_id, status, granted_by_principal
                     ) VALUES ($1,'local_user',$2,'active',$3)
                     ON CONFLICT (user_id) WHERE status='active' AND user_id IS NOT NULL DO NOTHING",
                )
                .bind(grant_id)
                .bind(subject_id)
                .bind(serde_json::to_value(Actor::from(&identity.principal)).map_err(|_| ApplicationError::Internal)?)
                .execute(&mut *transaction)
                .await?;
            }
            "deployment_management_api_key" => {
                let row = sqlx::query(
                    "SELECT scopes, capability_ceiling, status, expires_at
                     FROM management_api_keys
                     WHERE id=$1 AND resource_scope_kind='deployment' FOR UPDATE",
                )
                .bind(subject_id)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(ApplicationError::Validation(
                    "deployment management key does not exist".to_owned(),
                ))?;
                if row.try_get::<String, _>("status")? != "active"
                    || row
                        .try_get::<Option<DateTime<Utc>>, _>("expires_at")?
                        .is_some_and(|expiry| expiry <= Utc::now())
                {
                    return Err(ApplicationError::Conflict(
                        "administrator subject must be active".to_owned(),
                    ));
                }
                let scopes = scopes_from_value(row.try_get("scopes")?)?;
                let capabilities =
                    validate_capability_ceiling(&row.try_get("capability_ceiling")?)?;
                ensure_target_dominance(
                    identity,
                    &ResourceScope::Deployment,
                    &scopes,
                    &capabilities,
                    Some(KeyId::from_uuid(subject_id)),
                )?;
                sqlx::query(
                    "INSERT INTO system_administrator_grants(
                        id, subject_kind, management_api_key_id, status, granted_by_principal
                     ) VALUES ($1,'deployment_management_api_key',$2,'active',$3)
                     ON CONFLICT (management_api_key_id)
                     WHERE status='active' AND management_api_key_id IS NOT NULL DO NOTHING",
                )
                .bind(grant_id)
                .bind(subject_id)
                .bind(
                    serde_json::to_value(Actor::from(&identity.principal))
                        .map_err(|_| ApplicationError::Internal)?,
                )
                .execute(&mut *transaction)
                .await?;
            }
            _ => {
                return Err(ApplicationError::Validation(
                    "subject_kind must be local_user or deployment_management_api_key".to_owned(),
                ));
            }
        }
        self.store
            .commit_command(
                transaction,
                &AuditRecord {
                    actor: Some(Actor::from(&identity.principal)),
                    authentication_evidence: json!({"method": identity.principal.authentication_method}),
                    organization_id: None,
                    target_resource_kind: "system_administrator_grant".to_owned(),
                    target_resource_id: Some(input.subject_id),
                    operation_id: "system.administrators.grant".to_owned(),
                    outcome: "accepted",
                    request_id: identity.request_id.clone(),
                    changed_fields: vec!["status".to_owned()],
                    safe_details: json!({"subject_kind":input.subject_kind}),
                },
                Some(&RuntimeEvent {
                    event_kind: "system_administrator_grant.changed".to_owned(),
                    affected_scope: json!({"subject_kind":input.subject_kind,"subject_id":subject_id}),
                    security_tightening: false,
                }),
            )
            .await?;
        self.publish_committed_runtime(&identity.request_id, "system.administrators.grant")
            .await;
        Ok(())
    }

    pub async fn revoke_administrator(
        &self,
        identity: &RequestIdentity,
        subject_kind: &str,
        subject_id: &str,
    ) -> Result<(), ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Write, ManagementScope::Authority],
            AuthorizationTarget::System {
                capability: Capability::ManageAdministrators,
            },
        )?;
        if subject_kind == "seed_admin" || subject_id == "seed_admin" {
            return Err(ApplicationError::Validation(
                "seed_admin is not a grant target".to_owned(),
            ));
        }
        let subject_id = Uuid::parse_str(subject_id)
            .map_err(|_| ApplicationError::Validation("invalid subject_id".to_owned()))?;
        let (column, expected_kind) = match subject_kind {
            "local_user" => ("user_id", "local_user"),
            "deployment_management_api_key" => {
                ("management_api_key_id", "deployment_management_api_key")
            }
            _ => {
                return Err(ApplicationError::Validation(
                    "invalid subject_kind".to_owned(),
                ));
            }
        };
        let mut transaction = self.store.begin().await?;
        let query = format!(
            "UPDATE system_administrator_grants
             SET status='revoked', revoked_by_principal=$2, revoked_at=now()
             WHERE subject_kind=$3 AND {column}=$1 AND status='active'"
        );
        let changed = sqlx::query(&query)
            .bind(subject_id)
            .bind(
                serde_json::to_value(Actor::from(&identity.principal))
                    .map_err(|_| ApplicationError::Internal)?,
            )
            .bind(expected_kind)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
        if changed == 0 {
            return Err(ApplicationError::NotFound);
        }
        if expected_kind == "local_user" {
            sqlx::query(
                "UPDATE web_sessions SET status='revoked', revoked_at=now()
                 WHERE authentication_method='external_session' AND status='active'
                   AND principal->>'kind'='local_user' AND principal->>'user_id'=$1",
            )
            .bind(subject_id.to_string())
            .execute(&mut *transaction)
            .await?;
        } else {
            revoke_key_sessions(&mut transaction, KeyId::from_uuid(subject_id)).await?;
        }
        self.store
            .commit_command(
                transaction,
                &AuditRecord {
                    actor: Some(Actor::from(&identity.principal)),
                    authentication_evidence: json!({"method": identity.principal.authentication_method}),
                    organization_id: None,
                    target_resource_kind: "system_administrator_grant".to_owned(),
                    target_resource_id: Some(subject_id.to_string()),
                    operation_id: "system.administrators.revoke".to_owned(),
                    outcome: "accepted",
                    request_id: identity.request_id.clone(),
                    changed_fields: vec!["status".to_owned()],
                    safe_details: json!({"subject_kind":subject_kind}),
                },
                Some(&RuntimeEvent {
                    event_kind: "system_administrator_grant.changed".to_owned(),
                    affected_scope: json!({"subject_kind":subject_kind,"subject_id":subject_id}),
                    security_tightening: true,
                }),
            )
            .await?;
        self.publish_committed_runtime(&identity.request_id, "system.administrators.revoke")
            .await;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdministratorCursor {
    created_at: Option<DateTime<Utc>>,
    id: Option<Uuid>,
}

fn encode_administrator_cursor(cursor: &AdministratorCursor) -> Result<String, ApplicationError> {
    let bytes = serde_json::to_vec(cursor).map_err(|_| ApplicationError::Internal)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_administrator_cursor(value: &str) -> Result<AdministratorCursor, ApplicationError> {
    if value.is_empty() || value.len() > 1024 {
        return Err(ApplicationError::Validation(
            "administrator cursor is invalid".to_owned(),
        ));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApplicationError::Validation("administrator cursor is invalid".to_owned()))?;
    let cursor: AdministratorCursor = serde_json::from_slice(&bytes)
        .map_err(|_| ApplicationError::Validation("administrator cursor is invalid".to_owned()))?;
    if cursor.created_at.is_some() != cursor.id.is_some() {
        return Err(ApplicationError::Validation(
            "administrator cursor is invalid".to_owned(),
        ));
    }
    Ok(cursor)
}

async fn revoke_key_sessions(
    transaction: &mut Transaction<'_, Postgres>,
    key_id: KeyId,
) -> Result<(), ApplicationError> {
    sqlx::query(
        "UPDATE web_sessions SET status='revoked', revoked_at=now()
         WHERE management_api_key_id=$1 AND status='active'",
    )
    .bind(key_id.as_uuid())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn load_policy_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ResourceScope,
) -> Result<Value, ApplicationError> {
    match scope {
        ResourceScope::Deployment => sqlx::query_scalar::<_, Value>(
            "SELECT policy FROM deployment_management_key_policy
             WHERE singleton=true FOR UPDATE",
        )
        .fetch_one(&mut **transaction)
        .await
        .map_err(Into::into),
        ResourceScope::Organization { organization_id } => sqlx::query_scalar::<_, Value>(
            "SELECT policy FROM organization_api_key_policies
             WHERE organization_id=$1 FOR UPDATE",
        )
        .bind(organization_id.as_uuid())
        .fetch_one(&mut **transaction)
        .await
        .map_err(Into::into),
    }
}

const KEY_LIST_QUERY: &str =
    "SELECT k.id, k.resource_scope_kind, k.organization_id, k.issuance_policy_class,
            k.created_by_principal, k.name, k.key_prefix, k.scopes, k.capability_ceiling,
            k.status, k.expires_at, k.etag_token, k.created_at, k.updated_at,
            v.id AS current_secret_version_id,
            ov.overlap_until
     FROM management_api_keys k
     JOIN management_api_key_secret_versions v
       ON v.management_api_key_id=k.id AND v.state='current'
     LEFT JOIN management_api_key_secret_versions ov
       ON ov.management_api_key_id=k.id AND ov.state='overlap'
     WHERE (($1::uuid IS NULL AND k.organization_id IS NULL)
         OR ($1::uuid IS NOT NULL AND k.organization_id=$1))
       AND ($2::uuid IS NULL OR k.id < $2)
     ORDER BY k.id DESC LIMIT $3";

async fn load_key<'executor>(
    executor: impl Executor<'executor, Database = Postgres>,
    scope: &ResourceScope,
    key_id: KeyId,
) -> Result<(ManagementApiKey, EntityTag), ApplicationError> {
    let (_, organization_id) = scope_columns(scope);
    let row = sqlx::query(
        "SELECT k.id, k.resource_scope_kind, k.organization_id, k.issuance_policy_class,
                k.created_by_principal, k.name, k.key_prefix, k.scopes, k.capability_ceiling,
                k.status, k.expires_at, k.etag_token, k.created_at, k.updated_at,
                v.id AS current_secret_version_id, ov.overlap_until
         FROM management_api_keys k
         JOIN management_api_key_secret_versions v
           ON v.management_api_key_id=k.id AND v.state='current'
         LEFT JOIN management_api_key_secret_versions ov
           ON ov.management_api_key_id=k.id AND ov.state='overlap'
         WHERE k.id=$1 AND (($2::uuid IS NULL AND k.organization_id IS NULL)
                          OR ($2::uuid IS NOT NULL AND k.organization_id=$2))",
    )
    .bind(key_id.as_uuid())
    .bind(organization_id)
    .fetch_optional(executor)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    let etag = EntityTag::for_resource(
        "management_api_key",
        key_id.as_uuid(),
        row.try_get("etag_token")?,
    );
    Ok((key_from_row(row)?, etag))
}

fn key_from_row(row: sqlx::postgres::PgRow) -> Result<ManagementApiKey, ApplicationError> {
    let organization_id: Option<Uuid> = row.try_get("organization_id")?;
    let resource_scope = match row.try_get::<String, _>("resource_scope_kind")?.as_str() {
        "deployment" if organization_id.is_none() => ResourceScope::Deployment,
        "organization" => ResourceScope::Organization {
            organization_id: OrganizationId::from_uuid(
                organization_id.ok_or(ApplicationError::Internal)?,
            ),
        },
        _ => return Err(ApplicationError::Internal),
    };
    Ok(ManagementApiKey {
        id: KeyId::from_uuid(row.try_get("id")?),
        resource_scope,
        issuance_policy_class: row.try_get("issuance_policy_class")?,
        created_by_principal: row.try_get("created_by_principal")?,
        name: row.try_get("name")?,
        key_prefix: row.try_get("key_prefix")?,
        scopes: scopes_from_value(row.try_get("scopes")?)?,
        capability_ceiling: row.try_get("capability_ceiling")?,
        status: parse_key_status(&row.try_get::<String, _>("status")?)?,
        expires_at: row.try_get("expires_at")?,
        current_secret_version_id: MaterialVersionId::from_uuid(
            row.try_get("current_secret_version_id")?,
        ),
        overlap_until: row.try_get("overlap_until")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

async fn load_key_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ResourceScope,
    key_id: KeyId,
) -> Result<sqlx::postgres::PgRow, ApplicationError> {
    let (_, organization_id) = scope_columns(scope);
    sqlx::query(
        "SELECT id, name, scopes, capability_ceiling, status, expires_at, created_at,
                issuance_policy_class, etag_token
         FROM management_api_keys
         WHERE id=$1 AND (($2::uuid IS NULL AND organization_id IS NULL)
                       OR ($2::uuid IS NOT NULL AND organization_id=$2)) FOR UPDATE",
    )
    .bind(key_id.as_uuid())
    .bind(organization_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(ApplicationError::NotFound)
}

async fn lock_scope(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ResourceScope,
) -> Result<(), ApplicationError> {
    match scope {
        ResourceScope::Deployment => {
            sqlx::query(
                "SELECT singleton FROM deployment_management_key_policy
                 WHERE singleton=true FOR UPDATE",
            )
            .fetch_one(&mut **transaction)
            .await?;
        }
        ResourceScope::Organization { organization_id } => {
            let status = sqlx::query_scalar::<_, String>(
                "SELECT status FROM organizations WHERE id=$1 FOR UPDATE",
            )
            .bind(organization_id.as_uuid())
            .fetch_optional(&mut **transaction)
            .await?
            .ok_or(ApplicationError::NotFound)?;
            if status != "active" {
                return Err(ApplicationError::Conflict(
                    "organization is not active".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn authorize_key_scope(
    application: &Application,
    identity: &RequestIdentity,
    scope: &ResourceScope,
    write: bool,
    capability: Capability,
) -> Result<(), ApplicationError> {
    let mut scopes = vec![if write {
        ManagementScope::Write
    } else {
        ManagementScope::Read
    }];
    if write && capability == Capability::CreateManagementKeys {
        scopes.extend([ManagementScope::Secrets, ManagementScope::Authority]);
    } else if write && capability == Capability::ManageSystemKeys {
        // Creation and rotation handlers add the secret/authority semantics through dominance.
    }
    match scope {
        ResourceScope::Deployment => application.authorize(
            identity,
            &scopes,
            AuthorizationTarget::System { capability },
        ),
        ResourceScope::Organization { organization_id } => application.authorize(
            identity,
            &scopes,
            AuthorizationTarget::Organization {
                organization_id: *organization_id,
                capability,
            },
        ),
    }
}

fn ensure_target_dominance(
    identity: &RequestIdentity,
    target_scope: &ResourceScope,
    target_scopes: &ManagementScopeSet,
    target_capabilities: &std::collections::BTreeSet<String>,
    target_key_id: Option<KeyId>,
) -> Result<(), ApplicationError> {
    if !identity
        .principal
        .effective_management_scopes
        .is_superset(target_scopes)
    {
        return Err(ApplicationError::Forbidden);
    }
    if target_key_id.is_some_and(|target| match identity.principal.principal {
        Principal::DeploymentManagementApiKey {
            management_api_key_id,
        }
        | Principal::OrganizationManagementApiKey {
            management_api_key_id,
            ..
        } => target == management_api_key_id,
        _ => false,
    }) {
        return Err(ApplicationError::Forbidden);
    }
    match (&identity.principal.resource_scope, target_scope) {
        (
            ResourceScope::Organization {
                organization_id: caller,
            },
            ResourceScope::Organization {
                organization_id: target,
            },
        ) if caller == target => {}
        (ResourceScope::Deployment, _) => {}
        _ => return Err(ApplicationError::Forbidden),
    }
    let credential_capabilities = identity
        .principal
        .credential_capability_ceiling
        .iter()
        .map(|capability| capability.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let caller_capabilities = match (&identity.principal.principal, target_scope) {
        (Principal::SeedAdmin, _) => Capability::ALL
            .into_iter()
            .map(|capability| capability.as_str().to_owned())
            .collect(),
        (Principal::LocalUser { .. }, ResourceScope::Organization { organization_id })
            if !identity.principal.effective_system_administrator =>
        {
            identity
                .principal
                .effective_organization_capabilities
                .get(organization_id)
                .map(|capabilities| {
                    capabilities
                        .iter()
                        .filter(|capability| {
                            identity
                                .principal
                                .credential_capability_ceiling
                                .contains(capability)
                        })
                        .map(|capability| capability.as_str().to_owned())
                        .collect()
                })
                .unwrap_or_default()
        }
        (Principal::LocalUser { .. }, ResourceScope::Deployment)
            if !identity.principal.effective_system_administrator =>
        {
            return Err(ApplicationError::Forbidden);
        }
        _ => credential_capabilities,
    };
    if caller_capabilities.is_superset(target_capabilities) {
        Ok(())
    } else {
        Err(ApplicationError::Forbidden)
    }
}

fn validate_requested_scopes(
    scope: &ResourceScope,
    scopes: &ManagementScopeSet,
) -> Result<(), ApplicationError> {
    if scopes.iter().next().is_none() {
        return Err(ApplicationError::Validation(
            "at least one management scope is required".to_owned(),
        ));
    }
    if matches!(scope, ResourceScope::Organization { .. })
        && scopes.contains(ManagementScope::Operations)
    {
        return Err(ApplicationError::Validation(
            "organization keys cannot include management:operations".to_owned(),
        ));
    }
    Ok(())
}

fn validate_capability_ceiling(
    value: &Value,
) -> Result<std::collections::BTreeSet<String>, ApplicationError> {
    let array = value.as_array().ok_or_else(|| {
        ApplicationError::Validation("capability_ceiling must be an array".to_owned())
    })?;
    if array.is_empty() {
        return Err(ApplicationError::Validation(
            "capability_ceiling cannot be empty".to_owned(),
        ));
    }
    let allowed = Capability::ALL_NAMES;
    let mut capabilities = std::collections::BTreeSet::new();
    for item in array {
        let value = item.as_str().ok_or_else(|| {
            ApplicationError::Validation("capability values must be strings".to_owned())
        })?;
        if !allowed.contains(&value) && value != "system_administration" {
            return Err(ApplicationError::Validation(format!(
                "unknown capability: {value}"
            )));
        }
        if !capabilities.insert(value.to_owned()) {
            return Err(ApplicationError::Validation(
                "capability_ceiling contains duplicates".to_owned(),
            ));
        }
    }
    Ok(capabilities)
}

pub(crate) fn management_key_self_service_eligibility(
    policy: &Value,
    active_keys: u64,
    all_active_keys: u64,
) -> Result<ManagementKeySelfServiceEligibility, ApplicationError> {
    let enabled = policy
        .pointer("/member_self_service/management_key_creation")
        .and_then(Value::as_bool)
        .ok_or(ApplicationError::Internal)?;
    let allowed_scopes = effective_policy_values(policy, "member_self_service", "allowed_scopes")?
        .into_iter()
        .collect();
    let allowed_capabilities =
        effective_policy_values(policy, "member_self_service", "allowed_capabilities")?
            .into_iter()
            .collect();
    let max_expiry_days = effective_policy_limit(policy, "member_self_service", "max_expiry_days")?;
    let max_active_keys = effective_policy_limit(policy, "member_self_service", "max_active_keys")?;
    let management_max_active_keys = effective_policy_limit(policy, "standard", "max_active_keys")?;
    Ok(ManagementKeySelfServiceEligibility {
        eligible: enabled
            && active_keys < max_active_keys
            && all_active_keys < management_max_active_keys,
        allowed_scopes,
        allowed_capabilities,
        max_expiry_days,
        max_active_keys,
        active_keys,
    })
}

fn validate_destination_policy(
    scope: &ResourceScope,
    policy: &Value,
    class: &str,
    scopes: &ManagementScopeSet,
    capabilities: &std::collections::BTreeSet<String>,
    expires_at: Option<DateTime<Utc>>,
    issued_at: DateTime<Utc>,
) -> Result<(), ApplicationError> {
    let _ = scope;
    let allowed_scopes = effective_policy_values(policy, class, "allowed_scopes")?;
    if scopes
        .iter()
        .any(|scope| !allowed_scopes.contains(scope.as_str()))
    {
        return Err(ApplicationError::Forbidden);
    }
    let allowed_capabilities = effective_policy_values(policy, class, "allowed_capabilities")?;
    if capabilities
        .iter()
        .any(|capability| !allowed_capabilities.contains(capability.as_str()))
    {
        return Err(ApplicationError::Forbidden);
    }
    let max_days = effective_policy_limit(policy, class, "max_expiry_days")?;
    if expires_at.is_some_and(|expiry| {
        expiry > issued_at + Duration::days(i64::try_from(max_days).unwrap_or(i64::MAX))
    }) {
        return Err(ApplicationError::Validation(
            "expires_at exceeds the policy horizon".to_owned(),
        ));
    }
    Ok(())
}

async fn enforce_active_key_limit(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ResourceScope,
    policy: &Value,
    class: &str,
) -> Result<(), ApplicationError> {
    let (_, organization_id) = scope_columns(scope);
    match scope {
        ResourceScope::Deployment => {
            sqlx::query(
                "SELECT singleton FROM deployment_management_key_policy
                 WHERE singleton=true FOR UPDATE",
            )
            .fetch_one(&mut **transaction)
            .await?;
        }
        ResourceScope::Organization { organization_id } => {
            sqlx::query(
                "SELECT organization_id FROM organization_api_key_policies
                 WHERE organization_id=$1 FOR UPDATE",
            )
            .bind(organization_id.as_uuid())
            .fetch_one(&mut **transaction)
            .await?;
        }
    }
    let global_maximum = policy["management"]["max_active_keys"]
        .as_u64()
        .ok_or(ApplicationError::Internal)?;
    let global_count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM management_api_keys
         WHERE (($1::uuid IS NULL AND organization_id IS NULL)
             OR ($1::uuid IS NOT NULL AND organization_id=$1))
           AND status='active' AND (expires_at IS NULL OR expires_at > now())",
    )
    .bind(organization_id)
    .fetch_one(&mut **transaction)
    .await?;
    if u64::try_from(global_count).unwrap_or(u64::MAX) >= global_maximum {
        return Err(ApplicationError::Conflict(
            "global active key policy limit reached".to_owned(),
        ));
    }
    if class == "member_self_service" {
        let class_maximum = effective_policy_limit(policy, class, "max_active_keys")?;
        let class_count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM management_api_keys
             WHERE (($1::uuid IS NULL AND organization_id IS NULL)
                 OR ($1::uuid IS NOT NULL AND organization_id=$1))
               AND status='active' AND (expires_at IS NULL OR expires_at > now())
               AND issuance_policy_class='member_self_service'",
        )
        .bind(organization_id)
        .fetch_one(&mut **transaction)
        .await?;
        if u64::try_from(class_count).unwrap_or(u64::MAX) >= class_maximum {
            return Err(ApplicationError::Conflict(
                "member self-service active key policy limit reached".to_owned(),
            ));
        }
    }
    Ok(())
}

async fn ensure_active_key_counts_fit_policy(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ResourceScope,
    policy: &Value,
) -> Result<(), ApplicationError> {
    let (_, organization_id) = scope_columns(scope);
    let global_count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM management_api_keys
         WHERE (($1::uuid IS NULL AND organization_id IS NULL)
             OR ($1::uuid IS NOT NULL AND organization_id=$1))
           AND status='active' AND (expires_at IS NULL OR expires_at > now())",
    )
    .bind(organization_id)
    .fetch_one(&mut **transaction)
    .await?;
    let global_maximum = policy["management"]["max_active_keys"]
        .as_u64()
        .ok_or(ApplicationError::Internal)?;
    if u64::try_from(global_count).unwrap_or(u64::MAX) > global_maximum {
        return Err(ApplicationError::Conflict(
            "active keys exceed the proposed global policy limit".to_owned(),
        ));
    }
    if matches!(scope, ResourceScope::Organization { .. }) {
        let member_count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM management_api_keys
             WHERE organization_id=$1 AND status='active'
               AND (expires_at IS NULL OR expires_at > now())
               AND issuance_policy_class='member_self_service'",
        )
        .bind(organization_id)
        .fetch_one(&mut **transaction)
        .await?;
        let member_maximum =
            effective_policy_limit(policy, "member_self_service", "max_active_keys")?;
        if u64::try_from(member_count).unwrap_or(u64::MAX) > member_maximum {
            return Err(ApplicationError::Conflict(
                "active member self-service keys exceed the proposed policy limit".to_owned(),
            ));
        }
        let gateway_count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM gateway_api_keys
             WHERE organization_id=$1 AND status='active'
               AND (expires_at IS NULL OR expires_at > now())",
        )
        .bind(organization_id)
        .fetch_one(&mut **transaction)
        .await?;
        let gateway_maximum = policy["gateway"]["max_active_keys"]
            .as_u64()
            .ok_or(ApplicationError::Internal)?;
        if policy["gateway"]["enabled"] == true
            && u64::try_from(gateway_count).unwrap_or(u64::MAX) > gateway_maximum
        {
            return Err(ApplicationError::Conflict(
                "active Gateway keys exceed the proposed global policy limit".to_owned(),
            ));
        }
        let gateway_member_count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM gateway_api_keys
             WHERE organization_id=$1 AND status='active'
               AND (expires_at IS NULL OR expires_at > now())
               AND issuance_policy_class='member_self_service'",
        )
        .bind(organization_id)
        .fetch_one(&mut **transaction)
        .await?;
        let gateway_member_maximum = policy["gateway_member_self_service"]["max_active_keys"]
            .as_u64()
            .ok_or(ApplicationError::Internal)?;
        if policy["gateway_member_self_service"]["enabled"] == true
            && u64::try_from(gateway_member_count).unwrap_or(u64::MAX) > gateway_member_maximum
        {
            return Err(ApplicationError::Conflict(
                "active member self-service Gateway keys exceed the proposed policy limit"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

fn ensure_policy_expansion_dominance(
    identity: &RequestIdentity,
    scope: &ResourceScope,
    current: &Value,
    candidate: &Value,
) -> Result<(), ApplicationError> {
    let classes: &[&str] = if matches!(scope, ResourceScope::Deployment) {
        &["standard"]
    } else {
        &["standard", "member_self_service"]
    };
    for class in classes {
        let current_scopes = effective_policy_values(current, class, "allowed_scopes")?;
        let candidate_scopes = effective_policy_values(candidate, class, "allowed_scopes")?;
        let current_capabilities = effective_policy_values(current, class, "allowed_capabilities")?;
        let candidate_capabilities =
            effective_policy_values(candidate, class, "allowed_capabilities")?;
        if candidate_scopes.is_subset(&current_scopes)
            && candidate_capabilities.is_subset(&current_capabilities)
        {
            continue;
        }
        let parsed_scopes = candidate_scopes
            .iter()
            .map(|scope| scope.parse::<ManagementScope>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(ApplicationError::Validation)?;
        let scopes =
            ManagementScopeSet::new(parsed_scopes).map_err(ApplicationError::Validation)?;
        ensure_target_dominance(identity, scope, &scopes, &candidate_capabilities, None)?;
    }
    Ok(())
}

async fn clamp_keys_to_policy(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ResourceScope,
    policy: &Value,
) -> Result<(), ApplicationError> {
    let (_, organization_id) = scope_columns(scope);
    let rows = sqlx::query(
        "SELECT id, issuance_policy_class, scopes, capability_ceiling, status,
                expires_at, created_at
         FROM management_api_keys
         WHERE (($1::uuid IS NULL AND organization_id IS NULL)
             OR ($1::uuid IS NOT NULL AND organization_id=$1))
         FOR UPDATE",
    )
    .bind(organization_id)
    .fetch_all(&mut **transaction)
    .await?;
    for row in rows {
        let key_id: Uuid = row.try_get("id")?;
        let class: String = row.try_get("issuance_policy_class")?;
        let allowed_scopes = effective_policy_values(policy, &class, "allowed_scopes")?;
        let allowed_capabilities = effective_policy_values(policy, &class, "allowed_capabilities")?;
        let stored_scopes = serde_json::from_value::<BTreeSet<String>>(row.try_get("scopes")?)
            .map_err(|_| ApplicationError::Internal)?;
        let stored_capabilities =
            serde_json::from_value::<BTreeSet<String>>(row.try_get("capability_ceiling")?)
                .map_err(|_| ApplicationError::Internal)?;
        let scopes = stored_scopes
            .intersection(&allowed_scopes)
            .cloned()
            .collect::<BTreeSet<_>>();
        let capabilities = stored_capabilities
            .intersection(&allowed_capabilities)
            .cloned()
            .collect::<BTreeSet<_>>();
        let current_status: String = row.try_get("status")?;
        let status = if scopes.is_empty() || capabilities.is_empty() {
            "revoked"
        } else {
            current_status.as_str()
        };
        let created_at: DateTime<Utc> = row.try_get("created_at")?;
        let max_days = effective_policy_limit(policy, &class, "max_expiry_days")?;
        let policy_expiry = created_at
            + Duration::days(i64::try_from(max_days).map_err(|_| ApplicationError::Internal)?);
        let stored_expiry: Option<DateTime<Utc>> = row.try_get("expires_at")?;
        let expires_at = stored_expiry.map_or(policy_expiry, |expiry| expiry.min(policy_expiry));
        let authority_changed = scopes != stored_scopes
            || capabilities != stored_capabilities
            || status != current_status
            || stored_expiry != Some(expires_at);
        if authority_changed {
            sqlx::query(
                "UPDATE management_api_keys
                 SET scopes=$2, capability_ceiling=$3, status=$4, expires_at=$5,
                     etag_token=$6, updated_at=now()
                 WHERE id=$1",
            )
            .bind(key_id)
            .bind(serde_json::to_value(scopes).map_err(|_| ApplicationError::Internal)?)
            .bind(serde_json::to_value(capabilities).map_err(|_| ApplicationError::Internal)?)
            .bind(status)
            .bind(expires_at)
            .bind(Uuid::now_v7())
            .execute(&mut **transaction)
            .await?;
            revoke_key_sessions(transaction, KeyId::from_uuid(key_id)).await?;
        }

        let max_overlap = effective_policy_limit(policy, &class, "max_overlap_seconds")?;
        let overlap = sqlx::query(
            "SELECT id, overlap_started_at, overlap_until
             FROM management_api_key_secret_versions
             WHERE management_api_key_id=$1 AND state='overlap' FOR UPDATE",
        )
        .bind(key_id)
        .fetch_optional(&mut **transaction)
        .await?;
        let mut overlap_changed = false;
        if let Some(overlap) = overlap {
            let version_id: Uuid = overlap.try_get("id")?;
            let policy_until = overlap.try_get::<DateTime<Utc>, _>("overlap_started_at")?
                + Duration::seconds(
                    i64::try_from(max_overlap).map_err(|_| ApplicationError::Internal)?,
                );
            let stored_until: Option<DateTime<Utc>> = overlap.try_get("overlap_until")?;
            let overlap_until = stored_until.map_or(policy_until, |until| until.min(policy_until));
            if overlap_until <= Utc::now() {
                sqlx::query(
                    "UPDATE management_api_key_secret_versions
                     SET state='retired', overlap_started_at=NULL, overlap_until=NULL,
                         retired_at=now() WHERE id=$1",
                )
                .bind(version_id)
                .execute(&mut **transaction)
                .await?;
                overlap_changed = true;
            } else if stored_until != Some(overlap_until) {
                sqlx::query(
                    "UPDATE management_api_key_secret_versions SET overlap_until=$2 WHERE id=$1",
                )
                .bind(version_id)
                .bind(overlap_until)
                .execute(&mut **transaction)
                .await?;
                overlap_changed = true;
            }
        }
        if overlap_changed && !authority_changed {
            sqlx::query(
                "UPDATE management_api_keys
                 SET etag_token=$2, updated_at=now() WHERE id=$1",
            )
            .bind(key_id)
            .bind(Uuid::now_v7())
            .execute(&mut **transaction)
            .await?;
        }
    }
    Ok(())
}

async fn clamp_gateway_keys_to_policy(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    policy: &Value,
) -> Result<(), ApplicationError> {
    let rows = sqlx::query(
        "SELECT id,issuance_policy_class,scopes,status,expires_at,created_at
         FROM gateway_api_keys WHERE organization_id=$1 FOR UPDATE",
    )
    .bind(organization_id.as_uuid())
    .fetch_all(&mut **transaction)
    .await?;
    for row in rows {
        let key_id: Uuid = row.try_get("id")?;
        let class: String = row.try_get("issuance_policy_class")?;
        let global = gateway_policy_section(policy, "standard")?;
        let class_policy = gateway_policy_section(policy, &class)?;
        let enabled = gateway_policy_enabled(global)? && gateway_policy_enabled(class_policy)?;
        let global_scopes = gateway_policy_scopes(global)?;
        let class_scopes = gateway_policy_scopes(class_policy)?;
        let stored_scopes = scopes_from_policy_value(row.try_get("scopes")?)?;
        let effective_scopes = stored_scopes
            .intersection(&global_scopes)
            .and_then(|scopes| scopes.intersection(&class_scopes));
        let global_routes = gateway_policy_routes(global)?;
        let class_routes = gateway_policy_routes(class_policy)?;
        let allowed_routes = global_routes
            .intersection(&class_routes)
            .copied()
            .collect::<BTreeSet<_>>();
        let route_rows = sqlx::query_scalar::<_, Uuid>(
            "SELECT route_id FROM gateway_api_key_routes WHERE gateway_api_key_id=$1 FOR UPDATE",
        )
        .bind(key_id)
        .fetch_all(&mut **transaction)
        .await?;
        let stored_routes = route_rows
            .iter()
            .copied()
            .map(RouteId::from_uuid)
            .collect::<BTreeSet<_>>();
        let effective_routes = stored_routes
            .intersection(&allowed_routes)
            .copied()
            .collect::<BTreeSet<_>>();
        let current_status: String = row.try_get("status")?;
        let status = if current_status == "revoked"
            || !enabled
            || effective_scopes.is_none()
            || effective_routes.is_empty()
        {
            "revoked"
        } else {
            current_status.as_str()
        };
        let max_days = gateway_policy_limit(global, class_policy, "max_expiry_days")?;
        let created_at: DateTime<Utc> = row.try_get("created_at")?;
        let policy_expiry = created_at
            + Duration::days(i64::try_from(max_days).map_err(|_| ApplicationError::Internal)?);
        let stored_expiry: Option<DateTime<Utc>> = row.try_get("expires_at")?;
        let expires_at = stored_expiry.map_or(policy_expiry, |expiry| expiry.min(policy_expiry));
        let scopes_changed = effective_scopes
            .as_ref()
            .is_some_and(|scopes| scopes != &stored_scopes);
        let authority_changed = scopes_changed
            || effective_routes != stored_routes
            || status != current_status
            || stored_expiry != Some(expires_at);
        if authority_changed {
            sqlx::query(
                "UPDATE gateway_api_keys SET scopes=COALESCE($2,scopes),status=$3,
                        expires_at=$4,etag_token=$5,updated_at=now() WHERE id=$1",
            )
            .bind(key_id)
            .bind(
                effective_scopes
                    .as_ref()
                    .map(|scopes| {
                        serde_json::to_value(scopes).map_err(|_| ApplicationError::Internal)
                    })
                    .transpose()?,
            )
            .bind(status)
            .bind(expires_at)
            .bind(Uuid::now_v7())
            .execute(&mut **transaction)
            .await?;
        }
        if !effective_routes.is_empty() {
            for route_id in stored_routes.difference(&effective_routes) {
                sqlx::query(
                    "DELETE FROM gateway_api_key_routes
                     WHERE gateway_api_key_id=$1 AND route_id=$2",
                )
                .bind(key_id)
                .bind(route_id.as_uuid())
                .execute(&mut **transaction)
                .await?;
            }
        }

        let max_overlap = gateway_policy_limit(global, class_policy, "max_overlap_seconds")?;
        let overlap = sqlx::query(
            "SELECT id,created_at,overlap_until FROM gateway_api_key_secret_versions
             WHERE gateway_api_key_id=$1 AND state='overlap' FOR UPDATE",
        )
        .bind(key_id)
        .fetch_optional(&mut **transaction)
        .await?;
        if let Some(overlap) = overlap {
            let version_id: Uuid = overlap.try_get("id")?;
            let policy_until = overlap.try_get::<DateTime<Utc>, _>("created_at")?
                + Duration::seconds(
                    i64::try_from(max_overlap).map_err(|_| ApplicationError::Internal)?,
                );
            let stored_until: DateTime<Utc> = overlap.try_get("overlap_until")?;
            let overlap_until = stored_until.min(policy_until);
            if overlap_until <= Utc::now() {
                sqlx::query(
                    "UPDATE gateway_api_key_secret_versions
                     SET state='retired',overlap_until=NULL,retired_at=now() WHERE id=$1",
                )
                .bind(version_id)
                .execute(&mut **transaction)
                .await?;
            } else if overlap_until != stored_until {
                sqlx::query(
                    "UPDATE gateway_api_key_secret_versions SET overlap_until=$2 WHERE id=$1",
                )
                .bind(version_id)
                .bind(overlap_until)
                .execute(&mut **transaction)
                .await?;
            }
        }
    }
    Ok(())
}

async fn ensure_gateway_policies_fit_policy(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    policy: &Value,
) -> Result<(), ApplicationError> {
    let keys = sqlx::query(
        "SELECT id,issuance_policy_class,budget_policy_id,rate_policy_id
         FROM gateway_api_keys
         WHERE organization_id=$1 AND status<>'revoked' FOR UPDATE",
    )
    .bind(organization_id.as_uuid())
    .fetch_all(&mut **transaction)
    .await?;
    for key in keys {
        let class: String = key.try_get("issuance_policy_class")?;
        let global = gateway_policy_section(policy, "standard")?;
        let class_policy = gateway_policy_section(policy, &class)?;
        let budget_maximum = gateway_policy_nanos_limit(global, class_policy)?;
        let budget_modes = gateway_policy_budget_modes(global)?
            .intersection(&gateway_policy_budget_modes(class_policy)?)
            .copied()
            .collect::<BTreeSet<_>>();
        let budget_policy_id: Uuid = key.try_get("budget_policy_id")?;
        let budgets = sqlx::query(
            "SELECT version.limit_cost_nanos::text AS limit_cost_nanos,version.mode
             FROM gateway_key_budget_policies policy_row
             JOIN budget_policy_versions version
               ON version.id IN (policy_row.desired_version_id,policy_row.active_version_id)
             WHERE policy_row.id=$1",
        )
        .bind(budget_policy_id)
        .fetch_all(&mut **transaction)
        .await?;
        for budget in budgets {
            let limit = budget
                .try_get::<String, _>("limit_cost_nanos")?
                .parse::<u128>()
                .map_err(|_| ApplicationError::Internal)?;
            let mode = parse_budget_mode(&budget.try_get::<String, _>("mode")?)?;
            if limit > budget_maximum || !budget_modes.contains(&mode) {
                return Err(ApplicationError::Conflict(
                    "an existing Gateway-key budget exceeds the proposed organization policy"
                        .to_owned(),
                ));
            }
        }
        if let Some(rate_policy_id) = key.try_get::<Option<Uuid>, _>("rate_policy_id")? {
            let limits = sqlx::query(
                "SELECT version.requests_per_minute,version.input_units_per_minute,
                        version.concurrency_mode,version.concurrency_limit
                 FROM gateway_key_rate_policies policy_row
                 JOIN gateway_key_rate_policy_versions version
                   ON version.id IN (policy_row.desired_version_id,policy_row.active_version_id)
                 WHERE policy_row.id=$1",
            )
            .bind(rate_policy_id)
            .fetch_all(&mut **transaction)
            .await?;
            let max_requests =
                gateway_policy_limit(global, class_policy, "rate.max_requests_per_minute")?;
            let max_input =
                gateway_policy_limit(global, class_policy, "rate.max_input_units_per_minute")?;
            let max_concurrency =
                gateway_policy_limit(global, class_policy, "concurrency.max_limit")?;
            let concurrency_modes = gateway_policy_concurrency_modes(global)?
                .intersection(&gateway_policy_concurrency_modes(class_policy)?)
                .cloned()
                .collect::<BTreeSet<_>>();
            for limits in limits {
                let requests = u64::try_from(limits.try_get::<i32, _>("requests_per_minute")?)
                    .map_err(|_| ApplicationError::Internal)?;
                let input = limits
                    .try_get::<Option<i64>, _>("input_units_per_minute")?
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| ApplicationError::Internal)?;
                let concurrency_mode: Option<String> = limits.try_get("concurrency_mode")?;
                let concurrency = limits
                    .try_get::<Option<i32>, _>("concurrency_limit")?
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| ApplicationError::Internal)?;
                if requests > max_requests
                    || input.is_some_and(|value| value > max_input)
                    || concurrency.is_some_and(|value| value > max_concurrency)
                    || concurrency_mode
                        .as_ref()
                        .is_some_and(|mode| !concurrency_modes.contains(mode))
                {
                    return Err(ApplicationError::Conflict(
                        "existing Gateway-key request limits exceed the proposed organization policy"
                            .to_owned(),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn gateway_policy_section<'a>(
    policy: &'a Value,
    class: &str,
) -> Result<&'a Value, ApplicationError> {
    let name = match class {
        "standard" => "gateway",
        "member_self_service" => "gateway_member_self_service",
        _ => return Err(ApplicationError::Internal),
    };
    policy.get(name).ok_or(ApplicationError::Internal)
}

fn gateway_policy_enabled(section: &Value) -> Result<bool, ApplicationError> {
    section["enabled"]
        .as_bool()
        .ok_or(ApplicationError::Internal)
}

fn gateway_policy_scopes(section: &Value) -> Result<LlmScopeSet, ApplicationError> {
    serde_json::from_value(section["allowed_scopes"].clone())
        .map_err(|_| ApplicationError::Internal)
}

fn scopes_from_policy_value(value: Value) -> Result<LlmScopeSet, ApplicationError> {
    serde_json::from_value(value).map_err(|_| ApplicationError::Internal)
}

fn gateway_policy_routes(section: &Value) -> Result<BTreeSet<RouteId>, ApplicationError> {
    serde_json::from_value::<Vec<RouteId>>(section["allowed_route_ids"].clone())
        .map(|routes| routes.into_iter().collect())
        .map_err(|_| ApplicationError::Internal)
}

fn gateway_policy_limit(
    global: &Value,
    class: &Value,
    path: &str,
) -> Result<u64, ApplicationError> {
    let pointer = format!("/{}", path.replace('.', "/"));
    let global = global
        .pointer(&pointer)
        .and_then(Value::as_u64)
        .ok_or(ApplicationError::Internal)?;
    let class = class
        .pointer(&pointer)
        .and_then(Value::as_u64)
        .ok_or(ApplicationError::Internal)?;
    Ok(global.min(class))
}

fn gateway_policy_nanos_limit(global: &Value, class: &Value) -> Result<u128, ApplicationError> {
    let parse = |section: &Value| {
        section["budget"]["max_limit_cost_nanos"]
            .as_str()
            .and_then(|value| value.parse::<u128>().ok())
            .ok_or(ApplicationError::Internal)
    };
    Ok(parse(global)?.min(parse(class)?))
}

fn gateway_policy_budget_modes(section: &Value) -> Result<BTreeSet<BudgetMode>, ApplicationError> {
    serde_json::from_value::<Vec<BudgetMode>>(section["budget"]["allowed_modes"].clone())
        .map(|modes| modes.into_iter().collect())
        .map_err(|_| ApplicationError::Internal)
}

fn gateway_policy_concurrency_modes(section: &Value) -> Result<BTreeSet<String>, ApplicationError> {
    serde_json::from_value::<Vec<String>>(section["concurrency"]["allowed_modes"].clone())
        .map(|modes| modes.into_iter().collect())
        .map_err(|_| ApplicationError::Internal)
}

fn parse_budget_mode(value: &str) -> Result<BudgetMode, ApplicationError> {
    match value {
        "enforce" => Ok(BudgetMode::Enforce),
        "record_only" => Ok(BudgetMode::RecordOnly),
        _ => Err(ApplicationError::Internal),
    }
}

fn validate_deployment_policy_shape(policy: &Value) -> Result<(), ApplicationError> {
    let Some(object) = policy.as_object() else {
        return Err(ApplicationError::Validation(
            "deployment policy must be an object".to_owned(),
        ));
    };
    if object.len() != 1 || !object.contains_key("management") {
        return Err(ApplicationError::Validation(
            "deployment policy accepts only the management section".to_owned(),
        ));
    }
    validate_policy_section(&policy["management"], true)
}

fn validate_policy_shape(policy: &Value) -> Result<(), ApplicationError> {
    let Some(object) = policy.as_object() else {
        return Err(ApplicationError::Validation(
            "organization API key policy must be an object".to_owned(),
        ));
    };
    let expected = BTreeSet::from([
        "management",
        "member_self_service",
        "gateway",
        "gateway_member_self_service",
    ]);
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err(ApplicationError::Validation(
            "organization API key policy has unknown or missing sections".to_owned(),
        ));
    }
    validate_policy_section(&policy["management"], false)?;
    let member_enabled = policy["member_self_service"]["management_key_creation"]
        .as_bool()
        .ok_or_else(|| {
            ApplicationError::Validation(
                "member_self_service.management_key_creation must be boolean".to_owned(),
            )
        })?;
    if member_enabled {
        validate_policy_section(&policy["member_self_service"], false)?;
        for field in ["allowed_scopes", "allowed_capabilities"] {
            let global = policy["management"][field]
                .as_array()
                .ok_or(ApplicationError::Internal)?
                .iter()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>();
            let member = policy["member_self_service"][field]
                .as_array()
                .ok_or(ApplicationError::Internal)?
                .iter()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>();
            if !member.is_subset(&global) {
                return Err(ApplicationError::Validation(format!(
                    "member_self_service.{field} must be a subset of management.{field}"
                )));
            }
        }
        for field in ["max_active_keys", "max_expiry_days", "max_overlap_seconds"] {
            let global = policy["management"][field]
                .as_u64()
                .ok_or(ApplicationError::Internal)?;
            let member = policy["member_self_service"][field]
                .as_u64()
                .ok_or(ApplicationError::Internal)?;
            if member > global {
                return Err(ApplicationError::Validation(format!(
                    "member_self_service.{field} cannot exceed management.{field}"
                )));
            }
        }
    } else {
        validate_disabled_member_policy_section(&policy["member_self_service"])?;
    }
    validate_gateway_policy_section(&policy["gateway"], false)?;
    validate_gateway_policy_section(&policy["gateway_member_self_service"], true)?;
    if policy["gateway_member_self_service"]["enabled"] == true {
        validate_gateway_policy_subset(&policy["gateway"], &policy["gateway_member_self_service"])?;
    }
    Ok(())
}

fn validate_gateway_policy_section(section: &Value, member: bool) -> Result<(), ApplicationError> {
    let Some(object) = section.as_object() else {
        return Err(ApplicationError::Validation(
            "gateway key policy section must be an object".to_owned(),
        ));
    };
    let expected = BTreeSet::from([
        "enabled",
        "allowed_scopes",
        "allowed_capabilities",
        "allowed_route_ids",
        "max_active_keys",
        "max_expiry_days",
        "max_overlap_seconds",
        "budget",
        "rate",
        "concurrency",
    ]);
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err(ApplicationError::Validation(
            "gateway key policy section has unknown or missing fields".to_owned(),
        ));
    }
    let enabled = section["enabled"].as_bool().ok_or_else(|| {
        ApplicationError::Validation("gateway enabled must be boolean".to_owned())
    })?;
    let scopes =
        serde_json::from_value::<Vec<crate::domain::LlmScope>>(section["allowed_scopes"].clone())
            .map_err(|_| ApplicationError::Validation("allowed_scopes is invalid".to_owned()))?;
    let unique_scopes = scopes.iter().copied().collect::<BTreeSet<_>>();
    let capabilities = serde_json::from_value::<Vec<crate::domain::LlmFeatureCapability>>(
        section["allowed_capabilities"].clone(),
    )
    .map_err(|_| ApplicationError::Validation("allowed_capabilities is invalid".to_owned()))?;
    let unique_capabilities = capabilities.iter().copied().collect::<BTreeSet<_>>();
    let routes =
        serde_json::from_value::<Vec<crate::domain::RouteId>>(section["allowed_route_ids"].clone())
            .map_err(|_| ApplicationError::Validation("allowed_route_ids is invalid".to_owned()))?;
    let unique_routes = routes.iter().copied().collect::<BTreeSet<_>>();
    let max_active = section["max_active_keys"].as_u64();
    let max_expiry = section["max_expiry_days"].as_u64();
    let max_overlap = section["max_overlap_seconds"].as_u64();
    let budget = section["budget"].as_object().ok_or_else(|| {
        ApplicationError::Validation("gateway budget ceiling must be an object".to_owned())
    })?;
    let max_budget = budget
        .get("max_limit_cost_nanos")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<u128>().ok());
    let modes = budget
        .get("allowed_modes")
        .cloned()
        .and_then(|value| serde_json::from_value::<Vec<crate::domain::BudgetMode>>(value).ok());
    let rate = section["rate"].as_object().ok_or_else(|| {
        ApplicationError::Validation("gateway rate ceiling must be an object".to_owned())
    })?;
    let concurrency = section["concurrency"].as_object().ok_or_else(|| {
        ApplicationError::Validation("gateway concurrency ceiling must be an object".to_owned())
    })?;
    if scopes.len() != unique_scopes.len()
        || capabilities.len() != unique_capabilities.len()
        || routes.len() != unique_routes.len()
        || !max_active.is_some_and(|value| value <= 10_000)
        || !max_expiry.is_some_and(|value| value <= 3_650)
        || !max_overlap.is_some_and(|value| value <= 86_400)
        || max_budget.is_none()
        || modes.as_ref().is_none_or(|values| {
            values.iter().copied().collect::<BTreeSet<_>>().len() != values.len()
        })
        || rate
            .get("max_requests_per_minute")
            .and_then(Value::as_u64)
            .is_none()
        || rate
            .get("max_input_units_per_minute")
            .and_then(Value::as_u64)
            .is_none()
        || concurrency
            .get("max_limit")
            .and_then(Value::as_u64)
            .is_none()
        || !concurrency
            .get("allowed_modes")
            .is_some_and(Value::is_array)
    {
        return Err(ApplicationError::Validation(
            "gateway key policy ceiling is invalid or outside supported bounds".to_owned(),
        ));
    }
    if enabled
        && (max_active == Some(0)
            || max_expiry == Some(0)
            || max_budget == Some(0)
            || !unique_scopes.contains(&crate::domain::LlmScope::Invoke)
            || unique_routes.is_empty()
            || modes.as_ref().is_none_or(Vec::is_empty))
    {
        return Err(ApplicationError::Validation(
            "enabled gateway key policy requires invoke scope, routes, keys, expiry, budget, and mode ceilings"
                .to_owned(),
        ));
    }
    if !enabled
        && member
        && (!unique_scopes.is_empty()
            || !unique_capabilities.is_empty()
            || !unique_routes.is_empty()
            || max_active != Some(0)
            || max_expiry != Some(0)
            || max_overlap != Some(0)
            || max_budget != Some(0))
    {
        return Err(ApplicationError::Validation(
            "disabled gateway member self-service must have empty zero ceilings".to_owned(),
        ));
    }
    Ok(())
}

fn validate_gateway_policy_subset(global: &Value, member: &Value) -> Result<(), ApplicationError> {
    for field in [
        "allowed_scopes",
        "allowed_capabilities",
        "allowed_route_ids",
    ] {
        let global_values = global[field]
            .as_array()
            .ok_or(ApplicationError::Internal)?
            .iter()
            .map(Value::to_string)
            .collect::<BTreeSet<_>>();
        let member_values = member[field]
            .as_array()
            .ok_or(ApplicationError::Internal)?
            .iter()
            .map(Value::to_string)
            .collect::<BTreeSet<_>>();
        if !member_values.is_subset(&global_values) {
            return Err(ApplicationError::Validation(format!(
                "gateway_member_self_service.{field} must be a subset of gateway.{field}"
            )));
        }
    }
    for field in ["max_active_keys", "max_expiry_days", "max_overlap_seconds"] {
        if member[field].as_u64().ok_or(ApplicationError::Internal)?
            > global[field].as_u64().ok_or(ApplicationError::Internal)?
        {
            return Err(ApplicationError::Validation(format!(
                "gateway_member_self_service.{field} cannot exceed gateway.{field}"
            )));
        }
    }
    let global_budget = global["budget"]["max_limit_cost_nanos"]
        .as_str()
        .and_then(|value| value.parse::<u128>().ok())
        .ok_or(ApplicationError::Internal)?;
    let member_budget = member["budget"]["max_limit_cost_nanos"]
        .as_str()
        .and_then(|value| value.parse::<u128>().ok())
        .ok_or(ApplicationError::Internal)?;
    if member_budget > global_budget {
        return Err(ApplicationError::Validation(
            "gateway member budget ceiling cannot exceed the global ceiling".to_owned(),
        ));
    }
    let global_budget_modes = gateway_policy_budget_modes(global)?;
    let member_budget_modes = gateway_policy_budget_modes(member)?;
    if !member_budget_modes.is_subset(&global_budget_modes) {
        return Err(ApplicationError::Validation(
            "gateway member budget modes must be a subset of the global modes".to_owned(),
        ));
    }
    for path in [
        "rate.max_requests_per_minute",
        "rate.max_input_units_per_minute",
        "concurrency.max_limit",
    ] {
        if gateway_policy_limit(global, member, path)?
            != member
                .pointer(&format!("/{}", path.replace('.', "/")))
                .and_then(Value::as_u64)
                .ok_or(ApplicationError::Internal)?
        {
            return Err(ApplicationError::Validation(format!(
                "gateway member {path} cannot exceed the global ceiling"
            )));
        }
    }
    let global_concurrency_modes = gateway_policy_concurrency_modes(global)?;
    let member_concurrency_modes = gateway_policy_concurrency_modes(member)?;
    if !member_concurrency_modes.is_subset(&global_concurrency_modes) {
        return Err(ApplicationError::Validation(
            "gateway member concurrency modes must be a subset of the global modes".to_owned(),
        ));
    }
    Ok(())
}

fn validate_disabled_member_policy_section(section: &Value) -> Result<(), ApplicationError> {
    if !section["allowed_scopes"]
        .as_array()
        .is_some_and(Vec::is_empty)
        || !section["allowed_capabilities"]
            .as_array()
            .is_some_and(Vec::is_empty)
        || section["max_active_keys"].as_u64() != Some(0)
        || section["max_expiry_days"].as_u64() != Some(0)
        || section["max_overlap_seconds"].as_u64() != Some(0)
    {
        return Err(ApplicationError::Validation(
            "disabled member self-service must have empty zero ceilings".to_owned(),
        ));
    }
    Ok(())
}

fn validate_policy_section(
    section: &Value,
    allow_deployment_capabilities: bool,
) -> Result<(), ApplicationError> {
    let Some(object) = section.as_object() else {
        return Err(ApplicationError::Validation(
            "management key policy section must be an object".to_owned(),
        ));
    };
    let required = BTreeSet::from([
        "allowed_scopes",
        "allowed_capabilities",
        "max_active_keys",
        "max_expiry_days",
        "max_overlap_seconds",
    ]);
    if !required.iter().all(|field| object.contains_key(*field)) {
        return Err(ApplicationError::Validation(
            "management key policy section is incomplete".to_owned(),
        ));
    }
    let scopes = serde_json::from_value::<Vec<ManagementScope>>(section["allowed_scopes"].clone())
        .map_err(|_| ApplicationError::Validation("allowed_scopes is invalid".to_owned()))?;
    let unique_scopes = scopes.iter().copied().collect::<BTreeSet<_>>();
    if scopes.is_empty()
        || unique_scopes.len() != scopes.len()
        || (!allow_deployment_capabilities && unique_scopes.contains(&ManagementScope::Operations))
    {
        return Err(ApplicationError::Validation(
            "allowed_scopes is empty, duplicated, or outside the resource scope".to_owned(),
        ));
    }
    let capabilities =
        serde_json::from_value::<Vec<Capability>>(section["allowed_capabilities"].clone())
            .map_err(|_| {
                ApplicationError::Validation("allowed_capabilities is invalid".to_owned())
            })?;
    let unique_capabilities = capabilities.iter().copied().collect::<BTreeSet<_>>();
    let organization_capabilities = BTreeSet::from([
        Capability::ReadOrganization,
        Capability::UpdateOrganization,
        Capability::ReadMembers,
        Capability::ManageMembers,
        Capability::ManageOwners,
        Capability::ReadManagementKeys,
        Capability::CreateManagementKeys,
        Capability::ManageManagementKeys,
        Capability::UpdateApiKeyPolicy,
        Capability::ReadAudit,
    ]);
    if capabilities.is_empty()
        || unique_capabilities.len() != capabilities.len()
        || (!allow_deployment_capabilities
            && !unique_capabilities.is_subset(&organization_capabilities))
    {
        return Err(ApplicationError::Validation(
            "allowed_capabilities is empty, duplicated, or outside the resource scope".to_owned(),
        ));
    }
    let max_active = section["max_active_keys"].as_u64();
    let max_expiry = section["max_expiry_days"].as_u64();
    let max_overlap = section["max_overlap_seconds"].as_u64();
    if !max_active.is_some_and(|value| (1..=10_000).contains(&value))
        || !max_expiry.is_some_and(|value| (1..=3_650).contains(&value))
        || !max_overlap.is_some_and(|value| value <= 86_400)
    {
        return Err(ApplicationError::Validation(
            "management key policy numeric limits are outside supported bounds".to_owned(),
        ));
    }
    Ok(())
}

fn policy_max_overlap(policy: &Value, class: &str) -> Result<u32, ApplicationError> {
    u32::try_from(effective_policy_limit(
        policy,
        class,
        "max_overlap_seconds",
    )?)
    .map_err(|_| ApplicationError::Internal)
}

fn effective_policy_values(
    policy: &Value,
    class: &str,
    field: &str,
) -> Result<BTreeSet<String>, ApplicationError> {
    let global = policy["management"][field]
        .as_array()
        .ok_or(ApplicationError::Internal)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(ApplicationError::Internal)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if class != "member_self_service" {
        return Ok(global);
    }
    let member = policy["member_self_service"][field]
        .as_array()
        .ok_or(ApplicationError::Internal)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(ApplicationError::Internal)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    Ok(global.intersection(&member).cloned().collect())
}

fn effective_policy_limit(
    policy: &Value,
    class: &str,
    field: &str,
) -> Result<u64, ApplicationError> {
    let global = policy["management"][field]
        .as_u64()
        .ok_or(ApplicationError::Internal)?;
    if class != "member_self_service" {
        return Ok(global);
    }
    let member = policy["member_self_service"][field]
        .as_u64()
        .ok_or(ApplicationError::Internal)?;
    Ok(global.min(member))
}

fn effective_key_expiry(
    policy: &Value,
    class: &str,
    requested: Option<DateTime<Utc>>,
    issued_at: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>, ApplicationError> {
    let max_days = effective_policy_limit(policy, class, "max_expiry_days")?;
    let policy_expiry = issued_at
        + Duration::days(i64::try_from(max_days).map_err(|_| ApplicationError::Internal)?);
    Ok(Some(
        requested.map_or(policy_expiry, |expiry| expiry.min(policy_expiry)),
    ))
}

async fn load_deployment_policy<'executor>(
    executor: impl Executor<'executor, Database = Postgres>,
    installation_id: Uuid,
) -> Result<(DeploymentManagementKeyPolicy, EntityTag), ApplicationError> {
    let row = sqlx::query(
        "SELECT policy, etag_token, updated_at
         FROM deployment_management_key_policy WHERE singleton=true",
    )
    .fetch_one(executor)
    .await?;
    let etag = EntityTag::for_resource(
        "deployment_management_key_policy",
        installation_id,
        row.try_get("etag_token")?,
    );
    Ok((
        DeploymentManagementKeyPolicy {
            policy: row.try_get("policy")?,
            updated_at: row.try_get("updated_at")?,
        },
        etag,
    ))
}

async fn load_organization_policy<'executor>(
    executor: impl Executor<'executor, Database = Postgres>,
    organization_id: OrganizationId,
) -> Result<(OrganizationApiKeyPolicy, EntityTag), ApplicationError> {
    let row = sqlx::query(
        "SELECT policy, etag_token, updated_at FROM organization_api_key_policies
         WHERE organization_id=$1",
    )
    .bind(organization_id.as_uuid())
    .fetch_optional(executor)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    let etag = EntityTag::for_resource(
        "organization_api_key_policy",
        organization_id.as_uuid(),
        row.try_get("etag_token")?,
    );
    Ok((
        OrganizationApiKeyPolicy {
            organization_id,
            policy: row.try_get("policy")?,
            updated_at: row.try_get("updated_at")?,
        },
        etag,
    ))
}

fn key_audit(
    identity: &RequestIdentity,
    scope: &ResourceScope,
    key_id: KeyId,
    operation: &str,
    changed_fields: &[&str],
) -> AuditRecord {
    AuditRecord {
        actor: Some(Actor::from(&identity.principal)),
        authentication_evidence: json!({
            "method": identity.principal.authentication_method,
            "session_id": identity.principal.session_id,
        }),
        organization_id: match scope {
            ResourceScope::Deployment => None,
            ResourceScope::Organization { organization_id } => Some(*organization_id),
        },
        target_resource_kind: "management_api_key".to_owned(),
        target_resource_id: Some(key_id.to_string()),
        operation_id: operation.to_owned(),
        outcome: "accepted",
        request_id: identity.request_id.clone(),
        changed_fields: changed_fields
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        safe_details: json!({"resource_scope":scope}),
    }
}

fn key_event(scope: &ResourceScope, key_id: KeyId, security_tightening: bool) -> RuntimeEvent {
    RuntimeEvent {
        event_kind: "management_api_key.changed".to_owned(),
        affected_scope: json!({"resource_scope":scope,"management_api_key_id":key_id}),
        security_tightening,
    }
}

fn scope_columns(scope: &ResourceScope) -> (&'static str, Option<Uuid>) {
    match scope {
        ResourceScope::Deployment => ("deployment", None),
        ResourceScope::Organization { organization_id } => {
            ("organization", Some(organization_id.as_uuid()))
        }
    }
}

fn scopes_value(scopes: &ManagementScopeSet) -> Value {
    json!(
        scopes
            .iter()
            .map(ManagementScope::as_str)
            .collect::<Vec<_>>()
    )
}

fn scopes_from_value(value: Value) -> Result<ManagementScopeSet, ApplicationError> {
    let values = value
        .as_array()
        .ok_or(ApplicationError::Internal)?
        .iter()
        .map(|value| value.as_str().ok_or(ApplicationError::Internal))
        .collect::<Result<Vec<_>, _>>()?;
    let scopes = values
        .into_iter()
        .map(|value| {
            value
                .parse::<ManagementScope>()
                .map_err(|_| ApplicationError::Internal)
        })
        .collect::<Result<Vec<_>, _>>()?;
    ManagementScopeSet::new(scopes).map_err(|_| ApplicationError::Internal)
}

fn safe_key_prefix(lookup: &str) -> String {
    format!("owlrora_mgmt_v1.{}", &lookup[..lookup.len().min(8)])
}

fn validate_key_name(name: &str) -> Result<(), ApplicationError> {
    let name = name.trim();
    if name.is_empty() || name.len() > 160 || name.chars().any(char::is_control) {
        Err(ApplicationError::Validation(
            "key name must contain 1 to 160 safe characters".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn parse_key_status(value: &str) -> Result<KeyStatus, ApplicationError> {
    match value {
        "active" => Ok(KeyStatus::Active),
        "disabled" => Ok(KeyStatus::Disabled),
        "revoked" => Ok(KeyStatus::Revoked),
        _ => Err(ApplicationError::Internal),
    }
}

fn expiry_extended(current: Option<DateTime<Utc>>, candidate: Option<DateTime<Utc>>) -> bool {
    match (current, candidate) {
        (Some(current), Some(candidate)) => candidate > current,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

fn expiry_shortened(current: Option<DateTime<Utc>>, candidate: Option<DateTime<Utc>>) -> bool {
    match (current, candidate) {
        (Some(current), Some(candidate)) => candidate < current,
        (None, Some(_)) => true,
        _ => false,
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

impl Capability {
    const ALL_NAMES: &'static [&'static str] = &[
        "system_administration",
        "read_organization",
        "update_organization",
        "read_members",
        "manage_members",
        "manage_owners",
        "read_management_keys",
        "create_management_keys",
        "manage_management_keys",
        "update_api_key_policy",
        "read_audit",
        "manage_identity",
        "manage_system_keys",
        "manage_system_organizations",
        "manage_system_users",
        "manage_administrators",
        "read_operations",
        "recover_operations",
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_member_policy_cannot_exceed_global_rate_or_mode_ceilings() {
        let policy = crate::application::resources::default_organization_api_key_policy();
        let global = policy["gateway"].clone();
        let mut member = global.clone();
        member["rate"]["max_requests_per_minute"] =
            json!(global["rate"]["max_requests_per_minute"].as_u64().unwrap() + 1);
        assert!(validate_gateway_policy_subset(&global, &member).is_err());

        let mut member = global.clone();
        member["concurrency"]["allowed_modes"] = json!(["approximate", "strict"]);
        let mut narrowed_global = global;
        narrowed_global["concurrency"]["allowed_modes"] = json!(["strict"]);
        assert!(validate_gateway_policy_subset(&narrowed_global, &member).is_err());
    }

    #[test]
    fn organization_keys_cannot_request_operations_scope() {
        let scopes =
            ManagementScopeSet::new([ManagementScope::Read, ManagementScope::Operations]).unwrap();
        assert!(
            validate_requested_scopes(
                &ResourceScope::Organization {
                    organization_id: OrganizationId::new()
                },
                &scopes
            )
            .is_err()
        );
    }

    #[test]
    fn local_admin_cannot_mint_owner_capabilities_from_a_wider_issuer_ceiling() {
        use std::{collections::BTreeMap, sync::Arc};

        use crate::{
            domain::{AuthenticatedPrincipal, AuthenticationMethod, Principal, UserId},
            runtime::{IdentitySnapshot, RuntimeGeneration, RuntimeSnapshot},
        };

        let organization_id = OrganizationId::new();
        let admin_capabilities = BTreeSet::from([
            Capability::ReadOrganization,
            Capability::UpdateOrganization,
            Capability::ReadMembers,
            Capability::ManageMembers,
            Capability::ReadManagementKeys,
            Capability::CreateManagementKeys,
            Capability::ManageManagementKeys,
            Capability::UpdateApiKeyPolicy,
            Capability::ReadAudit,
        ]);
        let identity = RequestIdentity {
            principal: AuthenticatedPrincipal {
                principal: Principal::LocalUser {
                    user_id: UserId::new(),
                },
                authentication_method: AuthenticationMethod::ExternalSession,
                effective_management_scopes: ManagementScopeSet::all(),
                credential_capability_ceiling: Capability::ALL.into_iter().collect(),
                effective_system_administrator: false,
                effective_organization_capabilities: BTreeMap::from([(
                    organization_id,
                    admin_capabilities,
                )]),
                resource_scope: ResourceScope::Deployment,
                session_id: None,
                accepted_key_version_id: None,
                external_issuer_id: None,
                external_subject: None,
                management_organization_ceiling: Some(vec![organization_id]),
            },
            generation: Arc::new(RuntimeGeneration {
                snapshot: Arc::new(RuntimeSnapshot {
                    revision: 0,
                    security_revision: 0,
                    built_at: Utc::now(),
                    compatibility_registry_version: 1,
                    gateway_policy_ceilings: crate::runtime::GatewayPolicyCeilingsSnapshot::default(
                    ),
                    identity: IdentitySnapshot::default(),
                    gateway_keys: std::collections::HashMap::new(),
                    organizations: std::collections::HashMap::new(),
                    policy_activations: std::collections::HashMap::new(),
                    catalog: crate::runtime::CatalogSnapshot::default(),
                }),
                credential_clients: Arc::new(crate::runtime::CredentialClientRegistry::default()),
            }),
            request_id: "test-request".to_owned(),
            csrf_validated: true,
        };
        let result = ensure_target_dominance(
            &identity,
            &ResourceScope::Organization { organization_id },
            &ManagementScopeSet::new([ManagementScope::Read]).unwrap(),
            &BTreeSet::from([Capability::ManageOwners.as_str().to_owned()]),
            None,
        );
        assert!(matches!(result, Err(ApplicationError::Forbidden)));
    }

    #[test]
    fn member_self_service_projection_is_policy_and_capacity_bounded() {
        let mut policy = crate::application::resources::default_organization_api_key_policy();
        policy["member_self_service"] = json!({
            "management_key_creation": true,
            "allowed_scopes": ["management:read", "management:secrets"],
            "allowed_capabilities": ["read_organization"],
            "max_active_keys": 2,
            "max_expiry_days": 30,
            "max_overlap_seconds": 0
        });
        let available = management_key_self_service_eligibility(&policy, 1, 10).unwrap();
        assert!(available.eligible);
        assert_eq!(
            available.allowed_scopes,
            ["management:read", "management:secrets"]
        );
        assert_eq!(available.allowed_capabilities, ["read_organization"]);
        assert_eq!(available.max_expiry_days, 30);
        assert_eq!(available.max_active_keys, 2);
        assert_eq!(available.active_keys, 1);
        assert!(
            !management_key_self_service_eligibility(&policy, 2, 10)
                .unwrap()
                .eligible
        );
        assert!(
            !management_key_self_service_eligibility(&policy, 1, 100)
                .unwrap()
                .eligible
        );
    }

    #[test]
    fn expiry_changes_are_directional() {
        let now = Utc::now();
        assert!(expiry_extended(Some(now), None));
        assert!(expiry_shortened(None, Some(now)));
        assert!(!expiry_extended(None, Some(now)));
    }

    #[test]
    fn key_expiry_horizon_is_anchored_to_issuance() {
        let issued_at = Utc::now() - Duration::days(30);
        let policy = json!({
            "management": {
                "max_expiry_days": 7
            }
        });
        let effective = effective_key_expiry(
            &policy,
            "standard",
            Some(Utc::now() + Duration::days(6)),
            issued_at,
        )
        .unwrap();
        assert_eq!(effective, Some(issued_at + Duration::days(7)));
    }

    #[test]
    fn administrator_cursors_preserve_the_stable_tuple() {
        let cursor = AdministratorCursor {
            created_at: Some(Utc::now()),
            id: Some(Uuid::now_v7()),
        };
        let encoded = encode_administrator_cursor(&cursor).unwrap();
        let decoded = decode_administrator_cursor(&encoded).unwrap();
        assert_eq!(decoded.created_at, cursor.created_at);
        assert_eq!(decoded.id, cursor.id);
    }
}
