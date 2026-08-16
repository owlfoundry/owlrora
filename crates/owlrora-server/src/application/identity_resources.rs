use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::{
    adapters::postgres::{AuditRecord, RuntimeEvent},
    domain::{
        Actor, BindingId, Capability, IssuerId, ManagementScope, OrganizationId, OrganizationRole,
        PolicyId, ResourceScope, UserId,
    },
    runtime::{ExternalIssuerSnapshot, MembershipSnapshot, RuntimeGeneration},
};

use super::{
    Application, ApplicationError, AuthorizationTarget, CreateExternalIdentityBinding,
    CreateProvisioningPolicy, EntityTag, ExternalIdentityBinding, IdempotencyDecision,
    IdempotentCommand, Page, ProvisioningPolicy, RelinkExternalIdentityBinding, RequestIdentity,
    UpdateField, UpdateProvisioningPolicy,
};

#[derive(Debug, Deserialize)]
struct OnboardingConfiguration {
    allow_user_creation: bool,
    #[serde(default)]
    claim_predicates: Vec<OnboardingClaimPredicate>,
    display_name_claim: Option<String>,
    email_claim: Option<String>,
    #[serde(default)]
    create_personal_organization: bool,
    #[serde(default)]
    organization_mappings: Vec<OnboardingOrganizationMapping>,
}

#[derive(Debug, Deserialize)]
struct OnboardingClaimPredicate {
    claim: String,
    operator: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct OnboardingOrganizationMapping {
    claim: String,
    value: String,
    organization_id: OrganizationId,
    maximum_role: OrganizationRole,
}

impl Application {
    pub async fn list_external_identity_bindings(
        &self,
        identity: &RequestIdentity,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<ExternalIdentityBinding>, ApplicationError> {
        authorize_identity_read(self, identity)?;
        let family = "identity_bindings";
        let (cursor, limit) = super::resources::page_parameters(family, cursor, limit)?;
        let rows = sqlx::query(
            "SELECT id, issuer_id, external_subject, user_id, status, created_at, updated_at
             FROM external_identity_bindings
             WHERE ($1::uuid IS NULL OR id < $1)
             ORDER BY id DESC LIMIT $2",
        )
        .bind(cursor)
        .bind(i64::from(limit) + 1)
        .fetch_all(self.store.pool())
        .await?;
        super::resources::page_from_rows(rows, limit, family, |row| binding_from_row(&row))
    }

    pub async fn get_external_identity_binding(
        &self,
        identity: &RequestIdentity,
        binding_id: BindingId,
    ) -> Result<(ExternalIdentityBinding, EntityTag), ApplicationError> {
        authorize_identity_read(self, identity)?;
        load_binding(self.store.pool(), binding_id).await
    }

    pub async fn create_external_identity_binding(
        &self,
        identity: &RequestIdentity,
        input: CreateExternalIdentityBinding,
        idempotency_key: Option<&str>,
    ) -> Result<IdempotentCommand<(ExternalIdentityBinding, EntityTag)>, ApplicationError> {
        authorize_identity_write(self, identity)?;
        validate_external_subject(&input.external_subject)?;
        let binding_id = BindingId::new();
        let mut transaction = self.store.begin().await?;
        let handle = match self
            .begin_idempotent_command(
                &mut transaction,
                identity,
                &ResourceScope::Deployment,
                "system.identity_bindings.create",
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
        lock_external_subject(&mut transaction, input.issuer_id, &input.external_subject).await?;
        require_issuer_and_user(&mut transaction, input.issuer_id, input.user_id).await?;
        let existing = sqlx::query(
            "SELECT id, status FROM external_identity_bindings
             WHERE issuer_id=$1 AND external_subject=$2 FOR UPDATE",
        )
        .bind(input.issuer_id.as_uuid())
        .bind(&input.external_subject)
        .fetch_optional(&mut *transaction)
        .await?;
        let (binding_id, operation, changed_fields) = if let Some(existing) = existing {
            if existing.try_get::<String, _>("status")? == "active" {
                return Err(ApplicationError::Conflict(
                    "issuer subject already has an active binding".to_owned(),
                ));
            }
            let existing_id = BindingId::from_uuid(existing.try_get("id")?);
            sqlx::query(
                "UPDATE external_identity_bindings
                 SET user_id=$2, status='active', etag_token=$3, updated_at=now()
                 WHERE id=$1",
            )
            .bind(existing_id.as_uuid())
            .bind(input.user_id.as_uuid())
            .bind(Uuid::now_v7())
            .execute(&mut *transaction)
            .await?;
            (
                existing_id,
                "identity_bindings.reactivate",
                vec!["user_id", "status"],
            )
        } else {
            sqlx::query(
                "INSERT INTO external_identity_bindings(
                    id, issuer_id, external_subject, user_id, status,
                    created_by_principal, etag_token
                 ) VALUES ($1,$2,$3,$4,'active',$5,$6)",
            )
            .bind(binding_id.as_uuid())
            .bind(input.issuer_id.as_uuid())
            .bind(&input.external_subject)
            .bind(input.user_id.as_uuid())
            .bind(
                serde_json::to_value(&identity.principal.principal)
                    .map_err(|_| ApplicationError::Internal)?,
            )
            .bind(Uuid::now_v7())
            .execute(&mut *transaction)
            .await?;
            (
                binding_id,
                "identity_bindings.create",
                vec!["issuer_id", "external_subject", "user_id"],
            )
        };
        let result = load_binding(&mut *transaction, binding_id).await?;
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
                &identity_resource_audit(
                    identity,
                    "external_identity_binding",
                    binding_id.to_string(),
                    operation,
                    &changed_fields,
                ),
                Some(&binding_event(binding_id, false)),
            )
            .await?;
        self.publish_committed_runtime(&identity.request_id, "identity_bindings.create")
            .await;
        Ok(IdempotentCommand::Executed(result))
    }

    pub async fn relink_external_identity_binding(
        &self,
        identity: &RequestIdentity,
        binding_id: BindingId,
        if_match: Option<&str>,
        input: RelinkExternalIdentityBinding,
    ) -> Result<(ExternalIdentityBinding, EntityTag), ApplicationError> {
        authorize_identity_write(self, identity)?;
        let mut transaction = self.store.begin().await?;
        lock_binding_subject(&mut transaction, binding_id).await?;
        let row = sqlx::query(
            "SELECT issuer_id, external_subject, status, etag_token
             FROM external_identity_bindings WHERE id=$1 FOR UPDATE",
        )
        .bind(binding_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        require_if_match(
            if_match,
            &EntityTag::for_resource(
                "external_identity_binding",
                binding_id.as_uuid(),
                row.try_get("etag_token")?,
            ),
        )?;
        if row.try_get::<String, _>("status")? != "active" {
            return Err(ApplicationError::Conflict(
                "only active bindings can be relinked".to_owned(),
            ));
        }
        require_issuer_and_user(
            &mut transaction,
            IssuerId::from_uuid(row.try_get("issuer_id")?),
            input.user_id,
        )
        .await?;
        sqlx::query(
            "UPDATE external_identity_bindings
             SET user_id=$2, etag_token=$3, updated_at=now() WHERE id=$1",
        )
        .bind(binding_id.as_uuid())
        .bind(input.user_id.as_uuid())
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        revoke_external_sessions(
            &mut transaction,
            IssuerId::from_uuid(row.try_get("issuer_id")?),
            Some(row.try_get::<String, _>("external_subject")?),
        )
        .await?;
        let result = load_binding(&mut *transaction, binding_id).await?;
        self.store
            .commit_command(
                transaction,
                &identity_resource_audit(
                    identity,
                    "external_identity_binding",
                    binding_id.to_string(),
                    "identity_bindings.relink",
                    &["user_id"],
                ),
                Some(&binding_event(binding_id, true)),
            )
            .await?;
        self.publish_committed_runtime(&identity.request_id, "identity_bindings.relink")
            .await;
        Ok(result)
    }

    pub async fn remove_external_identity_binding(
        &self,
        identity: &RequestIdentity,
        binding_id: BindingId,
        if_match: Option<&str>,
    ) -> Result<(ExternalIdentityBinding, EntityTag), ApplicationError> {
        authorize_identity_write(self, identity)?;
        let mut transaction = self.store.begin().await?;
        lock_binding_subject(&mut transaction, binding_id).await?;
        let row = sqlx::query(
            "SELECT issuer_id, external_subject, status, etag_token
             FROM external_identity_bindings WHERE id=$1 FOR UPDATE",
        )
        .bind(binding_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        require_if_match(
            if_match,
            &EntityTag::for_resource(
                "external_identity_binding",
                binding_id.as_uuid(),
                row.try_get("etag_token")?,
            ),
        )?;
        if row.try_get::<String, _>("status")? != "active" {
            return Err(ApplicationError::Conflict(
                "binding is already removed".to_owned(),
            ));
        }
        sqlx::query(
            "UPDATE external_identity_bindings
             SET status='removed', etag_token=$2, updated_at=now() WHERE id=$1",
        )
        .bind(binding_id.as_uuid())
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        revoke_external_sessions(
            &mut transaction,
            IssuerId::from_uuid(row.try_get("issuer_id")?),
            Some(row.try_get::<String, _>("external_subject")?),
        )
        .await?;
        let result = load_binding(&mut *transaction, binding_id).await?;
        self.store
            .commit_command(
                transaction,
                &identity_resource_audit(
                    identity,
                    "external_identity_binding",
                    binding_id.to_string(),
                    "identity_bindings.remove",
                    &["status"],
                ),
                Some(&binding_event(binding_id, true)),
            )
            .await?;
        self.publish_committed_runtime(&identity.request_id, "identity_bindings.remove")
            .await;
        Ok(result)
    }

    pub async fn list_provisioning_policies(
        &self,
        identity: &RequestIdentity,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<ProvisioningPolicy>, ApplicationError> {
        authorize_identity_read(self, identity)?;
        let family = "provisioning_policies";
        let (cursor, limit) = super::resources::page_parameters(family, cursor, limit)?;
        let rows = sqlx::query(
            "SELECT id, name, status, user_kind, configuration, created_at, updated_at
             FROM provisioning_policies
             WHERE ($1::uuid IS NULL OR id < $1)
             ORDER BY id DESC LIMIT $2",
        )
        .bind(cursor)
        .bind(i64::from(limit) + 1)
        .fetch_all(self.store.pool())
        .await?;
        super::resources::page_from_rows(rows, limit, family, |row| policy_from_row(&row))
    }

    pub async fn get_provisioning_policy(
        &self,
        identity: &RequestIdentity,
        policy_id: PolicyId,
    ) -> Result<(ProvisioningPolicy, EntityTag), ApplicationError> {
        authorize_identity_read(self, identity)?;
        load_policy(self.store.pool(), policy_id).await
    }

    pub async fn create_provisioning_policy(
        &self,
        identity: &RequestIdentity,
        input: CreateProvisioningPolicy,
        idempotency_key: Option<&str>,
    ) -> Result<IdempotentCommand<(ProvisioningPolicy, EntityTag)>, ApplicationError> {
        authorize_identity_write(self, identity)?;
        validate_policy_name(&input.name)?;
        validate_policy_status(&input.status)?;
        validate_provisioning_configuration(&input.configuration)?;
        let policy_id = PolicyId::new();
        let mut transaction = self.store.begin().await?;
        let handle = match self
            .begin_idempotent_command(
                &mut transaction,
                identity,
                &ResourceScope::Deployment,
                "system.provisioning_policies.create",
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
            "INSERT INTO provisioning_policies(
                id, name, status, user_kind, configuration, created_by_principal, etag_token
             ) VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(policy_id.as_uuid())
        .bind(&input.name)
        .bind(&input.status)
        .bind(input.user_kind.as_str())
        .bind(&input.configuration)
        .bind(
            serde_json::to_value(&identity.principal.principal)
                .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let result = load_policy(&mut *transaction, policy_id).await?;
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
                &identity_resource_audit(
                    identity,
                    "provisioning_policy",
                    policy_id.to_string(),
                    "provisioning_policies.create",
                    &["name", "status", "user_kind", "configuration"],
                ),
                Some(&policy_event(policy_id, false)),
            )
            .await?;
        self.publish_committed_runtime(&identity.request_id, "provisioning_policies.create")
            .await;
        Ok(IdempotentCommand::Executed(result))
    }

    pub async fn update_provisioning_policy(
        &self,
        identity: &RequestIdentity,
        policy_id: PolicyId,
        if_match: Option<&str>,
        input: UpdateProvisioningPolicy,
    ) -> Result<(ProvisioningPolicy, EntityTag), ApplicationError> {
        authorize_identity_write(self, identity)?;
        if input.name.is_omitted()
            && input.status.is_omitted()
            && input.user_kind.is_omitted()
            && input.configuration.is_omitted()
        {
            return Err(ApplicationError::Validation(
                "at least one provisioning policy field must be updated".to_owned(),
            ));
        }
        let mut transaction = self.store.begin().await?;
        let row = sqlx::query(
            "SELECT name, status, user_kind, configuration, etag_token
             FROM provisioning_policies WHERE id=$1 FOR UPDATE",
        )
        .bind(policy_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        require_if_match(
            if_match,
            &EntityTag::for_resource(
                "provisioning_policy",
                policy_id.as_uuid(),
                row.try_get("etag_token")?,
            ),
        )?;
        let mut name: String = row.try_get("name")?;
        let mut status: String = row.try_get("status")?;
        let mut user_kind = match row.try_get::<String, _>("user_kind")?.as_str() {
            "human" => super::UserKind::Human,
            "synthetic" => super::UserKind::Synthetic,
            _ => return Err(ApplicationError::Internal),
        };
        let mut configuration: Value = row.try_get("configuration")?;
        apply_required(&mut name, input.name, "name")?;
        apply_required(&mut status, input.status, "status")?;
        apply_required(&mut user_kind, input.user_kind, "user_kind")?;
        apply_required(&mut configuration, input.configuration, "configuration")?;
        validate_policy_name(&name)?;
        validate_policy_status(&status)?;
        validate_provisioning_configuration(&configuration)?;
        sqlx::query(
            "UPDATE provisioning_policies SET
                name=$2, status=$3, user_kind=$4, configuration=$5,
                etag_token=$6, updated_at=now() WHERE id=$1",
        )
        .bind(policy_id.as_uuid())
        .bind(&name)
        .bind(&status)
        .bind(user_kind.as_str())
        .bind(&configuration)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let result = load_policy(&mut *transaction, policy_id).await?;
        self.store
            .commit_command(
                transaction,
                &identity_resource_audit(
                    identity,
                    "provisioning_policy",
                    policy_id.to_string(),
                    "provisioning_policies.update",
                    &["policy"],
                ),
                Some(&policy_event(policy_id, true)),
            )
            .await?;
        self.publish_committed_runtime(&identity.request_id, "provisioning_policies.update")
            .await;
        Ok(result)
    }

    pub(crate) async fn provision_oidc_subject(
        &self,
        issuer: &ExternalIssuerSnapshot,
        external_subject: &str,
        claims: &Value,
        request_id: &str,
        base_generation: &Arc<RuntimeGeneration>,
    ) -> Result<Arc<RuntimeGeneration>, ApplicationError> {
        let policy_id = issuer
            .provisioning_policy_id
            .ok_or(ApplicationError::InvalidCredential)?;
        let mut transaction = self.store.begin().await?;
        lock_external_subject(&mut transaction, issuer.id, external_subject).await?;
        if let Some(existing) = sqlx::query_scalar::<_, Uuid>(
            "SELECT user_id FROM external_identity_bindings
             WHERE issuer_id=$1 AND external_subject=$2 AND status='active'",
        )
        .bind(issuer.id.as_uuid())
        .bind(external_subject)
        .fetch_optional(&mut *transaction)
        .await?
        {
            let generation = oidc_subject_generation(
                &mut transaction,
                base_generation,
                issuer.id,
                external_subject,
                UserId::from_uuid(existing),
            )
            .await?;
            transaction.rollback().await?;
            return Ok(generation);
        }
        let current_issuer = sqlx::query(
            "SELECT status, policy_version, provisioning_policy_id
             FROM external_identity_issuers WHERE id=$1 FOR UPDATE",
        )
        .bind(issuer.id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::InvalidCredential)?;
        if current_issuer.try_get::<String, _>("status")? != "active"
            || current_issuer.try_get::<i64, _>("policy_version")? != issuer.policy_version
            || current_issuer.try_get::<Option<Uuid>, _>("provisioning_policy_id")?
                != Some(policy_id.as_uuid())
        {
            return Err(ApplicationError::InvalidCredential);
        }
        let policy = sqlx::query(
            "SELECT status, user_kind, configuration
             FROM provisioning_policies WHERE id=$1 FOR UPDATE",
        )
        .bind(policy_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::InvalidCredential)?;
        if policy.try_get::<String, _>("status")? != "active" {
            return Err(ApplicationError::InvalidCredential);
        }
        let user_kind: String = policy.try_get("user_kind")?;
        let configuration =
            serde_json::from_value::<OnboardingConfiguration>(policy.try_get("configuration")?)
                .map_err(|_| ApplicationError::Internal)?;
        if !configuration.allow_user_creation
            || !configuration
                .claim_predicates
                .iter()
                .all(|predicate| onboarding_predicate_matches(claims, predicate))
        {
            return Err(ApplicationError::InvalidCredential);
        }
        let display_name = configuration
            .display_name_claim
            .as_deref()
            .and_then(|claim| onboarding_claim_value(claims, claim))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty() && value.len() <= 160)
            .map(|value| value.trim().to_owned())
            .unwrap_or_else(|| "External user".to_owned());
        let primary_email = configuration
            .email_claim
            .as_deref()
            .and_then(|claim| onboarding_claim_value(claims, claim))
            .and_then(Value::as_str)
            .filter(|value| {
                (3..=320).contains(&value.len())
                    && value.contains('@')
                    && !value.chars().any(char::is_control)
            })
            .map(str::to_owned);
        let provisioning_actor = json!({
            "kind": "external_identity_provisioning",
            "issuer_id": issuer.id,
            "policy_id": policy_id,
        });
        let user_id = UserId::new();
        sqlx::query(
            "INSERT INTO users(
                id, kind, status, display_name, primary_email, created_by_principal, etag_token
             ) VALUES ($1,$2,'active',$3,$4,$5,$6)",
        )
        .bind(user_id.as_uuid())
        .bind(&user_kind)
        .bind(&display_name)
        .bind(primary_email)
        .bind(&provisioning_actor)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let binding_id = BindingId::new();
        sqlx::query(
            "INSERT INTO external_identity_bindings(
                id, issuer_id, external_subject, user_id, status,
                created_by_principal, etag_token
             ) VALUES ($1,$2,$3,$4,'active',$5,$6)",
        )
        .bind(binding_id.as_uuid())
        .bind(issuer.id.as_uuid())
        .bind(external_subject)
        .bind(user_id.as_uuid())
        .bind(&provisioning_actor)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        if configuration.create_personal_organization {
            let organization_id = OrganizationId::new();
            sqlx::query(
                "INSERT INTO organizations(
                    id, kind, status, name, slug, created_by_principal, etag_token
                 ) VALUES ($1,'ordinary','active',$2,NULL,$3,$4)",
            )
            .bind(organization_id.as_uuid())
            .bind(format!(
                "{} organization",
                display_name.chars().take(147).collect::<String>()
            ))
            .bind(&provisioning_actor)
            .bind(Uuid::now_v7())
            .execute(&mut *transaction)
            .await?;
            insert_provisioned_membership(
                &mut transaction,
                organization_id,
                user_id,
                OrganizationRole::Owner,
                &provisioning_actor,
            )
            .await?;
            sqlx::query(
                "INSERT INTO organization_api_key_policies(organization_id, policy, etag_token)
                 VALUES ($1,$2,$3)",
            )
            .bind(organization_id.as_uuid())
            .bind(super::resources::default_organization_api_key_policy())
            .bind(Uuid::now_v7())
            .execute(&mut *transaction)
            .await?;
        }
        for mapping in &configuration.organization_mappings {
            if !onboarding_claim_contains(claims, &mapping.claim, &mapping.value) {
                continue;
            }
            let active = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(
                    SELECT 1 FROM organizations WHERE id=$1 AND status='active'
                 )",
            )
            .bind(mapping.organization_id.as_uuid())
            .fetch_one(&mut *transaction)
            .await?;
            if !active {
                return Err(ApplicationError::InvalidCredential);
            }
            insert_provisioned_membership(
                &mut transaction,
                mapping.organization_id,
                user_id,
                mapping.maximum_role,
                &provisioning_actor,
            )
            .await?;
        }
        // Build the exact post-provision identity view before commit. The callback must not
        // depend on eventual runtime publication after this point: a failed refresh may leave
        // the shared generation stale, but it must not turn durable onboarding into login failure.
        let callback_generation = oidc_subject_generation(
            &mut transaction,
            base_generation,
            issuer.id,
            external_subject,
            user_id,
        )
        .await?;
        self.store
            .commit_command(
                transaction,
                &AuditRecord {
                    actor: None,
                    authentication_evidence: json!({
                        "method":"oidc_onboarding",
                        "issuer_id":issuer.id,
                        "policy_id":policy_id,
                    }),
                    organization_id: None,
                    target_resource_kind: "external_identity_binding".to_owned(),
                    target_resource_id: Some(binding_id.to_string()),
                    operation_id: "external_identity.onboarding.provision".to_owned(),
                    outcome: "accepted",
                    request_id: request_id.to_owned(),
                    changed_fields: vec![
                        "user".to_owned(),
                        "binding".to_owned(),
                        "memberships".to_owned(),
                    ],
                    safe_details: json!({"issuer_id":issuer.id,"policy_id":policy_id}),
                },
                Some(&RuntimeEvent {
                    event_kind: "external_identity.onboarding_provisioned".to_owned(),
                    affected_scope: json!({"issuer_id":issuer.id,"user_id":user_id}),
                    security_tightening: false,
                }),
            )
            .await?;
        self.publish_committed_runtime(request_id, "external_identity.onboarding.provision")
            .await;
        Ok(callback_generation)
    }
}

async fn lock_binding_subject(
    transaction: &mut Transaction<'_, Postgres>,
    binding_id: BindingId,
) -> Result<(), ApplicationError> {
    let row = sqlx::query(
        "SELECT issuer_id, external_subject FROM external_identity_bindings WHERE id=$1",
    )
    .bind(binding_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    lock_external_subject(
        transaction,
        IssuerId::from_uuid(row.try_get("issuer_id")?),
        &row.try_get::<String, _>("external_subject")?,
    )
    .await
}

async fn lock_external_subject(
    transaction: &mut Transaction<'_, Postgres>,
    issuer_id: IssuerId,
    external_subject: &str,
) -> Result<(), ApplicationError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(external_subject_lock_key(issuer_id, external_subject))
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

fn external_subject_lock_key(issuer_id: IssuerId, external_subject: &str) -> String {
    format!("external-identity-subject:{issuer_id}:{external_subject}")
}

async fn oidc_subject_generation(
    transaction: &mut Transaction<'_, Postgres>,
    base_generation: &Arc<RuntimeGeneration>,
    issuer_id: IssuerId,
    external_subject: &str,
    user_id: UserId,
) -> Result<Arc<RuntimeGeneration>, ApplicationError> {
    let user_active = sqlx::query_scalar::<_, String>("SELECT status FROM users WHERE id=$1")
        .bind(user_id.as_uuid())
        .fetch_one(&mut **transaction)
        .await?
        == "active";
    let system_administrator = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
            SELECT 1 FROM system_administrator_grants
            WHERE subject_kind='local_user' AND user_id=$1 AND status='active'
         )",
    )
    .bind(user_id.as_uuid())
    .fetch_one(&mut **transaction)
    .await?;
    let membership_rows = sqlx::query(
        "SELECT m.id, m.organization_id, m.role, m.llm_scope_ceiling,
                m.llm_capability_ceiling, m.llm_route_ceiling, o.status
         FROM memberships m
         JOIN organizations o ON o.id=m.organization_id
         WHERE m.user_id=$1 AND m.status='active'",
    )
    .bind(user_id.as_uuid())
    .fetch_all(&mut **transaction)
    .await?;
    let memberships = membership_rows
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get::<Uuid, _>("id")?,
                OrganizationId::from_uuid(row.try_get("organization_id")?),
                parse_organization_role(&row.try_get::<String, _>("role")?)?,
                serde_json::from_value(row.try_get("llm_scope_ceiling")?)
                    .map_err(|_| ApplicationError::Internal)?,
                serde_json::from_value(row.try_get("llm_capability_ceiling")?)
                    .map_err(|_| ApplicationError::Internal)?,
                serde_json::from_value(row.try_get("llm_route_ceiling")?)
                    .map_err(|_| ApplicationError::Internal)?,
                row.try_get::<String, _>("status")? == "active",
            ))
        })
        .collect::<Result<Vec<_>, ApplicationError>>()?;
    Ok(patch_oidc_subject_generation(
        base_generation,
        issuer_id,
        external_subject,
        user_id,
        user_active,
        system_administrator,
        &memberships,
    ))
}

fn patch_oidc_subject_generation(
    base_generation: &Arc<RuntimeGeneration>,
    issuer_id: IssuerId,
    external_subject: &str,
    user_id: UserId,
    user_active: bool,
    system_administrator: bool,
    memberships: &[(
        Uuid,
        OrganizationId,
        OrganizationRole,
        crate::domain::LlmScopeCeiling,
        std::collections::BTreeSet<crate::domain::LlmFeatureCapability>,
        crate::domain::JwtRouteCeiling,
        bool,
    )],
) -> Arc<RuntimeGeneration> {
    let mut snapshot = (*base_generation.snapshot).clone();
    let identity = &mut snapshot.identity;
    identity.active_users.insert(user_id, user_active);
    identity
        .external_bindings
        .insert((issuer_id, external_subject.to_owned()), user_id);
    if system_administrator {
        identity.system_administrator_users.insert(user_id, true);
    } else {
        identity.system_administrator_users.remove(&user_id);
    }
    identity
        .memberships
        .retain(|(_, member_user_id), _| *member_user_id != user_id);
    for (
        membership_id,
        organization_id,
        role,
        llm_scopes,
        llm_capabilities,
        llm_routes,
        organization_active,
    ) in memberships
    {
        identity
            .active_organizations
            .insert(*organization_id, *organization_active);
        identity.memberships.insert(
            (*organization_id, user_id),
            MembershipSnapshot {
                membership_id: *membership_id,
                role: *role,
                llm_scopes: llm_scopes.clone(),
                llm_capabilities: llm_capabilities.clone(),
                llm_routes: llm_routes.clone(),
            },
        );
    }
    Arc::new(RuntimeGeneration {
        snapshot: Arc::new(snapshot),
        credential_clients: Arc::clone(&base_generation.credential_clients),
    })
}

fn parse_organization_role(value: &str) -> Result<OrganizationRole, ApplicationError> {
    match value {
        "owner" => Ok(OrganizationRole::Owner),
        "admin" => Ok(OrganizationRole::Admin),
        "member" => Ok(OrganizationRole::Member),
        _ => Err(ApplicationError::Internal),
    }
}

async fn insert_provisioned_membership(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: OrganizationId,
    user_id: UserId,
    role: OrganizationRole,
    actor: &Value,
) -> Result<(), ApplicationError> {
    sqlx::query(
        "INSERT INTO memberships(
            id, organization_id, user_id, role, status, llm_scope_ceiling,
            etag_token, created_by_principal
         ) VALUES ($1,$2,$3,$4,'active','[]'::jsonb,$5,$6)",
    )
    .bind(Uuid::now_v7())
    .bind(organization_id.as_uuid())
    .bind(user_id.as_uuid())
    .bind(match role {
        OrganizationRole::Owner => "owner",
        OrganizationRole::Admin => "admin",
        OrganizationRole::Member => "member",
    })
    .bind(Uuid::now_v7())
    .bind(actor)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn onboarding_claim_value<'a>(claims: &'a Value, claim: &str) -> Option<&'a Value> {
    if claim.starts_with('/') {
        claims.pointer(claim)
    } else {
        claims.get(claim)
    }
}

fn onboarding_claim_contains(claims: &Value, claim: &str, expected: &str) -> bool {
    match onboarding_claim_value(claims, claim) {
        Some(Value::String(value)) => value == expected,
        Some(Value::Array(values)) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

fn onboarding_predicate_matches(claims: &Value, predicate: &OnboardingClaimPredicate) -> bool {
    match predicate.operator.as_str() {
        "equals" => {
            onboarding_claim_value(claims, &predicate.claim).and_then(Value::as_str)
                == Some(predicate.value.as_str())
        }
        "contains" => onboarding_claim_contains(claims, &predicate.claim, &predicate.value),
        _ => false,
    }
}

fn authorize_identity_read(
    application: &Application,
    identity: &RequestIdentity,
) -> Result<(), ApplicationError> {
    application.authorize(
        identity,
        &[ManagementScope::Read],
        AuthorizationTarget::System {
            capability: Capability::ManageIdentity,
        },
    )
}

fn authorize_identity_write(
    application: &Application,
    identity: &RequestIdentity,
) -> Result<(), ApplicationError> {
    application.authorize(
        identity,
        &[ManagementScope::Write, ManagementScope::Authority],
        AuthorizationTarget::System {
            capability: Capability::ManageIdentity,
        },
    )
}

pub(super) async fn revoke_external_sessions(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    issuer_id: IssuerId,
    external_subject: Option<String>,
) -> Result<(), ApplicationError> {
    sqlx::query(
        "UPDATE web_sessions SET status='revoked', revoked_at=now()
         WHERE authentication_method='external_session' AND status='active'
           AND external_issuer_id=$1 AND ($2::text IS NULL OR external_subject=$2)",
    )
    .bind(issuer_id.as_uuid())
    .bind(external_subject)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn require_issuer_and_user(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    issuer_id: IssuerId,
    user_id: UserId,
) -> Result<(), ApplicationError> {
    let issuer_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM external_identity_issuers WHERE id=$1)",
    )
    .bind(issuer_id.as_uuid())
    .fetch_one(&mut **transaction)
    .await?;
    if !issuer_exists {
        return Err(ApplicationError::NotFound);
    }
    let user_status =
        sqlx::query_scalar::<_, String>("SELECT status FROM users WHERE id=$1 FOR UPDATE")
            .bind(user_id.as_uuid())
            .fetch_optional(&mut **transaction)
            .await?
            .ok_or(ApplicationError::NotFound)?;
    if user_status != "active" {
        return Err(ApplicationError::Conflict(
            "binding target user must be active".to_owned(),
        ));
    }
    Ok(())
}

async fn load_binding<'e, E>(
    executor: E,
    binding_id: BindingId,
) -> Result<(ExternalIdentityBinding, EntityTag), ApplicationError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(
        "SELECT id, issuer_id, external_subject, user_id, status,
                etag_token, created_at, updated_at
         FROM external_identity_bindings WHERE id=$1",
    )
    .bind(binding_id.as_uuid())
    .fetch_optional(executor)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    let etag = EntityTag::for_resource(
        "external_identity_binding",
        binding_id.as_uuid(),
        row.try_get("etag_token")?,
    );
    Ok((binding_from_row(&row)?, etag))
}

fn binding_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<ExternalIdentityBinding, ApplicationError> {
    Ok(ExternalIdentityBinding {
        id: BindingId::from_uuid(row.try_get("id")?),
        issuer_id: IssuerId::from_uuid(row.try_get("issuer_id")?),
        external_subject: row.try_get("external_subject")?,
        user_id: UserId::from_uuid(row.try_get("user_id")?),
        status: row.try_get("status")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

async fn load_policy<'e, E>(
    executor: E,
    policy_id: PolicyId,
) -> Result<(ProvisioningPolicy, EntityTag), ApplicationError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(
        "SELECT id, name, status, user_kind, configuration,
                etag_token, created_at, updated_at
         FROM provisioning_policies WHERE id=$1",
    )
    .bind(policy_id.as_uuid())
    .fetch_optional(executor)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    let etag = EntityTag::for_resource(
        "provisioning_policy",
        policy_id.as_uuid(),
        row.try_get("etag_token")?,
    );
    Ok((policy_from_row(&row)?, etag))
}

fn policy_from_row(row: &sqlx::postgres::PgRow) -> Result<ProvisioningPolicy, ApplicationError> {
    let user_kind = match row.try_get::<String, _>("user_kind")?.as_str() {
        "human" => super::UserKind::Human,
        "synthetic" => super::UserKind::Synthetic,
        _ => return Err(ApplicationError::Internal),
    };
    Ok(ProvisioningPolicy {
        id: PolicyId::from_uuid(row.try_get("id")?),
        name: row.try_get("name")?,
        status: row.try_get("status")?,
        user_kind,
        configuration: row.try_get("configuration")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn valid_onboarding_claim_name(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 {
        return false;
    }
    if value.starts_with('/') {
        return value.split('/').skip(1).all(|segment| {
            !segment.is_empty()
                && segment.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'~')
                })
                && !segment
                    .as_bytes()
                    .windows(2)
                    .any(|pair| pair[0] == b'~' && !matches!(pair[1], b'0' | b'1'))
                && !segment.ends_with('~')
        });
    }
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn validate_external_subject(value: &str) -> Result<(), ApplicationError> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(ApplicationError::Validation(
            "external_subject must contain 1 to 512 safe characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_policy_name(value: &str) -> Result<(), ApplicationError> {
    if value.trim().is_empty() || value.len() > 160 {
        return Err(ApplicationError::Validation(
            "policy name must contain 1 to 160 characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_policy_status(value: &str) -> Result<(), ApplicationError> {
    if matches!(value, "active" | "disabled") {
        Ok(())
    } else {
        Err(ApplicationError::Validation(
            "policy status must be active or disabled".to_owned(),
        ))
    }
}

fn validate_provisioning_configuration(value: &Value) -> Result<(), ApplicationError> {
    let object = value.as_object().ok_or_else(|| {
        ApplicationError::Validation("provisioning configuration must be an object".to_owned())
    })?;
    const ALLOWED: &[&str] = &[
        "allow_user_creation",
        "claim_predicates",
        "display_name_claim",
        "email_claim",
        "create_personal_organization",
        "organization_mappings",
    ];
    if object.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(ApplicationError::Validation(
            "provisioning configuration contains an unknown field".to_owned(),
        ));
    }
    if !object
        .get("allow_user_creation")
        .is_some_and(Value::is_boolean)
    {
        return Err(ApplicationError::Validation(
            "allow_user_creation must be explicit".to_owned(),
        ));
    }
    for key in ["claim_predicates", "organization_mappings"] {
        if object.get(key).is_some_and(|value| !value.is_array()) {
            return Err(ApplicationError::Validation(format!(
                "{key} must be an array"
            )));
        }
        if object
            .get(key)
            .and_then(Value::as_array)
            .is_some_and(|values| values.len() > 64)
        {
            return Err(ApplicationError::Validation(format!(
                "{key} exceeds the bounded item count"
            )));
        }
    }
    for predicate in object
        .get("claim_predicates")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let predicate = predicate.as_object().ok_or_else(|| {
            ApplicationError::Validation("claim predicates must be objects".to_owned())
        })?;
        if predicate
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            != std::collections::BTreeSet::from(["claim", "operator", "value"])
            || !predicate
                .get("claim")
                .and_then(Value::as_str)
                .is_some_and(valid_onboarding_claim_name)
            || !predicate
                .get("operator")
                .and_then(Value::as_str)
                .is_some_and(|operator| matches!(operator, "equals" | "contains"))
            || !predicate
                .get("value")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty() && value.len() <= 512)
        {
            return Err(ApplicationError::Validation(
                "claim predicate is invalid".to_owned(),
            ));
        }
    }
    for mapping in object
        .get("organization_mappings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let mapping = mapping.as_object().ok_or_else(|| {
            ApplicationError::Validation("organization mappings must be objects".to_owned())
        })?;
        if mapping
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            != std::collections::BTreeSet::from([
                "claim",
                "maximum_role",
                "organization_id",
                "value",
            ])
            || !mapping
                .get("claim")
                .and_then(Value::as_str)
                .is_some_and(valid_onboarding_claim_name)
            || !mapping
                .get("value")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty() && value.len() <= 512)
            || serde_json::from_value::<OrganizationId>(mapping["organization_id"].clone()).is_err()
            || serde_json::from_value::<OrganizationRole>(mapping["maximum_role"].clone()).is_err()
        {
            return Err(ApplicationError::Validation(
                "organization mapping is invalid".to_owned(),
            ));
        }
    }
    if object
        .get("create_personal_organization")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(ApplicationError::Validation(
            "create_personal_organization must be boolean".to_owned(),
        ));
    }
    for key in ["display_name_claim", "email_claim"] {
        if object
            .get(key)
            .is_some_and(|value| !value.as_str().is_some_and(valid_onboarding_claim_name))
        {
            return Err(ApplicationError::Validation(format!(
                "{key} must be a bounded unambiguous claim name"
            )));
        }
    }
    Ok(())
}

fn apply_required<T>(
    target: &mut T,
    update: UpdateField<T>,
    field: &str,
) -> Result<(), ApplicationError> {
    match update {
        UpdateField::Omitted => Ok(()),
        UpdateField::Null => Err(ApplicationError::Validation(format!(
            "{field} cannot be null"
        ))),
        UpdateField::Value(value) => {
            *target = value;
            Ok(())
        }
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

fn identity_resource_audit(
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

fn binding_event(binding_id: BindingId, tightening: bool) -> RuntimeEvent {
    RuntimeEvent {
        event_kind: "external_identity_binding.changed".to_owned(),
        affected_scope: json!({"binding_id":binding_id}),
        security_tightening: tightening,
    }
}

fn policy_event(policy_id: PolicyId, tightening: bool) -> RuntimeEvent {
    RuntimeEvent {
        event_kind: "provisioning_policy.changed".to_owned(),
        affected_scope: json!({"policy_id":policy_id}),
        security_tightening: tightening,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisioning_configuration_rejects_implicit_or_unknown_authority() {
        assert!(validate_provisioning_configuration(&json!({})).is_err());
        assert!(
            validate_provisioning_configuration(&json!({
                "allow_user_creation": true,
                "system_administrator": true
            }))
            .is_err()
        );
        assert!(
            validate_provisioning_configuration(&json!({
                "allow_user_creation": true,
                "organization_mappings": []
            }))
            .is_ok()
        );
    }

    #[test]
    fn external_subjects_are_bounded_and_not_email_keys() {
        assert!(validate_external_subject("stable-subject").is_ok());
        assert!(validate_external_subject("").is_err());
        assert!(validate_external_subject(&"x".repeat(513)).is_err());
    }

    #[test]
    fn direct_binding_and_oidc_use_one_subject_lock_domain() {
        let issuer_id = IssuerId::new();
        assert_eq!(
            external_subject_lock_key(issuer_id, "stable-subject"),
            external_subject_lock_key(issuer_id, "stable-subject")
        );
        assert_ne!(
            external_subject_lock_key(issuer_id, "stable-subject"),
            external_subject_lock_key(issuer_id, "other-subject")
        );
    }

    #[test]
    fn oidc_callback_generation_contains_committed_subject_without_publication() {
        use chrono::Utc;

        let issuer_id = IssuerId::new();
        let user_id = UserId::new();
        let organization_id = OrganizationId::new();
        let base = Arc::new(RuntimeGeneration {
            snapshot: Arc::new(crate::runtime::RuntimeSnapshot {
                revision: 7,
                security_revision: 7,
                built_at: Utc::now(),
                compatibility_registry_version: 1,
                gateway_policy_ceilings: crate::runtime::GatewayPolicyCeilingsSnapshot::default(),
                identity: crate::runtime::IdentitySnapshot::default(),
                gateway_keys: std::collections::HashMap::new(),
                organizations: std::collections::HashMap::new(),
                policy_activations: std::collections::HashMap::new(),
                catalog: crate::runtime::CatalogSnapshot::default(),
            }),
            credential_clients: Arc::new(crate::runtime::CredentialClientRegistry::default()),
        });

        let callback = patch_oidc_subject_generation(
            &base,
            issuer_id,
            "new-subject",
            user_id,
            true,
            false,
            &[(
                Uuid::now_v7(),
                organization_id,
                OrganizationRole::Member,
                crate::domain::LlmScopeCeiling::denied(),
                std::collections::BTreeSet::new(),
                crate::domain::JwtRouteCeiling::None,
                true,
            )],
        );

        assert!(base.snapshot.identity.external_bindings.is_empty());
        assert_eq!(callback.snapshot.revision, 7);
        assert_eq!(
            callback
                .snapshot
                .identity
                .external_bindings
                .get(&(issuer_id, "new-subject".to_owned())),
            Some(&user_id)
        );
        assert_eq!(
            callback
                .snapshot
                .identity
                .memberships
                .get(&(organization_id, user_id))
                .map(|membership| membership.role),
            Some(OrganizationRole::Member)
        );
    }
}
