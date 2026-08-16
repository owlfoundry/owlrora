use chrono::{DateTime, Duration, Utc};
use owlrora_key_provider::{
    ContextVersion, FieldPurpose, InstallationId, MaterialId, OpaqueEnvelope,
    OrganizationId as SecretOrganizationId, OwnerId, OwnerKind, ProtectionContext,
    ProtectionContextParts, ProviderFormatVersion, ProviderId, SecretPlaintext, SecretScope,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::{Executor, Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::{
    adapters::{
        postgres::{AuditRecord, RuntimeEvent},
        provider::codex::{
            CodexAdapterError, DevicePoll, DevicePollingMaterial, RefreshResult, TokenMaterial,
            TokenSet, VERIFICATION_URL,
        },
    },
    domain::{
        Actor, Capability, CredentialId, CredentialKind, CredentialLoginSessionId,
        CredentialSecretVersionId, CredentialSourceKind, ManagementScope, OrganizationId,
        ResourceScope,
    },
};

use super::{
    Application, ApplicationError, AuthorizationTarget, CodexLoginSession, CompleteCodexLogin,
    CreateUpstreamCredential, CredentialLifecycleResult, EntityTag, IdempotencyDecision,
    IdempotentCommand, KeyStatus, Page, ReplaceUpstreamCredentialSecret, RequestIdentity,
    StartCodexLogin, UpdateField, UpdateUpstreamCredential, UpstreamCredential,
};

#[derive(Serialize)]
struct ReplaceSecretIdempotencyInput<'a> {
    credential_id: &'a CredentialId,
    input: &'a ReplaceUpstreamCredentialSecret,
}

impl Application {
    pub async fn list_upstream_credentials(
        &self,
        identity: &RequestIdentity,
        scope: ResourceScope,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<UpstreamCredential>, ApplicationError> {
        authorize_credentials(self, identity, &scope, false, Capability::ManageByok)?;
        let family = match scope {
            ResourceScope::Deployment => "upstream_credentials:deployment".to_owned(),
            ResourceScope::Organization { organization_id } => {
                format!("upstream_credentials:organization:{organization_id}")
            }
        };
        let (cursor, limit) = super::resources::page_parameters(&family, cursor, limit)?;
        let (_, organization_id) = scope_columns(&scope);
        let rows = sqlx::query(CREDENTIAL_SELECT_LIST)
            .bind(organization_id)
            .bind(cursor)
            .bind(i64::from(limit) + 1)
            .fetch_all(self.store.pool())
            .await?;
        super::resources::page_from_rows(rows, limit, &family, credential_from_row)
    }

    pub async fn get_upstream_credential(
        &self,
        identity: &RequestIdentity,
        scope: ResourceScope,
        credential_id: CredentialId,
    ) -> Result<(UpstreamCredential, EntityTag), ApplicationError> {
        authorize_credentials(self, identity, &scope, false, Capability::ManageByok)?;
        load_credential(self.store.pool(), &scope, credential_id).await
    }

    pub async fn create_upstream_credential(
        &self,
        identity: &RequestIdentity,
        scope: ResourceScope,
        input: CreateUpstreamCredential,
        idempotency_key: Option<&str>,
    ) -> Result<IdempotentCommand<(UpstreamCredential, EntityTag)>, ApplicationError> {
        authorize_credentials(self, identity, &scope, true, Capability::ManageByok)?;
        if input.secret.is_some() {
            self.authorize(
                identity,
                &[ManagementScope::Secrets],
                AuthorizationTarget::CurrentPrincipal,
            )?;
        }
        validate_create(&scope, &input)?;
        let operation_id = credential_operation_id(&scope, "create");
        if let Some(replay) = self
            .replay_completed_secret_idempotent_command(
                identity,
                &scope,
                operation_id,
                idempotency_key,
                &input,
            )
            .await?
        {
            return Ok(IdempotentCommand::Replay(replay));
        }
        let id = CredentialId::new();
        let version_id = CredentialSecretVersionId::new();
        let actor = actor_value(identity)?;
        let (scope_kind, organization_id) = scope_columns(&scope);
        let sealed_secret = match input.secret.as_deref() {
            Some(secret) => {
                let plaintext = SecretPlaintext::new(secret.as_bytes().to_vec()).map_err(|_| {
                    ApplicationError::Validation("secret must contain 1 to 65536 bytes".to_owned())
                })?;
                Some(seal_protected_version(self, &scope, id, version_id, 1, 1, &plaintext).await?)
            }
            None => None,
        };
        let mut transaction = self.store.begin().await?;
        let handle = match self
            .begin_secret_idempotent_command(
                &mut transaction,
                identity,
                &scope,
                operation_id,
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
        if let Some(organization_id) = organization_id {
            let active = sqlx::query_scalar::<_, bool>(
                "SELECT status='active' FROM organizations WHERE id=$1 FOR UPDATE",
            )
            .bind(organization_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(ApplicationError::NotFound)?;
            if !active {
                return Err(ApplicationError::Forbidden);
            }
        }
        let has_material = input.secret.is_some()
            || input.secret_source_kind != CredentialSourceKind::EncryptedDatabase;
        sqlx::query(
            "INSERT INTO upstream_credentials(
                id,resource_scope_kind,organization_id,name,credential_kind,secret_source_kind,
                source_configuration,injection_kind,sharing_policy,administrative_status,
                authentication_status,current_secret_version,state_identity_version,safe_metadata,
                created_by_principal,etag_token
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',$10,$11,1,$12,$13,$14)",
        )
        .bind(id.as_uuid())
        .bind(scope_kind)
        .bind(organization_id)
        .bind(input.name.trim())
        .bind(input.credential_kind.as_str())
        .bind(input.secret_source_kind.as_str())
        .bind(&input.source_configuration)
        .bind(input.injection_kind.trim())
        .bind(input.sharing_policy.trim())
        .bind(if has_material {
            "unvalidated"
        } else {
            "login_required"
        })
        .bind(has_material.then_some(1_i64))
        .bind(&input.safe_metadata)
        .bind(actor)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_conflict)?;
        if let Some(sealed_secret) = &sealed_secret {
            persist_protected_version(&mut transaction, id, sealed_secret, "current").await?;
        } else if input.secret_source_kind != CredentialSourceKind::EncryptedDatabase {
            insert_source_version(
                &mut transaction,
                id,
                version_id,
                1,
                1,
                &input.source_configuration,
            )
            .await?;
        }
        let result = load_credential(&mut *transaction, &scope, id).await?;
        self.complete_idempotent_command(
            &mut transaction,
            handle,
            200,
            &result.0,
            Some(result.1.as_str()),
        )
        .await?;
        commit_credential(
            self,
            transaction,
            identity,
            &scope,
            id,
            operation_id,
            &[
                "name",
                "credential_kind",
                "secret_source_kind",
                "source_configuration",
                "injection_kind",
                "sharing_policy",
                "safe_metadata",
                "secret_version",
            ],
            false,
        )
        .await?;
        self.publish_committed_runtime(&identity.request_id, operation_id)
            .await;
        Ok(IdempotentCommand::Executed(result))
    }

    pub async fn update_upstream_credential(
        &self,
        identity: &RequestIdentity,
        scope: ResourceScope,
        credential_id: CredentialId,
        if_match: Option<&str>,
        input: UpdateUpstreamCredential,
    ) -> Result<(UpstreamCredential, EntityTag), ApplicationError> {
        authorize_credentials(self, identity, &scope, true, Capability::ManageByok)?;
        if input.name.is_omitted()
            && input.sharing_policy.is_omitted()
            && input.administrative_status.is_omitted()
            && input.safe_metadata.is_omitted()
        {
            return Err(ApplicationError::Validation(
                "at least one update field is required".to_owned(),
            ));
        }
        let operation_id = credential_operation_id(&scope, "update");
        let (_, organization_id) = scope_columns(&scope);
        let mut transaction = self.store.begin().await?;
        let row = sqlx::query(
            "SELECT name,sharing_policy,administrative_status,safe_metadata,etag_token
             FROM upstream_credentials WHERE organization_id IS NOT DISTINCT FROM $1 AND id=$2 FOR UPDATE",
        )
        .bind(organization_id)
        .bind(credential_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        require_if_match(
            if_match,
            &EntityTag::for_resource(
                "upstream_credential",
                credential_id.as_uuid(),
                row.try_get("etag_token")?,
            ),
        )?;
        let mut name: String = row.try_get("name")?;
        let mut sharing: String = row.try_get("sharing_policy")?;
        let current_status: String = row.try_get("administrative_status")?;
        let mut status = current_status.clone();
        let mut metadata: Value = row.try_get("safe_metadata")?;
        let mut changed = Vec::new();
        match input.name {
            UpdateField::Omitted => {}
            UpdateField::Null => return Err(null_error("name")),
            UpdateField::Value(value) => {
                validate_name(&value)?;
                name = value.trim().to_owned();
                changed.push("name");
            }
        }
        match input.sharing_policy {
            UpdateField::Omitted => {}
            UpdateField::Null => return Err(null_error("sharing_policy")),
            UpdateField::Value(value) => {
                validate_sharing(&value)?;
                sharing = value;
                changed.push("sharing_policy");
            }
        }
        match input.administrative_status {
            UpdateField::Omitted => {}
            UpdateField::Null => return Err(null_error("administrative_status")),
            UpdateField::Value(value) => {
                if current_status == "revoked" && value != KeyStatus::Revoked {
                    return Err(ApplicationError::Conflict(
                        "a revoked upstream credential cannot be reactivated".to_owned(),
                    ));
                }
                status = value.as_str().to_owned();
                changed.push("administrative_status");
            }
        }
        match input.safe_metadata {
            UpdateField::Omitted => {}
            UpdateField::Null => return Err(null_error("safe_metadata")),
            UpdateField::Value(value) => {
                validate_safe_metadata(&value)?;
                metadata = value;
                changed.push("safe_metadata");
            }
        }
        sqlx::query(
            "UPDATE upstream_credentials SET name=$3,sharing_policy=$4,administrative_status=$5,
                    safe_metadata=$6,etag_token=$7,updated_at=now()
             WHERE organization_id IS NOT DISTINCT FROM $1 AND id=$2",
        )
        .bind(organization_id)
        .bind(credential_id.as_uuid())
        .bind(name)
        .bind(sharing)
        .bind(&status)
        .bind(metadata)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_conflict)?;
        let tightening = current_status == "active" && status != "active";
        let result = load_credential(&mut *transaction, &scope, credential_id).await?;
        commit_credential(
            self,
            transaction,
            identity,
            &scope,
            credential_id,
            operation_id,
            &changed,
            tightening,
        )
        .await?;
        self.publish_committed_runtime(&identity.request_id, operation_id)
            .await;
        Ok(result)
    }

    pub async fn replace_upstream_credential_secret(
        &self,
        identity: &RequestIdentity,
        scope: ResourceScope,
        credential_id: CredentialId,
        input: ReplaceUpstreamCredentialSecret,
        idempotency_key: Option<&str>,
    ) -> Result<IdempotentCommand<(UpstreamCredential, EntityTag)>, ApplicationError> {
        authorize_credentials(self, identity, &scope, true, Capability::ManageByok)?;
        self.authorize(
            identity,
            &[ManagementScope::Secrets],
            AuthorizationTarget::CurrentPrincipal,
        )?;
        let operation_id = credential_operation_id(&scope, "replace_secret");
        let idempotency_input = ReplaceSecretIdempotencyInput {
            credential_id: &credential_id,
            input: &input,
        };
        if let Some(replay) = self
            .replay_completed_secret_idempotent_command(
                identity,
                &scope,
                operation_id,
                idempotency_key,
                &idempotency_input,
            )
            .await?
        {
            return Ok(IdempotentCommand::Replay(replay));
        }
        let plaintext = SecretPlaintext::new(input.secret.as_bytes().to_vec()).map_err(|_| {
            ApplicationError::Validation("secret must contain 1 to 65536 bytes".to_owned())
        })?;
        let (_, organization_id) = scope_columns(&scope);
        let captured = sqlx::query(
            "SELECT credential_kind,secret_source_kind,current_secret_version,state_identity_version
             FROM upstream_credentials WHERE organization_id IS NOT DISTINCT FROM $1 AND id=$2",
        )
        .bind(organization_id)
        .bind(credential_id.as_uuid())
        .fetch_optional(self.store.pool())
        .await?
        .ok_or(ApplicationError::NotFound)?;
        require_static_database_credential(&captured)?;
        let captured_version: Option<i64> = captured.try_get("current_secret_version")?;
        let next_version = captured_version
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(ApplicationError::Internal)?;
        let captured_state_identity: i64 = captured.try_get("state_identity_version")?;
        // Static secret adapters cannot prove that replacement preserves the upstream account or
        // project. Conservatively fence all state-origin bindings by advancing account identity.
        let next_state_identity = captured_state_identity
            .checked_add(1)
            .ok_or(ApplicationError::Internal)?;
        let version_id = CredentialSecretVersionId::new();
        let sealed = seal_protected_version(
            self,
            &scope,
            credential_id,
            version_id,
            u64::try_from(next_state_identity).map_err(|_| ApplicationError::Internal)?,
            u64::try_from(next_version).map_err(|_| ApplicationError::Internal)?,
            &plaintext,
        )
        .await?;

        let mut transaction = self.store.begin().await?;
        let handle = match self
            .begin_secret_idempotent_command(
                &mut transaction,
                identity,
                &scope,
                operation_id,
                idempotency_key,
                &idempotency_input,
            )
            .await?
        {
            IdempotencyDecision::Execute(handle) => handle,
            IdempotencyDecision::Replay(replay) => {
                return Ok(IdempotentCommand::Replay(replay));
            }
        };
        let row = sqlx::query(
            "SELECT credential_kind,secret_source_kind,current_secret_version,state_identity_version
             FROM upstream_credentials WHERE organization_id IS NOT DISTINCT FROM $1 AND id=$2 FOR UPDATE",
        )
        .bind(organization_id)
        .bind(credential_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        require_static_database_credential(&row)?;
        if row.try_get::<Option<i64>, _>("current_secret_version")? != captured_version
            || row.try_get::<i64, _>("state_identity_version")? != captured_state_identity
        {
            return Err(ApplicationError::Conflict(
                "upstream credential changed while the replacement secret was being protected"
                    .to_owned(),
            ));
        }
        let retired_protected_ids = sqlx::query_scalar::<_, Uuid>(
            "SELECT protected_secret_version_id FROM upstream_credential_secret_versions
             WHERE credential_id=$1 AND state IN ('current','overlap')
               AND protected_secret_version_id IS NOT NULL FOR UPDATE",
        )
        .bind(credential_id.as_uuid())
        .fetch_all(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE upstream_credential_secret_versions SET state='retired',retired_at=now(),
                    overlap_until=NULL,protected_secret_version_id=NULL
             WHERE credential_id=$1 AND state IN ('current','overlap')",
        )
        .bind(credential_id.as_uuid())
        .execute(&mut *transaction)
        .await?;
        persist_protected_version(&mut transaction, credential_id, &sealed, "current").await?;
        sqlx::query(
            "UPDATE upstream_credentials SET current_secret_version=$3,state_identity_version=$4,
                    authentication_status='unvalidated',validation_evidence=NULL,validated_at=NULL,
                    etag_token=$5,updated_at=now()
             WHERE organization_id IS NOT DISTINCT FROM $1 AND id=$2",
        )
        .bind(organization_id)
        .bind(credential_id.as_uuid())
        .bind(next_version)
        .bind(next_state_identity)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        for protected_id in retired_protected_ids {
            sqlx::query("DELETE FROM protected_secret_versions WHERE id=$1")
                .bind(protected_id)
                .execute(&mut *transaction)
                .await?;
        }
        let (value, etag) = load_credential(&mut *transaction, &scope, credential_id).await?;
        self.complete_idempotent_command(
            &mut transaction,
            handle,
            200,
            &value,
            Some(etag.as_str()),
        )
        .await?;
        commit_credential(
            self,
            transaction,
            identity,
            &scope,
            credential_id,
            operation_id,
            &[
                "current_secret_version",
                "state_identity_version",
                "authentication_status",
            ],
            true,
        )
        .await?;
        self.publish_committed_runtime(&identity.request_id, operation_id)
            .await;
        Ok(IdempotentCommand::Executed((value, etag)))
    }

    pub async fn reload_upstream_credential_source(
        &self,
        identity: &RequestIdentity,
        credential_id: CredentialId,
        idempotency_key: Option<&str>,
    ) -> Result<IdempotentCommand<CredentialLifecycleResult>, ApplicationError> {
        let scope = ResourceScope::Deployment;
        authorize_credentials(self, identity, &scope, true, Capability::ManageByok)?;
        let operation_id = credential_operation_id(&scope, "reload_source");
        let request = json!({"credential_id": credential_id});
        let mut transaction = self.store.begin().await?;
        let handle = match self
            .begin_idempotent_command(
                &mut transaction,
                identity,
                &scope,
                operation_id,
                idempotency_key,
                &request,
            )
            .await?
        {
            IdempotencyDecision::Execute(handle) => handle,
            IdempotencyDecision::Replay(replay) => {
                return Ok(IdempotentCommand::Replay(replay));
            }
        };
        let row = sqlx::query(
            "SELECT secret_source_kind,source_configuration,current_secret_version,
                    state_identity_version,etag_token
             FROM upstream_credentials WHERE organization_id IS NULL AND id=$1 FOR UPDATE",
        )
        .bind(credential_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        let source_kind = row.try_get::<String, _>("secret_source_kind")?;
        if source_kind == "encrypted_database" {
            return Err(ApplicationError::Conflict(
                "encrypted-database credentials use replace-secret instead of reload-source"
                    .to_owned(),
            ));
        }
        let current_version: Option<i64> = row.try_get("current_secret_version")?;
        let next_version = current_version
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(ApplicationError::Internal)?;
        let state_identity: i64 = row.try_get("state_identity_version")?;
        let configuration: Value = row.try_get("source_configuration")?;
        sqlx::query(
            "UPDATE upstream_credential_secret_versions SET state='retired',retired_at=now(),
                    overlap_until=NULL WHERE credential_id=$1 AND state IN ('current','overlap')",
        )
        .bind(credential_id.as_uuid())
        .execute(&mut *transaction)
        .await?;
        insert_source_version(
            &mut transaction,
            credential_id,
            CredentialSecretVersionId::new(),
            next_version,
            state_identity,
            &configuration,
        )
        .await?;
        sqlx::query(
            "UPDATE upstream_credentials SET current_secret_version=$2,
                    authentication_status='unvalidated',validation_evidence=NULL,validated_at=NULL,
                    etag_token=$3,updated_at=now() WHERE id=$1",
        )
        .bind(credential_id.as_uuid())
        .bind(next_version)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let (credential, _) = load_credential(&mut *transaction, &scope, credential_id).await?;
        let result = CredentialLifecycleResult {
            credential,
            operation: "reload_source".to_owned(),
            outcome: "accepted".to_owned(),
        };
        self.complete_idempotent_command(&mut transaction, handle, 200, &result, None)
            .await?;
        commit_credential(
            self,
            transaction,
            identity,
            &scope,
            credential_id,
            operation_id,
            &["current_secret_version", "authentication_status"],
            false,
        )
        .await?;
        self.publish_committed_runtime(&identity.request_id, operation_id)
            .await;
        Ok(IdempotentCommand::Executed(result))
    }

    pub async fn validate_upstream_credential(
        &self,
        identity: &RequestIdentity,
        scope: ResourceScope,
        credential_id: CredentialId,
        idempotency_key: Option<&str>,
    ) -> Result<IdempotentCommand<CredentialLifecycleResult>, ApplicationError> {
        authorize_credentials(self, identity, &scope, true, Capability::ManageByok)?;
        let operation_id = credential_operation_id(&scope, "validate");
        let request = json!({"credential_id": credential_id});
        if let Some(replay) = self
            .replay_completed_idempotent_command(
                identity,
                &scope,
                operation_id,
                idempotency_key,
                &request,
            )
            .await?
        {
            return Ok(IdempotentCommand::Replay(replay));
        }
        let (_, organization_id) = scope_columns(&scope);
        let captured = sqlx::query(
            "SELECT current_secret_version,state_identity_version,administrative_status,
                    authentication_status,credential_kind,secret_source_kind
             FROM upstream_credentials
             WHERE organization_id IS NOT DISTINCT FROM $1 AND id=$2",
        )
        .bind(organization_id)
        .bind(credential_id.as_uuid())
        .fetch_optional(self.store.pool())
        .await?
        .ok_or(ApplicationError::NotFound)?;
        let captured_secret_version = captured
            .try_get::<Option<i64>, _>("current_secret_version")?
            .ok_or_else(|| {
                ApplicationError::Conflict("credential has no selected source version".to_owned())
            })?;
        let captured_state_identity: i64 = captured.try_get("state_identity_version")?;
        let captured_state_identity_u64 =
            u64::try_from(captured_state_identity).map_err(|_| ApplicationError::Internal)?;
        if captured.try_get::<String, _>("administrative_status")? != "active" {
            return Err(ApplicationError::Conflict(
                "a disabled or revoked credential cannot be validated".to_owned(),
            ));
        }
        if captured.try_get::<String, _>("credential_kind")? == "oauth_openai_codex"
            && captured.try_get::<String, _>("authentication_status")? != "ready"
        {
            return Err(ApplicationError::Conflict(
                "Codex credential validation requires a completed login".to_owned(),
            ));
        }
        // Compile/open/build outside the command transaction. The final write is fenced by the
        // exact selected version and credential state identity captured before this work.
        self.runtime
            .refresh_now()
            .await
            .map_err(|_| ApplicationError::DependencyUnavailable)?;
        let generation = self.runtime.capture();
        let dependent_deployments = generation
            .snapshot
            .catalog
            .deployments
            .values()
            .filter(|deployment| deployment.credential_id == credential_id)
            .collect::<Vec<_>>();
        let runtime_matches_capture = dependent_deployments.iter().all(|deployment| {
            deployment.credential_secret_version == captured_secret_version
                && deployment.credential_state_identity_version == captured_state_identity_u64
        });
        let client_available = dependent_deployments.iter().all(|deployment| {
            generation
                .credential_clients
                .clients
                .contains_key(&deployment.client_key())
        });
        let mut transaction = self.store.begin().await?;
        let handle = match self
            .begin_idempotent_command(
                &mut transaction,
                identity,
                &scope,
                operation_id,
                idempotency_key,
                &request,
            )
            .await?
        {
            IdempotencyDecision::Execute(handle) => handle,
            IdempotencyDecision::Replay(replay) => {
                return Ok(IdempotentCommand::Replay(replay));
            }
        };
        let row = sqlx::query(
            "SELECT credential_kind,secret_source_kind,administrative_status,
                    authentication_status,current_secret_version,state_identity_version
             FROM upstream_credentials
             WHERE organization_id IS NOT DISTINCT FROM $1 AND id=$2 FOR UPDATE",
        )
        .bind(organization_id)
        .bind(credential_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        if row.try_get::<Option<i64>, _>("current_secret_version")? != Some(captured_secret_version)
            || row.try_get::<i64, _>("state_identity_version")? != captured_state_identity
            || !runtime_matches_capture
        {
            return Err(ApplicationError::Conflict(
                "credential changed while validation was running".to_owned(),
            ));
        }
        if row.try_get::<String, _>("administrative_status")? != "active" {
            return Err(ApplicationError::Conflict(
                "a disabled or revoked credential cannot be validated".to_owned(),
            ));
        }
        let kind = row.try_get::<String, _>("credential_kind")?;
        if kind == "oauth_openai_codex"
            && row.try_get::<String, _>("authentication_status")? != "ready"
        {
            return Err(ApplicationError::Conflict(
                "Codex credential validation requires a completed login".to_owned(),
            ));
        }
        if row
            .try_get::<Option<i64>, _>("current_secret_version")?
            .is_none()
        {
            return Err(ApplicationError::Conflict(
                "credential has no selected source version".to_owned(),
            ));
        }
        if !client_available {
            return Err(ApplicationError::Conflict(
                "credential runtime client could not be built for every dependent deployment"
                    .to_owned(),
            ));
        }
        sqlx::query(
            "UPDATE upstream_credentials SET authentication_status='ready',
                    validation_evidence=$3,validated_at=now(),etag_token=$4,updated_at=now()
             WHERE organization_id IS NOT DISTINCT FROM $1 AND id=$2",
        )
        .bind(organization_id)
        .bind(credential_id.as_uuid())
        .bind(json!({
            "outcome":"accepted",
            "validation_kind":"runtime_client_build",
            "secret_source_kind":row.try_get::<String, _>("secret_source_kind")?,
            "credential_kind":kind,
        }))
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let (credential, _) = load_credential(&mut *transaction, &scope, credential_id).await?;
        let result = CredentialLifecycleResult {
            credential,
            operation: "validate".to_owned(),
            outcome: "accepted".to_owned(),
        };
        self.complete_idempotent_command(&mut transaction, handle, 200, &result, None)
            .await?;
        commit_credential(
            self,
            transaction,
            identity,
            &scope,
            credential_id,
            operation_id,
            &[
                "authentication_status",
                "validation_evidence",
                "validated_at",
            ],
            false,
        )
        .await?;
        self.publish_committed_runtime(&identity.request_id, operation_id)
            .await;
        Ok(IdempotentCommand::Executed(result))
    }

    pub async fn start_codex_login(
        &self,
        identity: &RequestIdentity,
        credential_id: CredentialId,
        _input: StartCodexLogin,
    ) -> Result<CodexLoginSession, ApplicationError> {
        let scope = ResourceScope::Deployment;
        authorize_credentials(self, identity, &scope, true, Capability::ManageByok)?;
        self.authorize(
            identity,
            &[ManagementScope::Secrets],
            AuthorizationTarget::CurrentPrincipal,
        )?;

        // Capture the exact credential state before provider I/O. The provider call must never
        // hold a PostgreSQL transaction open.
        let captured_identity = sqlx::query_scalar::<_, i64>(
            "SELECT state_identity_version FROM upstream_credentials
             WHERE organization_id IS NULL AND id=$1
               AND credential_kind='oauth_openai_codex'
               AND secret_source_kind='encrypted_database'
               AND administrative_status='active'",
        )
        .bind(credential_id.as_uuid())
        .fetch_optional(self.store.pool())
        .await?
        .ok_or(ApplicationError::NotFound)?;
        let provider_login = self
            .codex
            .start_device_login()
            .await
            .map_err(map_codex_error)?;
        let session_id = CredentialLoginSessionId::new();
        let secret_id = CredentialSecretVersionId::new();
        let expires_at = Utc::now()
            .checked_add_signed(Duration::seconds(i64::from(
                crate::adapters::provider::codex::LOGIN_LIFETIME_SECONDS,
            )))
            .ok_or(ApplicationError::Internal)?;
        let plaintext = SecretPlaintext::new(
            serde_json::to_vec(&provider_login.polling_material)
                .map_err(|_| ApplicationError::Internal)?,
        )
        .map_err(|_| ApplicationError::Internal)?;
        let sealed_login_secret = seal_codex_login_secret(
            self,
            session_id,
            secret_id,
            u64::try_from(captured_identity).map_err(|_| ApplicationError::Internal)?,
            &plaintext,
        )
        .await?;

        let operation_id = credential_operation_id(&scope, "codex_login_start");
        let mut transaction = self.store.begin().await?;
        let row = sqlx::query(
            "SELECT state_identity_version FROM upstream_credentials
             WHERE organization_id IS NULL AND id=$1
               AND credential_kind='oauth_openai_codex'
               AND secret_source_kind='encrypted_database'
               AND administrative_status='active' FOR UPDATE",
        )
        .bind(credential_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        let state_identity: i64 = row.try_get("state_identity_version")?;
        if state_identity != captured_identity {
            return Err(ApplicationError::Conflict(
                "Codex credential changed while device login was starting".to_owned(),
            ));
        }
        persist_codex_login_secret(&mut transaction, session_id, &sealed_login_secret).await?;
        sqlx::query(
            "INSERT INTO upstream_credential_login_sessions(
                id,credential_id,credential_state_identity_version,state,login_secret_id,
                safe_display,poll_interval_seconds,expires_at,next_poll_at,created_by_principal
             ) VALUES ($1,$2,$3,'pending',$4,$5,$6,$7,now(),$8)",
        )
        .bind(session_id.as_uuid())
        .bind(credential_id.as_uuid())
        .bind(state_identity)
        .bind(secret_id.as_uuid())
        .bind(json!({"display_available":false}))
        .bind(
            i32::try_from(provider_login.interval_seconds)
                .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(expires_at)
        .bind(actor_value(identity)?)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_conflict)?;
        sqlx::query(
            "UPDATE upstream_credentials SET authentication_status='login_pending',
                    validation_evidence=NULL,validated_at=NULL,etag_token=$2,updated_at=now()
             WHERE id=$1",
        )
        .bind(credential_id.as_uuid())
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let mut result =
            load_codex_login_session(&mut *transaction, credential_id, session_id).await?;
        result.verification_url = Some(VERIFICATION_URL.to_owned());
        result.user_code = Some(provider_login.user_code);
        commit_credential(
            self,
            transaction,
            identity,
            &scope,
            credential_id,
            operation_id,
            &["authentication_status", "codex_login_session"],
            true,
        )
        .await?;
        self.publish_committed_runtime(&identity.request_id, operation_id)
            .await;
        Ok(result)
    }

    pub async fn get_codex_login(
        &self,
        identity: &RequestIdentity,
        credential_id: CredentialId,
        session_id: CredentialLoginSessionId,
    ) -> Result<CodexLoginSession, ApplicationError> {
        let scope = ResourceScope::Deployment;
        authorize_credentials(self, identity, &scope, false, Capability::ManageByok)?;
        let mut transaction = self.store.begin().await?;
        expire_codex_login_if_due(&mut transaction, credential_id, session_id).await?;
        let result = load_codex_login_session(&mut *transaction, credential_id, session_id).await?;
        transaction.commit().await?;
        Ok(result)
    }

    pub async fn complete_codex_login(
        &self,
        identity: &RequestIdentity,
        credential_id: CredentialId,
        session_id: CredentialLoginSessionId,
        _input: CompleteCodexLogin,
    ) -> Result<CredentialLifecycleResult, ApplicationError> {
        let scope = ResourceScope::Deployment;
        authorize_credentials(self, identity, &scope, true, Capability::ManageByok)?;
        self.authorize(
            identity,
            &[ManagementScope::Secrets],
            AuthorizationTarget::CurrentPrincipal,
        )?;

        let captured = claim_codex_login(self, credential_id, session_id).await?;
        let poll = self
            .codex
            .poll_device_login(&captured.polling_material)
            .await
            .map_err(map_codex_error)?;
        let DevicePoll::Authorized(grant) = poll else {
            let next_poll_at = Utc::now()
                .checked_add_signed(Duration::seconds(i64::from(captured.poll_interval_seconds)))
                .ok_or(ApplicationError::Internal)?;
            let updated = sqlx::query(
                "UPDATE upstream_credential_login_sessions
                 SET state='pending',attempt_token=NULL,claim_expires_at=NULL,
                     next_poll_at=$4,updated_at=now()
                 WHERE id=$1 AND credential_id=$2 AND state='polling'
                   AND attempt_token=$6
                   AND credential_state_identity_version=$3 AND login_secret_id=$5
                   AND expires_at>now()",
            )
            .bind(session_id.as_uuid())
            .bind(credential_id.as_uuid())
            .bind(captured.state_identity_version)
            .bind(next_poll_at)
            .bind(captured.login_secret_id)
            .bind(captured.attempt_token)
            .execute(self.store.pool())
            .await?
            .rows_affected();
            if updated != 1 {
                return Err(ApplicationError::Conflict(
                    "Codex login session changed while polling".to_owned(),
                ));
            }
            let (credential, _) = load_credential(self.store.pool(), &scope, credential_id).await?;
            return Ok(CredentialLifecycleResult {
                credential,
                operation: "codex_login_complete".to_owned(),
                outcome: "pending".to_owned(),
            });
        };
        let exchanging = sqlx::query(
            "UPDATE upstream_credential_login_sessions
             SET state='exchanging',claim_expires_at=now()+interval '50 seconds',updated_at=now()
             WHERE id=$1 AND credential_id=$2 AND state='polling' AND attempt_token=$3
               AND credential_state_identity_version=$4 AND login_secret_id=$5
               AND expires_at>now()",
        )
        .bind(session_id.as_uuid())
        .bind(credential_id.as_uuid())
        .bind(captured.attempt_token)
        .bind(captured.state_identity_version)
        .bind(captured.login_secret_id)
        .execute(self.store.pool())
        .await?
        .rows_affected();
        if exchanging != 1 {
            return Err(ApplicationError::Conflict(
                "Codex login session changed before token exchange".to_owned(),
            ));
        }
        let token_set = match self.codex.exchange_authorization_code(grant).await {
            Ok(tokens) => tokens,
            Err(error) => {
                fail_claimed_codex_login(
                    self,
                    credential_id,
                    session_id,
                    captured.attempt_token,
                    captured.login_secret_id,
                    "token_exchange_failed",
                )
                .await?;
                return Err(map_codex_error(error));
            }
        };
        let account_id = token_set.account_id.clone();
        let captured_credential = sqlx::query(
            "SELECT current_secret_version,state_identity_version,safe_metadata,
                    credential_kind,administrative_status,etag_token
             FROM upstream_credentials WHERE id=$1",
        )
        .bind(credential_id.as_uuid())
        .fetch_one(self.store.pool())
        .await?;
        require_codex_active(&captured_credential)?;
        let captured_identity: i64 = captured_credential.try_get("state_identity_version")?;
        if captured_identity != captured.state_identity_version {
            return Err(ApplicationError::Conflict(
                "Codex credential changed while login completed".to_owned(),
            ));
        }
        let captured_version: Option<i64> =
            captured_credential.try_get("current_secret_version")?;
        let next_version = captured_version
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(ApplicationError::Internal)?;
        let captured_metadata: Value = captured_credential.try_get("safe_metadata")?;
        let prior_account = captured_metadata.get("account_id").and_then(Value::as_str);
        let next_identity = if prior_account.is_some_and(|value| value != account_id) {
            captured_identity
                .checked_add(1)
                .ok_or(ApplicationError::Internal)?
        } else {
            captured_identity
        };
        let captured_etag_token: Uuid = captured_credential.try_get("etag_token")?;
        let prepared =
            prepare_codex_token(self, credential_id, next_version, next_identity, token_set)
                .await?;

        let operation_id = credential_operation_id(&scope, "codex_login_complete");
        let mut transaction = self.store.begin().await?;
        let session = sqlx::query(
            "SELECT state,attempt_token,login_secret_id,credential_state_identity_version
             FROM upstream_credential_login_sessions
             WHERE credential_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(credential_id.as_uuid())
        .bind(session_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        let state = session.try_get::<String, _>("state")?;
        if state == "completed" {
            let (credential, _) = load_credential(&mut *transaction, &scope, credential_id).await?;
            transaction.commit().await?;
            return Ok(CredentialLifecycleResult {
                credential,
                operation: "codex_login_complete".to_owned(),
                outcome: "already_completed".to_owned(),
            });
        }
        if state != "exchanging"
            || session.try_get::<Option<Uuid>, _>("attempt_token")? != Some(captured.attempt_token)
            || session.try_get::<i64, _>("credential_state_identity_version")?
                != captured.state_identity_version
            || session.try_get::<Option<Uuid>, _>("login_secret_id")?
                != Some(captured.login_secret_id)
        {
            return Err(ApplicationError::Conflict(
                "Codex login session changed while completing".to_owned(),
            ));
        }
        let credential = sqlx::query(
            "SELECT current_secret_version,state_identity_version,credential_kind,
                    administrative_status,etag_token
             FROM upstream_credentials WHERE id=$1 FOR UPDATE",
        )
        .bind(credential_id.as_uuid())
        .fetch_one(&mut *transaction)
        .await?;
        require_codex_active(&credential)?;
        if credential.try_get::<i64, _>("state_identity_version")? != captured_identity
            || credential.try_get::<Option<i64>, _>("current_secret_version")? != captured_version
            || credential.try_get::<Uuid, _>("etag_token")? != captured_etag_token
        {
            return Err(ApplicationError::Conflict(
                "Codex credential changed while token material was being protected".to_owned(),
            ));
        }
        sqlx::query(
            "UPDATE upstream_credential_refresh_leases SET state='outcome_unknown',
                    safe_outcome='{\"outcome\":\"fenced_by_login\"}'::jsonb,completed_at=now()
             WHERE credential_id=$1 AND state='refreshing'",
        )
        .bind(credential_id.as_uuid())
        .execute(&mut *transaction)
        .await?;
        activate_codex_token(&mut transaction, credential_id, &prepared).await?;
        terminalize_codex_login(
            &mut transaction,
            session_id,
            "completed",
            session.try_get("login_secret_id")?,
        )
        .await?;
        let (credential, _) = load_credential(&mut *transaction, &scope, credential_id).await?;
        let result = CredentialLifecycleResult {
            credential,
            operation: "codex_login_complete".to_owned(),
            outcome: "accepted".to_owned(),
        };
        commit_credential(
            self,
            transaction,
            identity,
            &scope,
            credential_id,
            operation_id,
            &[
                "current_secret_version",
                "state_identity_version",
                "authentication_status",
                "safe_metadata",
                "codex_login_session",
            ],
            false,
        )
        .await?;
        self.publish_committed_runtime(&identity.request_id, operation_id)
            .await;
        Ok(result)
    }

    pub async fn cancel_codex_login(
        &self,
        identity: &RequestIdentity,
        credential_id: CredentialId,
        session_id: CredentialLoginSessionId,
    ) -> Result<CodexLoginSession, ApplicationError> {
        let scope = ResourceScope::Deployment;
        authorize_credentials(self, identity, &scope, true, Capability::ManageByok)?;
        let operation_id = credential_operation_id(&scope, "codex_login_cancel");
        let mut transaction = self.store.begin().await?;
        let row = sqlx::query(
            "SELECT state,login_secret_id FROM upstream_credential_login_sessions
             WHERE credential_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(credential_id.as_uuid())
        .bind(session_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        if matches!(
            row.try_get::<String, _>("state")?.as_str(),
            "pending" | "polling"
        ) {
            terminalize_codex_login(
                &mut transaction,
                session_id,
                "cancelled",
                row.try_get("login_secret_id")?,
            )
            .await?;
            sqlx::query(
                "UPDATE upstream_credentials SET authentication_status=CASE
                    WHEN current_secret_version IS NULL THEN 'login_required' ELSE 'ready' END,
                    etag_token=$2,updated_at=now() WHERE id=$1",
            )
            .bind(credential_id.as_uuid())
            .bind(Uuid::now_v7())
            .execute(&mut *transaction)
            .await?;
        }
        let result = load_codex_login_session(&mut *transaction, credential_id, session_id).await?;
        commit_credential(
            self,
            transaction,
            identity,
            &scope,
            credential_id,
            operation_id,
            &["authentication_status", "codex_login_session"],
            true,
        )
        .await?;
        self.publish_committed_runtime(&identity.request_id, operation_id)
            .await;
        Ok(result)
    }

    pub async fn refresh_codex_credential(
        &self,
        identity: &RequestIdentity,
        credential_id: CredentialId,
    ) -> Result<CredentialLifecycleResult, ApplicationError> {
        let scope = ResourceScope::Deployment;
        authorize_credentials(self, identity, &scope, true, Capability::ManageByok)?;
        self.authorize(
            identity,
            &[ManagementScope::Secrets],
            AuthorizationTarget::CurrentPrincipal,
        )?;
        let operation_id = credential_operation_id(&scope, "refresh");
        let captured = claim_codex_refresh(self, identity, credential_id).await?;
        let provider_timeout = remaining_before(captured.network_deadline);
        let provider_result = tokio::time::timeout(
            provider_timeout,
            self.codex.refresh(&captured.token_material),
        )
        .await;
        let result = match provider_result {
            Ok(Ok(RefreshResult::Succeeded(tokens))) => {
                let next_identity = if tokens.account_id == captured.account_id {
                    captured.state_identity_version
                } else {
                    captured
                        .state_identity_version
                        .checked_add(1)
                        .ok_or(ApplicationError::Internal)?
                };
                let next_version = captured
                    .secret_version
                    .checked_add(1)
                    .ok_or(ApplicationError::Internal)?;
                let seal_timeout = remaining_before(captured.lease_expires_at)
                    .min(std::time::Duration::from_secs(10));
                match tokio::time::timeout(
                    seal_timeout,
                    prepare_codex_token(
                        self,
                        captured.credential_id,
                        next_version,
                        next_identity,
                        tokens,
                    ),
                )
                .await
                {
                    Ok(Ok(prepared)) => {
                        commit_codex_refresh_success(
                            self,
                            identity,
                            captured,
                            prepared,
                            operation_id,
                        )
                        .await?
                    }
                    Ok(Err(_)) | Err(_) => {
                        commit_codex_refresh_unknown(
                            self,
                            identity,
                            captured,
                            "local_token_protection",
                            operation_id,
                        )
                        .await?
                    }
                }
            }
            Ok(Ok(RefreshResult::Rejected)) => {
                commit_codex_refresh_failure(
                    self,
                    identity,
                    captured,
                    true,
                    "provider_rejected_refresh",
                    operation_id,
                )
                .await?
            }
            Ok(Ok(RefreshResult::TransientFailure)) => {
                commit_codex_refresh_failure(
                    self,
                    identity,
                    captured,
                    false,
                    "provider_transient_failure",
                    operation_id,
                )
                .await?
            }
            Ok(Err(CodexAdapterError::DependencyUnavailable)) | Err(_) => {
                // A transport failure after dispatch is ambiguous. Fail closed and require a new
                // login rather than replaying an undocumented refresh-token operation.
                commit_codex_refresh_unknown(
                    self,
                    identity,
                    captured,
                    "provider_transport",
                    operation_id,
                )
                .await?
            }
            Ok(Err(error)) => {
                commit_codex_refresh_failure(
                    self,
                    identity,
                    captured,
                    true,
                    match error {
                        CodexAdapterError::Rejected => "provider_rejected_refresh",
                        CodexAdapterError::UnsupportedContract => "unsupported_provider_contract",
                        CodexAdapterError::DependencyUnavailable => unreachable!(),
                    },
                    operation_id,
                )
                .await?
            }
        };
        self.publish_committed_runtime(&identity.request_id, operation_id)
            .await;
        Ok(result)
    }

    async fn execute_due_codex_refresh(
        &self,
        credential_id: CredentialId,
    ) -> Result<bool, ApplicationError> {
        let request_id = format!("worker-codex-refresh-{}", Uuid::now_v7());
        let claim =
            match claim_codex_refresh_with_owner(self, credential_id, request_id.clone(), true)
                .await
            {
                Ok(claim) => claim,
                Err(ApplicationError::Conflict(_)) | Err(ApplicationError::NotFound) => {
                    return Ok(false);
                }
                Err(error) => return Err(error),
            };
        let provider_result = tokio::time::timeout(
            remaining_before(claim.network_deadline),
            self.codex.refresh(&claim.token_material),
        )
        .await;
        match provider_result {
            Ok(Ok(RefreshResult::Succeeded(tokens))) => {
                let next_identity = if tokens.account_id == claim.account_id {
                    claim.state_identity_version
                } else {
                    claim
                        .state_identity_version
                        .checked_add(1)
                        .ok_or(ApplicationError::Internal)?
                };
                let next_version = claim
                    .secret_version
                    .checked_add(1)
                    .ok_or(ApplicationError::Internal)?;
                match tokio::time::timeout(
                    remaining_before(claim.lease_expires_at)
                        .min(std::time::Duration::from_secs(10)),
                    prepare_codex_token(
                        self,
                        claim.credential_id,
                        next_version,
                        next_identity,
                        tokens,
                    ),
                )
                .await
                {
                    Ok(Ok(prepared)) => {
                        commit_codex_refresh_success_internal(self, claim, prepared, &request_id)
                            .await?;
                    }
                    Ok(Err(_)) | Err(_) => {
                        commit_codex_refresh_unknown_internal(
                            self,
                            claim,
                            "local_token_protection",
                            &request_id,
                        )
                        .await?;
                    }
                }
            }
            Ok(Ok(RefreshResult::Rejected)) => {
                commit_codex_refresh_failure_internal(
                    self,
                    claim,
                    true,
                    "provider_rejected_refresh",
                    &request_id,
                )
                .await?;
            }
            Ok(Ok(RefreshResult::TransientFailure)) => {
                commit_codex_refresh_failure_internal(
                    self,
                    claim,
                    false,
                    "provider_transient_failure",
                    &request_id,
                )
                .await?;
            }
            Ok(Err(CodexAdapterError::DependencyUnavailable)) | Err(_) => {
                commit_codex_refresh_unknown_internal(
                    self,
                    claim,
                    "provider_transport",
                    &request_id,
                )
                .await?;
            }
            Ok(Err(error)) => {
                commit_codex_refresh_failure_internal(
                    self,
                    claim,
                    true,
                    match error {
                        CodexAdapterError::Rejected => "provider_rejected_refresh",
                        CodexAdapterError::UnsupportedContract => "unsupported_provider_contract",
                        CodexAdapterError::DependencyUnavailable => unreachable!(),
                    },
                    &request_id,
                )
                .await?;
            }
        }
        Ok(true)
    }

    pub(crate) async fn refresh_due_codex_credentials(
        &self,
        limit: u32,
    ) -> Result<u64, ApplicationError> {
        let ids = sqlx::query_scalar::<_, Uuid>(
            "SELECT auth.credential_id
             FROM upstream_credential_auth_state auth
             JOIN upstream_credentials credential ON credential.id=auth.credential_id
             WHERE auth.refresh_due_at<=now()
               AND (auth.refresh_backoff_until IS NULL OR auth.refresh_backoff_until<=now())
               AND credential.credential_kind='oauth_openai_codex'
               AND credential.administrative_status='active'
               AND credential.authentication_status IN ('ready','refresh_error')
             ORDER BY auth.refresh_due_at,auth.credential_id LIMIT $1",
        )
        .bind(i64::from(limit.clamp(1, 100)))
        .fetch_all(self.store.pool())
        .await?;
        let mut refreshed = 0_u64;
        for id in ids {
            if self
                .execute_due_codex_refresh(CredentialId::from_uuid(id))
                .await?
            {
                refreshed = refreshed.checked_add(1).ok_or(ApplicationError::Internal)?;
            }
        }
        Ok(refreshed)
    }

    pub async fn revoke_codex_credential(
        &self,
        identity: &RequestIdentity,
        credential_id: CredentialId,
    ) -> Result<CredentialLifecycleResult, ApplicationError> {
        let scope = ResourceScope::Deployment;
        authorize_credentials(self, identity, &scope, true, Capability::ManageByok)?;
        let operation_id = credential_operation_id(&scope, "revoke");
        let mut transaction = self.store.begin().await?;
        let row = sqlx::query(
            "SELECT credential_kind,state_identity_version FROM upstream_credentials
             WHERE organization_id IS NULL AND id=$1 FOR UPDATE",
        )
        .bind(credential_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        if row.try_get::<String, _>("credential_kind")? != "oauth_openai_codex" {
            return Err(ApplicationError::Conflict(
                "explicit revoke is available only for Codex credentials".to_owned(),
            ));
        }
        let next_identity = row
            .try_get::<i64, _>("state_identity_version")?
            .checked_add(1)
            .ok_or(ApplicationError::Internal)?;
        // The current community contract has no stable upstream revocation endpoint. Local revoke
        // therefore fails closed and records that no upstream call was available.
        sqlx::query(
            "UPDATE upstream_credentials SET administrative_status='revoked',
                    authentication_status='revoked',current_secret_version=NULL,
                    state_identity_version=$2,validation_evidence=$3,validated_at=now(),
                    etag_token=$4,updated_at=now() WHERE id=$1",
        )
        .bind(credential_id.as_uuid())
        .bind(next_identity)
        .bind(json!({"outcome":"accepted","upstream_revocation":"unsupported"}))
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let protected_ids = sqlx::query_scalar::<_, Uuid>(
            "SELECT protected_secret_version_id FROM upstream_credential_secret_versions
             WHERE credential_id=$1 AND protected_secret_version_id IS NOT NULL FOR UPDATE",
        )
        .bind(credential_id.as_uuid())
        .fetch_all(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE upstream_credential_secret_versions SET state='retired',retired_at=now(),
                    overlap_until=NULL,protected_secret_version_id=NULL
             WHERE credential_id=$1 AND state IN ('current','overlap')",
        )
        .bind(credential_id.as_uuid())
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE upstream_credential_refresh_leases SET state='outcome_unknown',
                    safe_outcome='{\"outcome\":\"cancelled_by_revoke\"}'::jsonb,completed_at=now()
             WHERE credential_id=$1 AND state='refreshing'",
        )
        .bind(credential_id.as_uuid())
        .execute(&mut *transaction)
        .await?;
        sqlx::query("DELETE FROM upstream_credential_auth_state WHERE credential_id=$1")
            .bind(credential_id.as_uuid())
            .execute(&mut *transaction)
            .await?;
        for protected_id in protected_ids {
            sqlx::query(
                "DELETE FROM protected_secret_versions WHERE id=$1
                 AND NOT EXISTS (
                    SELECT 1 FROM upstream_credential_secret_versions
                    WHERE protected_secret_version_id=$1 AND state IN ('current','overlap')
                 )",
            )
            .bind(protected_id)
            .execute(&mut *transaction)
            .await?;
        }
        let pending = sqlx::query(
            "SELECT id,login_secret_id FROM upstream_credential_login_sessions
             WHERE credential_id=$1 AND state IN ('pending','polling') FOR UPDATE",
        )
        .bind(credential_id.as_uuid())
        .fetch_all(&mut *transaction)
        .await?;
        for login in pending {
            terminalize_codex_login(
                &mut transaction,
                CredentialLoginSessionId::from_uuid(login.try_get("id")?),
                "cancelled",
                login.try_get("login_secret_id")?,
            )
            .await?;
        }
        let (credential, _) = load_credential(&mut *transaction, &scope, credential_id).await?;
        let result = CredentialLifecycleResult {
            credential,
            operation: "revoke".to_owned(),
            outcome: "accepted".to_owned(),
        };
        commit_credential(
            self,
            transaction,
            identity,
            &scope,
            credential_id,
            operation_id,
            &[
                "administrative_status",
                "authentication_status",
                "current_secret_version",
                "state_identity_version",
            ],
            true,
        )
        .await?;
        self.publish_committed_runtime(&identity.request_id, operation_id)
            .await;
        Ok(result)
    }

    pub(crate) async fn reconcile_codex_login_sessions(
        &self,
        limit: u32,
    ) -> Result<u64, ApplicationError> {
        let limit = i64::from(limit.clamp(1, 100));
        let mut transaction = self.store.begin().await?;
        let sessions = sqlx::query(
            "SELECT session.id,session.credential_id,session.state,session.login_secret_id,
                    session.credential_state_identity_version,session.expires_at,
                    credential.state_identity_version AS current_identity
             FROM upstream_credential_login_sessions session
             JOIN upstream_credentials credential ON credential.id=session.credential_id
             WHERE (session.state='pending' AND session.expires_at<=now())
                OR (session.state='polling' AND (
                    session.expires_at<=now() OR session.claim_expires_at<=now()))
                OR (session.state='exchanging' AND session.claim_expires_at<=now())
             ORDER BY COALESCE(session.claim_expires_at,session.expires_at),session.id
             LIMIT $1 FOR UPDATE OF session,credential SKIP LOCKED",
        )
        .bind(limit)
        .fetch_all(&mut *transaction)
        .await?;
        let mut reset_polling = 0_u64;
        let mut terminalized = 0_u64;
        let mut changed_credentials = 0_u64;
        for session in &sessions {
            let session_id: Uuid = session.try_get("id")?;
            let credential_id: Uuid = session.try_get("credential_id")?;
            let state: String = session.try_get("state")?;
            let expired = session.try_get::<DateTime<Utc>, _>("expires_at")? <= Utc::now();
            if state == "polling" && !expired {
                let changed = sqlx::query(
                    "UPDATE upstream_credential_login_sessions
                     SET state='pending',attempt_token=NULL,claim_expires_at=NULL,updated_at=now()
                     WHERE id=$1 AND state='polling' AND claim_expires_at<=now()",
                )
                .bind(session_id)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                reset_polling = reset_polling
                    .checked_add(changed)
                    .ok_or(ApplicationError::Internal)?;
                continue;
            }
            let login_secret_id: Option<Uuid> = session.try_get("login_secret_id")?;
            let terminal_state = if state == "exchanging" {
                "failed"
            } else {
                "expired"
            };
            let safe_display = if state == "exchanging" {
                json!({
                    "display_available":false,
                    "safe_error":"token_exchange_outcome_unknown"
                })
            } else {
                json!({"display_available":false})
            };
            let changed = sqlx::query(
                "UPDATE upstream_credential_login_sessions
                 SET state=$2,attempt_token=NULL,claim_expires_at=NULL,login_secret_id=NULL,
                     safe_display=$3,next_poll_at=NULL,terminal_cleanup_at=now(),updated_at=now()
                 WHERE id=$1 AND state IN ('pending','polling','exchanging')",
            )
            .bind(session_id)
            .bind(terminal_state)
            .bind(safe_display)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            if changed != 1 {
                continue;
            }
            if let Some(login_secret_id) = login_secret_id {
                sqlx::query("DELETE FROM protected_secret_versions WHERE id=$1")
                    .bind(login_secret_id)
                    .execute(&mut *transaction)
                    .await?;
            }
            terminalized = terminalized
                .checked_add(1)
                .ok_or(ApplicationError::Internal)?;
            if session.try_get::<i64, _>("credential_state_identity_version")?
                == session.try_get::<i64, _>("current_identity")?
            {
                changed_credentials = changed_credentials
                    .checked_add(
                        sqlx::query(
                            "UPDATE upstream_credentials
                             SET authentication_status=CASE
                                    WHEN current_secret_version IS NULL THEN 'login_required'
                                    ELSE 'ready' END,
                                 validation_evidence=$2,validated_at=now(),
                                 etag_token=$3,updated_at=now()
                             WHERE id=$1 AND authentication_status='login_pending'",
                        )
                        .bind(credential_id)
                        .bind(if state == "exchanging" {
                            json!({
                                "outcome":"unknown",
                                "reason":"codex_token_exchange_claim_expired"
                            })
                        } else {
                            json!({"outcome":"expired","reason":"codex_login_expired"})
                        })
                        .bind(Uuid::now_v7())
                        .execute(&mut *transaction)
                        .await?
                        .rows_affected(),
                    )
                    .ok_or(ApplicationError::Internal)?;
            }
        }
        if sessions.is_empty() {
            transaction.commit().await?;
        } else {
            self.store
                .commit_command(
                    transaction,
                    &AuditRecord {
                        actor: None,
                        authentication_evidence: json!({"method":"internal_worker"}),
                        organization_id: None,
                        target_resource_kind: "codex_login_session".to_owned(),
                        target_resource_id: None,
                        operation_id: "system.workers.codex_login_sessions.reconcile".to_owned(),
                        outcome: "accepted",
                        request_id: format!("worker-codex-login-{}", Uuid::now_v7()),
                        changed_fields: vec!["expired_claims".to_owned()],
                        safe_details: json!({
                            "reset_polling_claims":reset_polling,
                            "terminalized_sessions":terminalized,
                            "changed_credentials":changed_credentials,
                        }),
                    },
                    Some(&RuntimeEvent {
                        event_kind: "upstream_credential.codex_login_reconciled".to_owned(),
                        affected_scope: json!({"changed_credentials":changed_credentials}),
                        security_tightening: changed_credentials > 0,
                    }),
                )
                .await?;
        }
        Ok(changed_credentials)
    }

    pub(crate) async fn reconcile_expired_codex_refresh_leases(
        &self,
        limit: u32,
    ) -> Result<u64, ApplicationError> {
        let limit = i64::from(limit.clamp(1, 100));
        let mut transaction = self.store.begin().await?;
        let leases = sqlx::query(
            "SELECT lease.id,lease.credential_id,lease.credential_state_identity_version,
                    lease.secret_version,lease.token_fingerprint,lease.refresh_fence,
                    credential.state_identity_version AS current_identity,
                    credential.current_secret_version,credential.authentication_status,
                    auth.credential_state_identity_version AS auth_identity,
                    auth.token_fingerprint AS auth_fingerprint,auth.refresh_fence AS auth_fence
             FROM upstream_credential_refresh_leases lease
             JOIN upstream_credentials credential ON credential.id=lease.credential_id
             LEFT JOIN upstream_credential_auth_state auth ON auth.credential_id=lease.credential_id
             WHERE lease.state='refreshing' AND lease.lease_expires_at<=now()
             ORDER BY lease.lease_expires_at,lease.id
             LIMIT $1 FOR UPDATE OF lease,credential SKIP LOCKED",
        )
        .bind(limit)
        .fetch_all(&mut *transaction)
        .await?;
        let mut changed_credentials = 0_u64;
        for lease in &leases {
            let lease_id: Uuid = lease.try_get("id")?;
            let credential_id: Uuid = lease.try_get("credential_id")?;
            let identity: i64 = lease.try_get("credential_state_identity_version")?;
            let secret_version: i64 = lease.try_get("secret_version")?;
            let fingerprint: Vec<u8> = lease.try_get("token_fingerprint")?;
            let fence: i64 = lease.try_get("refresh_fence")?;
            let still_current = lease.try_get::<i64, _>("current_identity")? == identity
                && lease.try_get::<Option<i64>, _>("current_secret_version")?
                    == Some(secret_version)
                && lease.try_get::<String, _>("authentication_status")? == "refreshing"
                && lease.try_get::<Option<i64>, _>("auth_identity")? == Some(identity)
                && lease
                    .try_get::<Option<Vec<u8>>, _>("auth_fingerprint")?
                    .as_deref()
                    == Some(fingerprint.as_slice())
                && lease.try_get::<Option<i64>, _>("auth_fence")? == Some(fence);
            sqlx::query(
                "UPDATE upstream_credential_refresh_leases SET state='outcome_unknown',
                        safe_outcome=$2,completed_at=now()
                 WHERE id=$1 AND state='refreshing'",
            )
            .bind(lease_id)
            .bind(if still_current {
                json!({"outcome":"unknown","reason":"lease_expired"})
            } else {
                json!({"outcome":"unknown","reason":"lease_expired_after_fence"})
            })
            .execute(&mut *transaction)
            .await?;
            if still_current {
                sqlx::query(
                    "UPDATE upstream_credentials SET authentication_status='refresh_outcome_unknown',
                            validation_evidence=$2,validated_at=now(),etag_token=$3,updated_at=now()
                     WHERE id=$1 AND authentication_status='refreshing'",
                )
                .bind(credential_id)
                .bind(json!({"outcome":"unknown","reason":"refresh_lease_expired"}))
                .bind(Uuid::now_v7())
                .execute(&mut *transaction)
                .await?;
                sqlx::query(
                    "UPDATE upstream_credential_auth_state SET refresh_due_at=NULL,
                            refresh_backoff_until=NULL,last_safe_error=$2,updated_at=now()
                     WHERE credential_id=$1 AND credential_state_identity_version=$3
                       AND token_fingerprint=$4 AND refresh_fence=$5",
                )
                .bind(credential_id)
                .bind(json!({"reason":"refresh_lease_expired"}))
                .bind(identity)
                .bind(&fingerprint)
                .bind(fence)
                .execute(&mut *transaction)
                .await?;
                changed_credentials = changed_credentials
                    .checked_add(1)
                    .ok_or(ApplicationError::Internal)?;
            }
        }
        if leases.is_empty() {
            transaction.commit().await?;
        } else {
            self.store
                .commit_command(
                    transaction,
                    &AuditRecord {
                        actor: None,
                        authentication_evidence: json!({"method":"internal_worker"}),
                        organization_id: None,
                        target_resource_kind: "codex_refresh_lease".to_owned(),
                        target_resource_id: None,
                        operation_id: "system.workers.codex_refresh_leases.reconcile".to_owned(),
                        outcome: "accepted",
                        request_id: format!("worker-codex-refresh-{}", Uuid::now_v7()),
                        changed_fields: vec!["expired_leases".to_owned()],
                        safe_details: json!({
                            "terminalized_leases": leases.len(),
                            "changed_credentials": changed_credentials,
                        }),
                    },
                    Some(&RuntimeEvent {
                        event_kind: "upstream_credential.refresh_lease_reconciled".to_owned(),
                        affected_scope: json!({"changed_credentials":changed_credentials}),
                        security_tightening: changed_credentials > 0,
                    }),
                )
                .await?;
        }
        Ok(changed_credentials)
    }

    pub fn start_codex_credential_workers(self: &std::sync::Arc<Self>) {
        let application = std::sync::Arc::downgrade(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let Some(application) = application.upgrade() else {
                    break;
                };
                let login_changed = match application.reconcile_codex_login_sessions(100).await {
                    Ok(changed) => changed,
                    Err(error) => {
                        tracing::error!(%error, "could not reconcile Codex login sessions");
                        0
                    }
                };
                let refresh_changed = match application
                    .reconcile_expired_codex_refresh_leases(100)
                    .await
                {
                    Ok(changed) => changed,
                    Err(error) => {
                        tracing::error!(%error, "could not reconcile expired Codex refresh leases");
                        0
                    }
                };
                let due_refreshed = match application.refresh_due_codex_credentials(10).await {
                    Ok(changed) => changed,
                    Err(error) => {
                        tracing::error!(%error, "could not refresh due Codex credentials");
                        0
                    }
                };
                if (login_changed > 0 || refresh_changed > 0 || due_refreshed > 0)
                    && let Err(error) = application.runtime.refresh_now().await
                {
                    tracing::error!(%error, login_changed, refresh_changed, due_refreshed, "Codex credential worker committed with runtime publication pending");
                }
            }
        });
    }
}

const CREDENTIAL_SELECT_LIST: &str =
    "SELECT credential.id,credential.resource_scope_kind,credential.organization_id,
            credential.name,credential.credential_kind,credential.secret_source_kind,
            credential.source_configuration,credential.injection_kind,credential.sharing_policy,
            credential.administrative_status,credential.authentication_status,
            credential.current_secret_version,credential.state_identity_version,
            credential.safe_metadata,credential.validation_evidence,credential.etag_token,
            credential.created_at,credential.updated_at,credential.validated_at,
            current_secret.id AS current_secret_version_id,overlap_secret.overlap_until
     FROM upstream_credentials credential
     LEFT JOIN upstream_credential_secret_versions current_secret
       ON current_secret.credential_id=credential.id AND current_secret.state='current'
     LEFT JOIN upstream_credential_secret_versions overlap_secret
       ON overlap_secret.credential_id=credential.id AND overlap_secret.state='overlap'
     WHERE credential.organization_id IS NOT DISTINCT FROM $1 AND ($2::uuid IS NULL OR credential.id>$2)
     ORDER BY credential.id LIMIT $3";

async fn load_credential<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    scope: &ResourceScope,
    id: CredentialId,
) -> Result<(UpstreamCredential, EntityTag), ApplicationError> {
    let (_, organization_id) = scope_columns(scope);
    let row = sqlx::query(
        "SELECT credential.id,credential.resource_scope_kind,credential.organization_id,
                credential.name,credential.credential_kind,credential.secret_source_kind,
                credential.source_configuration,credential.injection_kind,credential.sharing_policy,
                credential.administrative_status,credential.authentication_status,
                credential.current_secret_version,credential.state_identity_version,
                credential.safe_metadata,credential.validation_evidence,credential.etag_token,
                credential.created_at,credential.updated_at,credential.validated_at,
                current_secret.id AS current_secret_version_id,overlap_secret.overlap_until
         FROM upstream_credentials credential
         LEFT JOIN upstream_credential_secret_versions current_secret
           ON current_secret.credential_id=credential.id AND current_secret.state='current'
         LEFT JOIN upstream_credential_secret_versions overlap_secret
           ON overlap_secret.credential_id=credential.id AND overlap_secret.state='overlap'
         WHERE credential.organization_id IS NOT DISTINCT FROM $1 AND credential.id=$2",
    )
    .bind(organization_id)
    .bind(id.as_uuid())
    .fetch_optional(executor)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    let tag = EntityTag::for_resource(
        "upstream_credential",
        id.as_uuid(),
        row.try_get("etag_token")?,
    );
    Ok((credential_from_row(row)?, tag))
}

fn credential_from_row(row: sqlx::postgres::PgRow) -> Result<UpstreamCredential, ApplicationError> {
    let organization_id = row.try_get::<Option<Uuid>, _>("organization_id")?;
    Ok(UpstreamCredential {
        id: CredentialId::from_uuid(row.try_get("id")?),
        resource_scope: match row.try_get::<String, _>("resource_scope_kind")?.as_str() {
            "deployment" => ResourceScope::Deployment,
            "organization" => ResourceScope::Organization {
                organization_id: OrganizationId::from_uuid(
                    organization_id.ok_or(ApplicationError::Internal)?,
                ),
            },
            _ => return Err(ApplicationError::Internal),
        },
        name: row.try_get("name")?,
        credential_kind: parse_credential_kind(&row.try_get::<String, _>("credential_kind")?)?,
        secret_source_kind: parse_source_kind(&row.try_get::<String, _>("secret_source_kind")?)?,
        source_configuration: row.try_get("source_configuration")?,
        injection_kind: row.try_get("injection_kind")?,
        sharing_policy: row.try_get("sharing_policy")?,
        administrative_status: parse_status(&row.try_get::<String, _>("administrative_status")?)?,
        authentication_status: row.try_get("authentication_status")?,
        current_secret_version: row.try_get("current_secret_version")?,
        state_identity_version: row.try_get("state_identity_version")?,
        safe_metadata: row.try_get("safe_metadata")?,
        validation_evidence: row.try_get("validation_evidence")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        validated_at: row.try_get("validated_at")?,
        current_secret_version_id: row
            .try_get::<Option<Uuid>, _>("current_secret_version_id")?
            .map(CredentialSecretVersionId::from_uuid),
        overlap_until: row.try_get("overlap_until")?,
    })
}

struct SealedProtectedVersion {
    material_id: CredentialSecretVersionId,
    scope_kind: &'static str,
    organization_id: Option<Uuid>,
    owner_generation: i64,
    secret_version: i64,
    provider_id: String,
    provider_format_version: i32,
    envelope: Vec<u8>,
    fingerprint: Vec<u8>,
}

async fn seal_protected_version(
    application: &Application,
    scope: &ResourceScope,
    credential_id: CredentialId,
    material_id: CredentialSecretVersionId,
    owner_generation: u64,
    secret_version: u64,
    plaintext: &SecretPlaintext,
) -> Result<SealedProtectedVersion, ApplicationError> {
    let context = credential_context(
        application.store.installation_id(),
        scope,
        credential_id,
        material_id,
        owner_generation,
        secret_version,
        application.secrets.write_pair(),
    )?;
    let envelope = application
        .secrets
        .seal(&context, plaintext)
        .await
        .map_err(|error| {
            tracing::error!(%error, credential_id=%credential_id, "credential secret protection failed");
            ApplicationError::DependencyUnavailable
        })?;
    let fingerprint = plaintext
        .expose(|value| {
            application
                .secrets
                .safe_fingerprint(application.store.installation_id(), value)
        })
        .map_err(|_| ApplicationError::Internal)?;
    let (scope_kind, organization_id) = match scope {
        ResourceScope::Deployment => ("system", None),
        ResourceScope::Organization { organization_id } => {
            ("organization", Some(organization_id.as_uuid()))
        }
    };
    Ok(SealedProtectedVersion {
        material_id,
        scope_kind,
        organization_id,
        owner_generation: i64::try_from(owner_generation)
            .map_err(|_| ApplicationError::Internal)?,
        secret_version: i64::try_from(secret_version).map_err(|_| ApplicationError::Internal)?,
        provider_id: context.parts().provider_id.as_str().to_owned(),
        provider_format_version: i32::try_from(context.parts().provider_format_version.get())
            .map_err(|_| ApplicationError::Internal)?,
        envelope: envelope.expose(<[u8]>::to_vec),
        fingerprint: fingerprint.to_vec(),
    })
}

async fn persist_protected_version(
    transaction: &mut Transaction<'_, Postgres>,
    credential_id: CredentialId,
    sealed: &SealedProtectedVersion,
    state: &str,
) -> Result<(), ApplicationError> {
    sqlx::query(
        "INSERT INTO protected_secret_versions(
            id,scope_kind,organization_id,owner_kind,owner_id,owner_generation,secret_version,
            field_purpose,custody_provider_id,provider_format_version,context_version,opaque_envelope
         ) VALUES ($1,$2,$3,'upstream_credential',$4,$5,$6,'upstream_credential_material',$7,$8,1,$9)",
    )
    .bind(sealed.material_id.as_uuid())
    .bind(sealed.scope_kind)
    .bind(sealed.organization_id)
    .bind(credential_id.as_uuid())
    .bind(sealed.owner_generation)
    .bind(sealed.secret_version)
    .bind(&sealed.provider_id)
    .bind(sealed.provider_format_version)
    .bind(&sealed.envelope)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "INSERT INTO upstream_credential_secret_versions(
            id,credential_id,version,credential_state_identity_version,
            protected_secret_version_id,safe_fingerprint,state
         ) VALUES ($1,$2,$3,$4,$1,$5,$6)",
    )
    .bind(sealed.material_id.as_uuid())
    .bind(credential_id.as_uuid())
    .bind(sealed.secret_version)
    .bind(sealed.owner_generation)
    .bind(&sealed.fingerprint)
    .bind(state)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn require_static_database_credential(row: &sqlx::postgres::PgRow) -> Result<(), ApplicationError> {
    if row.try_get::<String, _>("secret_source_kind")? != "encrypted_database" {
        return Err(ApplicationError::Conflict(
            "only encrypted-database credentials accept secret replacement".to_owned(),
        ));
    }
    if row.try_get::<String, _>("credential_kind")? == "oauth_openai_codex" {
        return Err(ApplicationError::Conflict(
            "Codex token material is changed only by the login and refresh state machines"
                .to_owned(),
        ));
    }
    Ok(())
}

async fn insert_source_version(
    transaction: &mut Transaction<'_, Postgres>,
    credential_id: CredentialId,
    material_id: CredentialSecretVersionId,
    version: i64,
    state_identity_version: i64,
    configuration: &Value,
) -> Result<(), ApplicationError> {
    let fingerprint =
        Sha256::digest(serde_json::to_vec(configuration).map_err(|_| ApplicationError::Internal)?);
    sqlx::query(
        "INSERT INTO upstream_credential_secret_versions(
            id,credential_id,version,credential_state_identity_version,
            source_configuration,safe_fingerprint,state
         ) VALUES ($1,$2,$3,$4,$5,$6,'current')",
    )
    .bind(material_id.as_uuid())
    .bind(credential_id.as_uuid())
    .bind(version)
    .bind(state_identity_version)
    .bind(configuration)
    .bind(fingerprint.to_vec())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

struct CapturedCodexLogin {
    attempt_token: Uuid,
    state_identity_version: i64,
    login_secret_id: Uuid,
    polling_material: DevicePollingMaterial,
    poll_interval_seconds: u32,
}

struct ClaimedCodexRefresh {
    lease_id: Uuid,
    network_deadline: DateTime<Utc>,
    credential_id: CredentialId,
    secret_version: i64,
    state_identity_version: i64,
    token_fingerprint: Vec<u8>,
    refresh_fence: i64,
    attempt_token: Uuid,
    credential_etag_token: Uuid,
    lease_expires_at: DateTime<Utc>,
    account_id: String,
    protected_secret_id: Uuid,
    token_material: TokenMaterial,
}

struct PreparedCodexToken {
    sealed: SealedProtectedVersion,
    account_id: String,
    token_expires_at: Option<DateTime<Utc>>,
    token_fingerprint: Vec<u8>,
}

async fn claim_codex_login(
    application: &Application,
    credential_id: CredentialId,
    session_id: CredentialLoginSessionId,
) -> Result<CapturedCodexLogin, ApplicationError> {
    let attempt_token = Uuid::now_v7();
    let mut transaction = application.store.begin().await?;
    let row = sqlx::query(
        "SELECT session.credential_state_identity_version,session.login_secret_id,
                session.poll_interval_seconds,session.next_poll_at,session.expires_at,
                protected.owner_generation,protected.secret_version,protected.opaque_envelope,
                protected.custody_provider_id,protected.provider_format_version,
                protected.context_version
         FROM upstream_credential_login_sessions session
         JOIN upstream_credentials credential ON credential.id=session.credential_id
         JOIN protected_secret_versions protected ON protected.id=session.login_secret_id
         WHERE session.credential_id=$1 AND session.id=$2
           AND (session.state='pending'
             OR (session.state='polling' AND session.claim_expires_at<=now()))
           AND session.next_poll_at<=now() AND session.expires_at>now()
           AND credential.state_identity_version=session.credential_state_identity_version
           AND credential.credential_kind='oauth_openai_codex'
           AND credential.secret_source_kind='encrypted_database'
           AND credential.administrative_status='active'
         FOR UPDATE OF session",
    )
    .bind(credential_id.as_uuid())
    .bind(session_id.as_uuid())
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| ApplicationError::Conflict("Codex login session is not due".to_owned()))?;
    let login_secret_id: Uuid = row.try_get("login_secret_id")?;
    let state_identity_version: i64 = row.try_get("credential_state_identity_version")?;
    let context = codex_login_context(
        application.store.installation_id(),
        session_id,
        CredentialSecretVersionId::from_uuid(login_secret_id),
        u64::try_from(row.try_get::<i64, _>("owner_generation")?)
            .map_err(|_| ApplicationError::Internal)?,
        &custody_pair_from_row(&row)?,
    )?;
    if row.try_get::<i64, _>("secret_version")? != 1
        || row.try_get::<i32, _>("context_version")? != 1
    {
        return Err(ApplicationError::Internal);
    }
    let envelope = OpaqueEnvelope::new(row.try_get::<Vec<u8>, _>("opaque_envelope")?)
        .map_err(|_| ApplicationError::Internal)?;
    let claimed = sqlx::query(
        "UPDATE upstream_credential_login_sessions
         SET state='polling',attempt_token=$3,claim_expires_at=now()+interval '40 seconds',
             updated_at=now()
         WHERE credential_id=$1 AND id=$2
           AND (state='pending' OR (state='polling' AND claim_expires_at<=now()))",
    )
    .bind(credential_id.as_uuid())
    .bind(session_id.as_uuid())
    .bind(attempt_token)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if claimed != 1 {
        return Err(ApplicationError::Conflict(
            "Codex login session was claimed concurrently".to_owned(),
        ));
    }
    transaction.commit().await?;
    let plaintext = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        application.secrets.open(&context, &envelope),
    )
    .await
    {
        Ok(Ok(plaintext)) => plaintext,
        Ok(Err(_)) | Err(_) => {
            let mut transaction = application.store.begin().await?;
            sqlx::query(
                "UPDATE upstream_credential_login_sessions
                 SET state='pending',attempt_token=NULL,claim_expires_at=NULL,updated_at=now()
                 WHERE credential_id=$1 AND id=$2 AND state='polling' AND attempt_token=$3",
            )
            .bind(credential_id.as_uuid())
            .bind(session_id.as_uuid())
            .bind(attempt_token)
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            return Err(ApplicationError::DependencyUnavailable);
        }
    };
    let polling_material = plaintext
        .expose(|bytes| serde_json::from_slice::<DevicePollingMaterial>(bytes))
        .map_err(|_| ApplicationError::Internal)?;
    Ok(CapturedCodexLogin {
        attempt_token,
        state_identity_version,
        login_secret_id,
        polling_material,
        poll_interval_seconds: u32::try_from(row.try_get::<i32, _>("poll_interval_seconds")?)
            .map_err(|_| ApplicationError::Internal)?,
    })
}

async fn fail_claimed_codex_login(
    application: &Application,
    credential_id: CredentialId,
    session_id: CredentialLoginSessionId,
    attempt_token: Uuid,
    login_secret_id: Uuid,
    reason: &'static str,
) -> Result<(), ApplicationError> {
    let mut transaction = application.store.begin().await?;
    let changed = sqlx::query(
        "UPDATE upstream_credential_login_sessions
         SET state='failed',attempt_token=NULL,claim_expires_at=NULL,login_secret_id=NULL,
             safe_display=$5,next_poll_at=NULL,terminal_cleanup_at=now(),updated_at=now()
         WHERE credential_id=$1 AND id=$2 AND state IN ('polling','exchanging')
           AND attempt_token=$3 AND login_secret_id=$4",
    )
    .bind(credential_id.as_uuid())
    .bind(session_id.as_uuid())
    .bind(attempt_token)
    .bind(login_secret_id)
    .bind(json!({"display_available":false,"safe_error":reason}))
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed == 1 {
        sqlx::query("DELETE FROM protected_secret_versions WHERE id=$1")
            .bind(login_secret_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "UPDATE upstream_credentials SET authentication_status=CASE
                WHEN current_secret_version IS NULL THEN 'login_required' ELSE 'ready' END,
                etag_token=$2,updated_at=now() WHERE id=$1",
        )
        .bind(credential_id.as_uuid())
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}

async fn prepare_codex_token(
    application: &Application,
    credential_id: CredentialId,
    next_version: i64,
    next_identity: i64,
    token_set: TokenSet,
) -> Result<PreparedCodexToken, ApplicationError> {
    let TokenSet {
        material,
        account_id,
        token_expires_at,
    } = token_set;
    let token_payload = SecretPlaintext::new(
        serde_json::to_vec(&material).map_err(|_| ApplicationError::Internal)?,
    )
    .map_err(|_| ApplicationError::Internal)?;
    let token_fingerprint = token_payload.expose(codex_token_fingerprint);
    let sealed = seal_protected_version(
        application,
        &ResourceScope::Deployment,
        credential_id,
        CredentialSecretVersionId::new(),
        u64::try_from(next_identity).map_err(|_| ApplicationError::Internal)?,
        u64::try_from(next_version).map_err(|_| ApplicationError::Internal)?,
        &token_payload,
    )
    .await?;
    Ok(PreparedCodexToken {
        sealed,
        account_id,
        token_expires_at,
        token_fingerprint,
    })
}

async fn activate_codex_token(
    transaction: &mut Transaction<'_, Postgres>,
    credential_id: CredentialId,
    prepared: &PreparedCodexToken,
) -> Result<(), ApplicationError> {
    let next_identity = prepared.sealed.owner_generation;
    let next_version = prepared.sealed.secret_version;
    let old_protected_ids = sqlx::query_scalar::<_, Uuid>(
        "SELECT protected_secret_version_id FROM upstream_credential_secret_versions
         WHERE credential_id=$1 AND protected_secret_version_id IS NOT NULL
           AND state IN ('current','overlap') FOR UPDATE",
    )
    .bind(credential_id.as_uuid())
    .fetch_all(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE upstream_credential_secret_versions SET state='retired',retired_at=now(),
                overlap_until=NULL,protected_secret_version_id=NULL
         WHERE credential_id=$1 AND state IN ('current','overlap')",
    )
    .bind(credential_id.as_uuid())
    .execute(&mut **transaction)
    .await?;
    sqlx::query("UPDATE upstream_credentials SET state_identity_version=$2 WHERE id=$1")
        .bind(credential_id.as_uuid())
        .bind(next_identity)
        .execute(&mut **transaction)
        .await?;
    persist_protected_version(transaction, credential_id, &prepared.sealed, "current").await?;
    let safe_metadata = json!({"account_id":prepared.account_id});
    sqlx::query(
        "UPDATE upstream_credentials SET current_secret_version=$2,
                authentication_status='ready',safe_metadata=$3,
                validation_evidence='{\"outcome\":\"accepted\",\"validation_kind\":\"codex_oauth\"}'::jsonb,
                validated_at=now(),etag_token=$4,updated_at=now() WHERE id=$1",
    )
    .bind(credential_id.as_uuid())
    .bind(next_version)
    .bind(safe_metadata)
    .bind(Uuid::now_v7())
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "INSERT INTO upstream_credential_auth_state(
            credential_id,credential_state_identity_version,token_fingerprint,
            token_expires_at,refresh_due_at,refresh_failure_count,refresh_fence
         ) VALUES ($1,$2,$3,$4,$5,0,0)
         ON CONFLICT (credential_id) DO UPDATE SET
            credential_state_identity_version=EXCLUDED.credential_state_identity_version,
            token_fingerprint=EXCLUDED.token_fingerprint,
            token_expires_at=EXCLUDED.token_expires_at,
            refresh_due_at=EXCLUDED.refresh_due_at,refresh_backoff_until=NULL,
            refresh_failure_count=0,refresh_fence=0,last_safe_error=NULL,updated_at=now()",
    )
    .bind(credential_id.as_uuid())
    .bind(next_identity)
    .bind(&prepared.token_fingerprint)
    .bind(prepared.token_expires_at)
    .bind(
        prepared
            .token_expires_at
            .map(|expiry| expiry - Duration::minutes(5)),
    )
    .execute(&mut **transaction)
    .await?;
    for protected_id in old_protected_ids {
        sqlx::query("DELETE FROM protected_secret_versions WHERE id=$1")
            .bind(protected_id)
            .execute(&mut **transaction)
            .await?;
    }
    Ok(())
}

fn codex_token_fingerprint(bytes: &[u8]) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(b"owlrora/codex-token/fence/v1\0");
    digest.update(bytes);
    digest.finalize().to_vec()
}

async fn claim_codex_refresh(
    application: &Application,
    identity: &RequestIdentity,
    credential_id: CredentialId,
) -> Result<ClaimedCodexRefresh, ApplicationError> {
    claim_codex_refresh_with_owner(
        application,
        credential_id,
        format!("management:{}", identity.request_id),
        false,
    )
    .await
}

async fn claim_codex_refresh_with_owner(
    application: &Application,
    credential_id: CredentialId,
    lease_owner: String,
    require_due: bool,
) -> Result<ClaimedCodexRefresh, ApplicationError> {
    let mut transaction = application.store.begin().await?;
    let row = sqlx::query(
        "SELECT credential.current_secret_version,credential.state_identity_version,
                credential.credential_kind,credential.administrative_status,
                credential.authentication_status,credential.etag_token,credential.safe_metadata,
                auth.token_fingerprint,auth.refresh_fence,
                secret.protected_secret_version_id,protected.owner_generation,
                protected.secret_version AS protected_version,protected.opaque_envelope,
                protected.custody_provider_id,protected.provider_format_version,
                protected.context_version
         FROM upstream_credentials credential
         JOIN upstream_credential_auth_state auth ON auth.credential_id=credential.id
         JOIN upstream_credential_secret_versions secret
           ON secret.credential_id=credential.id
          AND secret.version=credential.current_secret_version AND secret.state='current'
         JOIN protected_secret_versions protected ON protected.id=secret.protected_secret_version_id
         WHERE credential.organization_id IS NULL AND credential.id=$1 FOR UPDATE OF credential,auth",
    )
    .bind(credential_id.as_uuid())
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    require_codex_active(&row)?;
    if row.try_get::<String, _>("authentication_status")? == "refresh_outcome_unknown" {
        return Err(ApplicationError::Conflict(
            "refresh outcome is unknown and requires reauthentication".to_owned(),
        ));
    }
    if require_due {
        let due = sqlx::query_scalar::<_, bool>(
            "SELECT refresh_due_at<=now()
                 AND (refresh_backoff_until IS NULL OR refresh_backoff_until<=now())
             FROM upstream_credential_auth_state WHERE credential_id=$1",
        )
        .bind(credential_id.as_uuid())
        .fetch_one(&mut *transaction)
        .await?;
        if !due {
            return Err(ApplicationError::Conflict(
                "Codex credential refresh is not due".to_owned(),
            ));
        }
    }
    let secret_version = row
        .try_get::<Option<i64>, _>("current_secret_version")?
        .ok_or_else(|| {
            ApplicationError::Conflict("Codex credential is not logged in".to_owned())
        })?;
    let state_identity_version: i64 = row.try_get("state_identity_version")?;
    let token_fingerprint = row
        .try_get::<Option<Vec<u8>>, _>("token_fingerprint")?
        .ok_or(ApplicationError::Internal)?;
    let refresh_fence = row
        .try_get::<i64, _>("refresh_fence")?
        .checked_add(1)
        .ok_or(ApplicationError::Internal)?;
    let lease_id = Uuid::now_v7();
    let attempt_token = Uuid::now_v7();
    let lease_expires_at = Utc::now()
        .checked_add_signed(Duration::seconds(55))
        .ok_or(ApplicationError::Internal)?;
    let custody_deadline = Utc::now()
        .checked_add_signed(Duration::seconds(10))
        .ok_or(ApplicationError::Internal)?;
    let network_deadline = Utc::now()
        .checked_add_signed(Duration::seconds(40))
        .ok_or(ApplicationError::Internal)?;
    let safe_metadata: Value = row.try_get("safe_metadata")?;
    let account_id = safe_metadata
        .get("account_id")
        .and_then(Value::as_str)
        .ok_or(ApplicationError::Internal)?
        .to_owned();
    let protected_secret_id: Uuid = row.try_get("protected_secret_version_id")?;
    let context = credential_context(
        application.store.installation_id(),
        &ResourceScope::Deployment,
        credential_id,
        CredentialSecretVersionId::from_uuid(protected_secret_id),
        u64::try_from(row.try_get::<i64, _>("owner_generation")?)
            .map_err(|_| ApplicationError::Internal)?,
        u64::try_from(row.try_get::<i64, _>("protected_version")?)
            .map_err(|_| ApplicationError::Internal)?,
        &custody_pair_from_row(&row)?,
    )?;
    if row.try_get::<i32, _>("context_version")? != 1 {
        return Err(ApplicationError::Internal);
    }
    let envelope = OpaqueEnvelope::new(row.try_get::<Vec<u8>, _>("opaque_envelope")?)
        .map_err(|_| ApplicationError::Internal)?;
    transaction.commit().await?;
    let custody_timeout = remaining_before(custody_deadline);
    let plaintext = match tokio::time::timeout(
        custody_timeout,
        application.secrets.open(&context, &envelope),
    )
    .await
    {
        Ok(Ok(plaintext)) => plaintext,
        Ok(Err(_)) | Err(_) => return Err(ApplicationError::DependencyUnavailable),
    };
    let token_material = plaintext
        .expose(|bytes| serde_json::from_slice::<TokenMaterial>(bytes))
        .map_err(|_| ApplicationError::Internal)?;
    let mut transaction = application.store.begin().await?;
    let current = sqlx::query(
        "SELECT credential.current_secret_version,credential.state_identity_version,
                credential.credential_kind,credential.administrative_status,
                credential.authentication_status,credential.etag_token,
                auth.token_fingerprint,auth.refresh_fence
         FROM upstream_credentials credential
         JOIN upstream_credential_auth_state auth ON auth.credential_id=credential.id
         WHERE credential.organization_id IS NULL AND credential.id=$1
         FOR UPDATE OF credential,auth",
    )
    .bind(credential_id.as_uuid())
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    require_codex_active(&current)?;
    if current.try_get::<Option<i64>, _>("current_secret_version")? != Some(secret_version)
        || current.try_get::<i64, _>("state_identity_version")? != state_identity_version
        || current
            .try_get::<Option<Vec<u8>>, _>("token_fingerprint")?
            .as_deref()
            != Some(token_fingerprint.as_slice())
        || current.try_get::<i64, _>("refresh_fence")? != refresh_fence - 1
        || !matches!(
            current
                .try_get::<String, _>("authentication_status")?
                .as_str(),
            "ready" | "refresh_error"
        )
    {
        return Err(ApplicationError::Conflict(
            "Codex credential changed while token material was opened".to_owned(),
        ));
    }
    sqlx::query(
        "INSERT INTO upstream_credential_refresh_leases(
            id,credential_id,credential_state_identity_version,secret_version,token_fingerprint,
            refresh_fence,attempt_token,state,lease_owner,lease_expires_at,network_deadline
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,'refreshing',$8,$9,$10)",
    )
    .bind(lease_id)
    .bind(credential_id.as_uuid())
    .bind(state_identity_version)
    .bind(secret_version)
    .bind(&token_fingerprint)
    .bind(refresh_fence)
    .bind(attempt_token)
    .bind(lease_owner)
    .bind(lease_expires_at)
    .bind(network_deadline)
    .execute(&mut *transaction)
    .await
    .map_err(map_database_conflict)?;
    sqlx::query(
        "UPDATE upstream_credential_auth_state SET refresh_fence=$2,updated_at=now()
         WHERE credential_id=$1",
    )
    .bind(credential_id.as_uuid())
    .bind(refresh_fence)
    .execute(&mut *transaction)
    .await?;
    let credential_etag_token = Uuid::now_v7();
    sqlx::query(
        "UPDATE upstream_credentials SET authentication_status='refreshing',
                etag_token=$2,updated_at=now() WHERE id=$1",
    )
    .bind(credential_id.as_uuid())
    .bind(credential_etag_token)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(ClaimedCodexRefresh {
        lease_id,
        network_deadline,
        credential_id,
        secret_version,
        state_identity_version,
        token_fingerprint,
        refresh_fence,
        attempt_token,
        credential_etag_token,
        lease_expires_at,
        account_id,
        protected_secret_id,
        token_material,
    })
}

async fn lock_claimed_refresh(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &ClaimedCodexRefresh,
) -> Result<(), ApplicationError> {
    let matched = sqlx::query_scalar::<_, bool>(
        "SELECT true FROM upstream_credential_refresh_leases lease
         JOIN upstream_credentials credential ON credential.id=lease.credential_id
         JOIN upstream_credential_auth_state auth ON auth.credential_id=credential.id
         WHERE lease.id=$1 AND lease.credential_id=$2 AND lease.state='refreshing'
           AND lease.credential_state_identity_version=$3 AND lease.secret_version=$4
           AND lease.token_fingerprint=$5 AND lease.refresh_fence=$6
           AND lease.attempt_token=$7
           AND credential.state_identity_version=$3 AND credential.current_secret_version=$4
           AND credential.etag_token=$8
           AND auth.credential_state_identity_version=$3
           AND auth.token_fingerprint=$5 AND auth.refresh_fence=$6
           AND lease.lease_expires_at>now() FOR UPDATE OF lease,credential,auth",
    )
    .bind(claim.lease_id)
    .bind(claim.credential_id.as_uuid())
    .bind(claim.state_identity_version)
    .bind(claim.secret_version)
    .bind(&claim.token_fingerprint)
    .bind(claim.refresh_fence)
    .bind(claim.attempt_token)
    .bind(claim.credential_etag_token)
    .fetch_optional(&mut **transaction)
    .await?
    .unwrap_or(false);
    if matched {
        Ok(())
    } else {
        Err(ApplicationError::Conflict(
            "Codex refresh result was fenced by newer state".to_owned(),
        ))
    }
}

async fn commit_codex_refresh_success(
    application: &Application,
    identity: &RequestIdentity,
    claim: ClaimedCodexRefresh,
    prepared: PreparedCodexToken,
    operation_id: &'static str,
) -> Result<CredentialLifecycleResult, ApplicationError> {
    let mut transaction = application.store.begin().await?;
    lock_claimed_refresh(&mut transaction, &claim).await?;
    sqlx::query(
        "UPDATE upstream_credential_refresh_leases SET state='known_success',
                safe_outcome='{\"outcome\":\"accepted\"}'::jsonb,completed_at=now() WHERE id=$1",
    )
    .bind(claim.lease_id)
    .execute(&mut *transaction)
    .await?;
    activate_codex_token(&mut transaction, claim.credential_id, &prepared).await?;
    let (credential, _) = load_credential(
        &mut *transaction,
        &ResourceScope::Deployment,
        claim.credential_id,
    )
    .await?;
    let result = CredentialLifecycleResult {
        credential,
        operation: "refresh".to_owned(),
        outcome: "accepted".to_owned(),
    };
    commit_credential(
        application,
        transaction,
        identity,
        &ResourceScope::Deployment,
        claim.credential_id,
        operation_id,
        &[
            "current_secret_version",
            "authentication_status",
            "refresh_fence",
        ],
        false,
    )
    .await?;
    Ok(result)
}

async fn commit_codex_refresh_failure(
    application: &Application,
    identity: &RequestIdentity,
    claim: ClaimedCodexRefresh,
    terminal: bool,
    reason: &'static str,
    operation_id: &'static str,
) -> Result<CredentialLifecycleResult, ApplicationError> {
    let mut transaction = application.store.begin().await?;
    lock_claimed_refresh(&mut transaction, &claim).await?;
    let status = if terminal { "expired" } else { "refresh_error" };
    sqlx::query(
        "UPDATE upstream_credential_refresh_leases SET state='known_failure',safe_outcome=$2,
                completed_at=now() WHERE id=$1",
    )
    .bind(claim.lease_id)
    .bind(json!({"outcome":"rejected","reason":reason}))
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE upstream_credential_auth_state SET refresh_failure_count=refresh_failure_count+1,
                refresh_backoff_until=CASE WHEN $2 THEN NULL ELSE now()+interval '5 minutes' END,
                refresh_due_at=CASE WHEN $2 THEN NULL ELSE now()+interval '5 minutes' END,
                last_safe_error=$3,updated_at=now() WHERE credential_id=$1",
    )
    .bind(claim.credential_id.as_uuid())
    .bind(terminal)
    .bind(json!({"reason":reason}))
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE upstream_credentials SET authentication_status=$2,
                validation_evidence=$3,validated_at=now(),etag_token=$4,updated_at=now()
         WHERE id=$1",
    )
    .bind(claim.credential_id.as_uuid())
    .bind(status)
    .bind(json!({"outcome":"rejected","reason":reason}))
    .bind(Uuid::now_v7())
    .execute(&mut *transaction)
    .await?;
    if terminal {
        sqlx::query(
            "UPDATE upstream_credential_secret_versions SET state='retired',retired_at=now(),
                    protected_secret_version_id=NULL WHERE credential_id=$1 AND version=$2",
        )
        .bind(claim.credential_id.as_uuid())
        .bind(claim.secret_version)
        .execute(&mut *transaction)
        .await?;
        sqlx::query("UPDATE upstream_credentials SET current_secret_version=NULL WHERE id=$1")
            .bind(claim.credential_id.as_uuid())
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM protected_secret_versions WHERE id=$1")
            .bind(claim.protected_secret_id)
            .execute(&mut *transaction)
            .await?;
    }
    let (credential, _) = load_credential(
        &mut *transaction,
        &ResourceScope::Deployment,
        claim.credential_id,
    )
    .await?;
    let result = CredentialLifecycleResult {
        credential,
        operation: "refresh".to_owned(),
        outcome: status.to_owned(),
    };
    commit_credential(
        application,
        transaction,
        identity,
        &ResourceScope::Deployment,
        claim.credential_id,
        operation_id,
        &["authentication_status", "refresh_fence"],
        terminal,
    )
    .await?;
    Ok(result)
}

async fn commit_codex_refresh_unknown(
    application: &Application,
    identity: &RequestIdentity,
    claim: ClaimedCodexRefresh,
    reason: &'static str,
    operation_id: &'static str,
) -> Result<CredentialLifecycleResult, ApplicationError> {
    let mut transaction = application.store.begin().await?;
    lock_claimed_refresh(&mut transaction, &claim).await?;
    sqlx::query(
        "UPDATE upstream_credential_refresh_leases SET state='outcome_unknown',
                safe_outcome=$2,completed_at=now() WHERE id=$1",
    )
    .bind(claim.lease_id)
    .bind(json!({"outcome":"unknown","reason":reason}))
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE upstream_credentials SET authentication_status='refresh_outcome_unknown',
                validation_evidence=$2,validated_at=now(),etag_token=$3,updated_at=now()
         WHERE id=$1",
    )
    .bind(claim.credential_id.as_uuid())
    .bind(json!({"outcome":"unknown","reason":reason}))
    .bind(Uuid::now_v7())
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE upstream_credential_auth_state SET refresh_due_at=NULL,
                refresh_backoff_until=NULL,last_safe_error='{\"reason\":\"outcome_unknown\"}'::jsonb,
                updated_at=now() WHERE credential_id=$1",
    )
    .bind(claim.credential_id.as_uuid())
    .execute(&mut *transaction)
    .await?;
    let (credential, _) = load_credential(
        &mut *transaction,
        &ResourceScope::Deployment,
        claim.credential_id,
    )
    .await?;
    let result = CredentialLifecycleResult {
        credential,
        operation: "refresh".to_owned(),
        outcome: "outcome_unknown".to_owned(),
    };
    commit_credential(
        application,
        transaction,
        identity,
        &ResourceScope::Deployment,
        claim.credential_id,
        operation_id,
        &["authentication_status", "refresh_fence"],
        true,
    )
    .await?;
    Ok(result)
}

async fn commit_codex_refresh_success_internal(
    application: &Application,
    claim: ClaimedCodexRefresh,
    prepared: PreparedCodexToken,
    request_id: &str,
) -> Result<(), ApplicationError> {
    let credential_id = claim.credential_id;
    let mut transaction = application.store.begin().await?;
    lock_claimed_refresh(&mut transaction, &claim).await?;
    sqlx::query(
        "UPDATE upstream_credential_refresh_leases SET state='known_success',
                safe_outcome='{\"outcome\":\"accepted\"}'::jsonb,completed_at=now() WHERE id=$1",
    )
    .bind(claim.lease_id)
    .execute(&mut *transaction)
    .await?;
    activate_codex_token(&mut transaction, credential_id, &prepared).await?;
    commit_credential_internal(
        application,
        transaction,
        credential_id,
        request_id,
        &[
            "current_secret_version",
            "authentication_status",
            "refresh_fence",
        ],
        false,
    )
    .await
}

async fn commit_codex_refresh_failure_internal(
    application: &Application,
    claim: ClaimedCodexRefresh,
    terminal: bool,
    reason: &'static str,
    request_id: &str,
) -> Result<(), ApplicationError> {
    let credential_id = claim.credential_id;
    let mut transaction = application.store.begin().await?;
    lock_claimed_refresh(&mut transaction, &claim).await?;
    let status = if terminal { "expired" } else { "refresh_error" };
    sqlx::query(
        "UPDATE upstream_credential_refresh_leases SET state='known_failure',safe_outcome=$2,
                completed_at=now() WHERE id=$1",
    )
    .bind(claim.lease_id)
    .bind(json!({"outcome":"rejected","reason":reason}))
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE upstream_credential_auth_state SET refresh_failure_count=refresh_failure_count+1,
                refresh_backoff_until=CASE WHEN $2 THEN NULL ELSE now()+interval '5 minutes' END,
                refresh_due_at=CASE WHEN $2 THEN NULL ELSE now()+interval '5 minutes' END,
                last_safe_error=$3,updated_at=now() WHERE credential_id=$1",
    )
    .bind(credential_id.as_uuid())
    .bind(terminal)
    .bind(json!({"reason":reason}))
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE upstream_credentials SET authentication_status=$2,
                validation_evidence=$3,validated_at=now(),etag_token=$4,updated_at=now()
         WHERE id=$1",
    )
    .bind(credential_id.as_uuid())
    .bind(status)
    .bind(json!({"outcome":"rejected","reason":reason}))
    .bind(Uuid::now_v7())
    .execute(&mut *transaction)
    .await?;
    if terminal {
        sqlx::query(
            "UPDATE upstream_credential_secret_versions SET state='retired',retired_at=now(),
                    protected_secret_version_id=NULL WHERE credential_id=$1 AND version=$2",
        )
        .bind(credential_id.as_uuid())
        .bind(claim.secret_version)
        .execute(&mut *transaction)
        .await?;
        sqlx::query("UPDATE upstream_credentials SET current_secret_version=NULL WHERE id=$1")
            .bind(credential_id.as_uuid())
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM protected_secret_versions WHERE id=$1")
            .bind(claim.protected_secret_id)
            .execute(&mut *transaction)
            .await?;
    }
    commit_credential_internal(
        application,
        transaction,
        credential_id,
        request_id,
        &["authentication_status", "refresh_fence"],
        terminal,
    )
    .await
}

async fn commit_codex_refresh_unknown_internal(
    application: &Application,
    claim: ClaimedCodexRefresh,
    reason: &'static str,
    request_id: &str,
) -> Result<(), ApplicationError> {
    let credential_id = claim.credential_id;
    let mut transaction = application.store.begin().await?;
    lock_claimed_refresh(&mut transaction, &claim).await?;
    sqlx::query(
        "UPDATE upstream_credential_refresh_leases SET state='outcome_unknown',
                safe_outcome=$2,completed_at=now() WHERE id=$1",
    )
    .bind(claim.lease_id)
    .bind(json!({"outcome":"unknown","reason":reason}))
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE upstream_credentials SET authentication_status='refresh_outcome_unknown',
                validation_evidence=$2,validated_at=now(),etag_token=$3,updated_at=now()
         WHERE id=$1",
    )
    .bind(credential_id.as_uuid())
    .bind(json!({"outcome":"unknown","reason":reason}))
    .bind(Uuid::now_v7())
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE upstream_credential_auth_state SET refresh_due_at=NULL,
                refresh_backoff_until=NULL,last_safe_error=$2,updated_at=now()
         WHERE credential_id=$1",
    )
    .bind(credential_id.as_uuid())
    .bind(json!({"reason":reason}))
    .execute(&mut *transaction)
    .await?;
    commit_credential_internal(
        application,
        transaction,
        credential_id,
        request_id,
        &["authentication_status", "refresh_fence"],
        true,
    )
    .await
}

async fn commit_credential_internal(
    application: &Application,
    transaction: Transaction<'_, Postgres>,
    credential_id: CredentialId,
    request_id: &str,
    changed_fields: &[&str],
    tightening: bool,
) -> Result<(), ApplicationError> {
    application
        .store
        .commit_command(
            transaction,
            &AuditRecord {
                actor: None,
                authentication_evidence: json!({"method":"internal_worker"}),
                organization_id: None,
                target_resource_kind: "upstream_credential".to_owned(),
                target_resource_id: Some(credential_id.to_string()),
                operation_id: "system.workers.codex_credentials.refresh".to_owned(),
                outcome: "accepted",
                request_id: request_id.to_owned(),
                changed_fields: changed_fields
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                safe_details: json!({"resource_scope":"deployment"}),
            },
            Some(&RuntimeEvent {
                event_kind: "upstream_credential.changed".to_owned(),
                affected_scope: json!({
                    "resource_scope":"deployment",
                    "credential_id":credential_id,
                }),
                security_tightening: tightening,
            }),
        )
        .await?;
    Ok(())
}

fn remaining_before(deadline: DateTime<Utc>) -> std::time::Duration {
    (deadline - Utc::now())
        .to_std()
        .unwrap_or(std::time::Duration::from_millis(1))
        .max(std::time::Duration::from_millis(1))
}

fn map_codex_error(error: CodexAdapterError) -> ApplicationError {
    match error {
        CodexAdapterError::DependencyUnavailable => ApplicationError::DependencyUnavailable,
        CodexAdapterError::Rejected => {
            ApplicationError::Conflict("OpenAI rejected the Codex authentication action".to_owned())
        }
        CodexAdapterError::UnsupportedContract => ApplicationError::Conflict(
            "OpenAI returned an unsupported Codex authentication contract".to_owned(),
        ),
    }
}

struct SealedCodexLoginSecret {
    material_id: CredentialSecretVersionId,
    owner_generation: i64,
    provider_id: String,
    provider_format_version: i32,
    envelope: Vec<u8>,
}

async fn seal_codex_login_secret(
    application: &Application,
    session_id: CredentialLoginSessionId,
    material_id: CredentialSecretVersionId,
    owner_generation: u64,
    plaintext: &SecretPlaintext,
) -> Result<SealedCodexLoginSecret, ApplicationError> {
    let context = codex_login_context(
        application.store.installation_id(),
        session_id,
        material_id,
        owner_generation,
        application.secrets.write_pair(),
    )?;
    let envelope = application
        .secrets
        .seal(&context, plaintext)
        .await
        .map_err(|_| ApplicationError::DependencyUnavailable)?;
    Ok(SealedCodexLoginSecret {
        material_id,
        owner_generation: i64::try_from(owner_generation)
            .map_err(|_| ApplicationError::Internal)?,
        provider_id: context.parts().provider_id.as_str().to_owned(),
        provider_format_version: i32::try_from(context.parts().provider_format_version.get())
            .map_err(|_| ApplicationError::Internal)?,
        envelope: envelope.expose(<[u8]>::to_vec),
    })
}

async fn persist_codex_login_secret(
    transaction: &mut Transaction<'_, Postgres>,
    session_id: CredentialLoginSessionId,
    sealed: &SealedCodexLoginSecret,
) -> Result<(), ApplicationError> {
    sqlx::query(
        "INSERT INTO protected_secret_versions(
            id,scope_kind,organization_id,owner_kind,owner_id,owner_generation,secret_version,
            field_purpose,custody_provider_id,provider_format_version,context_version,opaque_envelope
         ) VALUES ($1,'system',NULL,'upstream_credential_login_session',$2,$3,1,
                   'codex_device_login_material',$4,$5,1,$6)",
    )
    .bind(sealed.material_id.as_uuid())
    .bind(session_id.as_uuid())
    .bind(sealed.owner_generation)
    .bind(&sealed.provider_id)
    .bind(sealed.provider_format_version)
    .bind(&sealed.envelope)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn codex_login_context(
    installation_id: Uuid,
    session_id: CredentialLoginSessionId,
    material_id: CredentialSecretVersionId,
    owner_generation: u64,
    pair: &crate::secrets::CustodyPair,
) -> Result<ProtectionContext, ApplicationError> {
    ProtectionContext::new(ProtectionContextParts {
        version: ContextVersion::V1,
        installation_id: InstallationId::new(installation_id.to_string())
            .map_err(|_| ApplicationError::Internal)?,
        scope: SecretScope::System,
        material_id: MaterialId::new(material_id.to_string())
            .map_err(|_| ApplicationError::Internal)?,
        owner_kind: OwnerKind::new("upstream_credential_login_session")
            .map_err(|_| ApplicationError::Internal)?,
        owner_id: OwnerId::new(session_id.to_string()).map_err(|_| ApplicationError::Internal)?,
        owner_generation,
        secret_version: 1,
        field_purpose: FieldPurpose::new("codex_device_login_material")
            .map_err(|_| ApplicationError::Internal)?,
        provider_id: pair.provider_id().clone(),
        provider_format_version: pair.format_version(),
    })
    .map_err(|_| ApplicationError::Internal)
}

async fn load_codex_login_session<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    credential_id: CredentialId,
    session_id: CredentialLoginSessionId,
) -> Result<CodexLoginSession, ApplicationError> {
    let row = sqlx::query(
        "SELECT id,credential_id,state,poll_interval_seconds,expires_at,
                next_poll_at,created_at,updated_at
         FROM upstream_credential_login_sessions WHERE credential_id=$1 AND id=$2",
    )
    .bind(credential_id.as_uuid())
    .bind(session_id.as_uuid())
    .fetch_optional(executor)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    Ok(CodexLoginSession {
        id: CredentialLoginSessionId::from_uuid(row.try_get("id")?),
        credential_id: CredentialId::from_uuid(row.try_get("credential_id")?),
        state: row.try_get("state")?,
        verification_url: None,
        user_code: None,
        poll_interval_seconds: u32::try_from(row.try_get::<i32, _>("poll_interval_seconds")?)
            .map_err(|_| ApplicationError::Internal)?,
        expires_at: row.try_get("expires_at")?,
        next_poll_at: row.try_get("next_poll_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

async fn expire_codex_login_if_due(
    transaction: &mut Transaction<'_, Postgres>,
    credential_id: CredentialId,
    session_id: CredentialLoginSessionId,
) -> Result<(), ApplicationError> {
    let row = sqlx::query(
        "SELECT state,login_secret_id,expires_at FROM upstream_credential_login_sessions
         WHERE credential_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(credential_id.as_uuid())
    .bind(session_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    if matches!(
        row.try_get::<String, _>("state")?.as_str(),
        "pending" | "polling"
    ) && row.try_get::<DateTime<Utc>, _>("expires_at")? <= Utc::now()
    {
        terminalize_codex_login(
            transaction,
            session_id,
            "expired",
            row.try_get("login_secret_id")?,
        )
        .await?;
        sqlx::query(
            "UPDATE upstream_credentials SET authentication_status=CASE
                WHEN current_secret_version IS NULL THEN 'login_required' ELSE 'ready' END,
                etag_token=$2,updated_at=now() WHERE id=$1",
        )
        .bind(credential_id.as_uuid())
        .bind(Uuid::now_v7())
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn terminalize_codex_login(
    transaction: &mut Transaction<'_, Postgres>,
    session_id: CredentialLoginSessionId,
    state: &str,
    login_secret_id: Option<Uuid>,
) -> Result<(), ApplicationError> {
    sqlx::query(
        "UPDATE upstream_credential_login_sessions SET state=$2,attempt_token=NULL,
                claim_expires_at=NULL,login_secret_id=NULL,
                safe_display='{\"display_available\":false}'::jsonb,next_poll_at=NULL,
                terminal_cleanup_at=now(),updated_at=now() WHERE id=$1",
    )
    .bind(session_id.as_uuid())
    .bind(state)
    .execute(&mut **transaction)
    .await?;
    if let Some(login_secret_id) = login_secret_id {
        sqlx::query("DELETE FROM protected_secret_versions WHERE id=$1")
            .bind(login_secret_id)
            .execute(&mut **transaction)
            .await?;
    }
    Ok(())
}

fn credential_context(
    installation_id: Uuid,
    scope: &ResourceScope,
    credential_id: CredentialId,
    material_id: CredentialSecretVersionId,
    owner_generation: u64,
    secret_version: u64,
    pair: &crate::secrets::CustodyPair,
) -> Result<ProtectionContext, ApplicationError> {
    let scope = match scope {
        ResourceScope::Deployment => SecretScope::System,
        ResourceScope::Organization { organization_id } => SecretScope::Organization(
            SecretOrganizationId::new(organization_id.to_string())
                .map_err(|_| ApplicationError::Internal)?,
        ),
    };
    ProtectionContext::new(ProtectionContextParts {
        version: ContextVersion::V1,
        installation_id: InstallationId::new(installation_id.to_string())
            .map_err(|_| ApplicationError::Internal)?,
        scope,
        material_id: MaterialId::new(material_id.to_string())
            .map_err(|_| ApplicationError::Internal)?,
        owner_kind: OwnerKind::new("upstream_credential")
            .map_err(|_| ApplicationError::Internal)?,
        owner_id: OwnerId::new(credential_id.to_string())
            .map_err(|_| ApplicationError::Internal)?,
        owner_generation,
        secret_version,
        field_purpose: FieldPurpose::new("upstream_credential_material")
            .map_err(|_| ApplicationError::Internal)?,
        provider_id: pair.provider_id().clone(),
        provider_format_version: pair.format_version(),
    })
    .map_err(|_| ApplicationError::Internal)
}

fn custody_pair_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<crate::secrets::CustodyPair, ApplicationError> {
    let provider_id = ProviderId::new(row.try_get::<String, _>("custody_provider_id")?)
        .map_err(|_| ApplicationError::Internal)?;
    let format_version = ProviderFormatVersion::new(
        u32::try_from(row.try_get::<i32, _>("provider_format_version")?)
            .map_err(|_| ApplicationError::Internal)?,
    )
    .map_err(|_| ApplicationError::Internal)?;
    Ok(crate::secrets::CustodyPair::new(
        provider_id,
        format_version,
    ))
}

fn require_codex_active(row: &sqlx::postgres::PgRow) -> Result<(), ApplicationError> {
    if row.try_get::<String, _>("credential_kind")? != "oauth_openai_codex"
        || row.try_get::<String, _>("administrative_status")? != "active"
    {
        return Err(ApplicationError::Conflict(
            "operation requires an active Codex credential".to_owned(),
        ));
    }
    Ok(())
}

fn validate_create(
    scope: &ResourceScope,
    input: &CreateUpstreamCredential,
) -> Result<(), ApplicationError> {
    validate_name(&input.name)?;
    validate_object(&input.source_configuration, "source_configuration")?;
    validate_safe_metadata(&input.safe_metadata)?;
    validate_sharing(&input.sharing_policy)?;
    let allowed_injections: &[&str] = match input.credential_kind {
        CredentialKind::StaticApiKey => &["bearer", "x_api_key", "api_key_header"],
        CredentialKind::OauthOpenaiCodex => &["bearer"],
        CredentialKind::AwsDefaultChain | CredentialKind::AwsAssumeRole => &["aws_sigv4"],
        CredentialKind::GoogleApplicationDefault | CredentialKind::GoogleServiceAccount => {
            &["google_oauth"]
        }
        CredentialKind::AzureApiKey => &["api_key_header"],
        CredentialKind::AzureWorkloadIdentity => &["azure_bearer"],
    };
    if !allowed_injections.contains(&input.injection_kind.as_str()) {
        return Err(ApplicationError::Validation(
            "injection_kind does not match the credential kind".to_owned(),
        ));
    }
    if matches!(scope, ResourceScope::Organization { .. })
        && (!input.credential_kind.organization_self_service_allowed()
            || !input.secret_source_kind.organization_self_service_allowed())
    {
        return Err(ApplicationError::Validation(
            "organization BYOK accepts only encrypted static or Azure API keys".to_owned(),
        ));
    }
    validate_source_configuration(input.secret_source_kind, &input.source_configuration)?;
    validate_credential_source_contract(input)?;
    if input.secret_source_kind == CredentialSourceKind::EncryptedDatabase
        && input.credential_kind != CredentialKind::OauthOpenaiCodex
        && input.secret.is_none()
    {
        return Err(ApplicationError::Validation(
            "encrypted credential creation requires secret material".to_owned(),
        ));
    }
    if input.secret_source_kind != CredentialSourceKind::EncryptedDatabase && input.secret.is_some()
    {
        return Err(ApplicationError::Validation(
            "external secret sources cannot include inline secret material".to_owned(),
        ));
    }
    if matches!(scope, ResourceScope::Organization { .. })
        && input.sharing_policy != "same_scope_reusable"
    {
        return Err(ApplicationError::Validation(
            "organization credentials require same_scope_reusable sharing".to_owned(),
        ));
    }
    Ok(())
}

fn validate_source_configuration(
    kind: CredentialSourceKind,
    value: &Value,
) -> Result<(), ApplicationError> {
    let object = value.as_object().ok_or_else(|| {
        ApplicationError::Validation("source_configuration must be an object".to_owned())
    })?;
    let exact_string = |field: &str| {
        (object.len() == 1)
            .then(|| object.get(field))
            .flatten()
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
    };
    match kind {
        CredentialSourceKind::EncryptedDatabase if object.is_empty() => Ok(()),
        CredentialSourceKind::EnvironmentReference
            if exact_string("environment_variable").is_some_and(|name| {
                name.len() <= 128
                    && name.bytes().enumerate().all(|(index, byte)| {
                        byte == b'_'
                            || byte.is_ascii_uppercase()
                            || (index > 0 && byte.is_ascii_digit())
                    })
            }) =>
        {
            Ok(())
        }
        CredentialSourceKind::MountedFileReference
            if exact_string("path").is_some_and(|path| {
                path.len() <= 4096 && std::path::Path::new(path).is_absolute()
            }) =>
        {
            Ok(())
        }
        CredentialSourceKind::WorkloadIdentity
            if object.len() <= 16
                && object.iter().all(|(key, value)| {
                    !key.is_empty()
                        && key.len() <= 128
                        && value.as_str().is_some_and(|value| value.len() <= 4096)
                }) =>
        {
            Ok(())
        }
        _ => Err(ApplicationError::Validation(
            "source_configuration does not match the selected source kind".to_owned(),
        )),
    }
}

fn validate_credential_source_contract(
    input: &CreateUpstreamCredential,
) -> Result<(), ApplicationError> {
    let valid = match input.credential_kind {
        CredentialKind::StaticApiKey
        | CredentialKind::OauthOpenaiCodex
        | CredentialKind::AzureApiKey => {
            input.secret_source_kind != CredentialSourceKind::WorkloadIdentity
        }
        CredentialKind::AwsDefaultChain => {
            input.secret_source_kind == CredentialSourceKind::WorkloadIdentity
                && input
                    .source_configuration
                    .as_object()
                    .is_some_and(serde_json::Map::is_empty)
        }
        CredentialKind::AwsAssumeRole => {
            input.secret_source_kind == CredentialSourceKind::WorkloadIdentity
                && serde_json::from_value::<AwsAssumeRoleSource>(input.source_configuration.clone())
                    .is_ok_and(|source| source.valid())
        }
        CredentialKind::GoogleApplicationDefault => {
            input.secret_source_kind == CredentialSourceKind::WorkloadIdentity
                && input
                    .source_configuration
                    .as_object()
                    .is_some_and(serde_json::Map::is_empty)
        }
        CredentialKind::GoogleServiceAccount => {
            input.secret_source_kind != CredentialSourceKind::WorkloadIdentity
        }
        CredentialKind::AzureWorkloadIdentity => {
            input.secret_source_kind == CredentialSourceKind::WorkloadIdentity
                && serde_json::from_value::<AzureWorkloadSource>(input.source_configuration.clone())
                    .is_ok_and(|source| source.valid())
        }
    };
    if valid {
        Ok(())
    } else {
        Err(ApplicationError::Validation(
            "credential kind and source configuration are incompatible".to_owned(),
        ))
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AwsAssumeRoleSource {
    role_arn: String,
    #[serde(default = "default_aws_role_session_name")]
    role_session_name: String,
    #[serde(default)]
    external_id: Option<String>,
}

impl AwsAssumeRoleSource {
    fn valid(&self) -> bool {
        self.role_arn.starts_with("arn:")
            && self.role_arn.len() <= 2048
            && !self.role_session_name.is_empty()
            && self.role_session_name.len() <= 64
            && self
                .external_id
                .as_ref()
                .is_none_or(|value| !value.is_empty() && value.len() <= 1024)
    }
}

fn default_aws_role_session_name() -> String {
    "owlrora".to_owned()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AzureWorkloadSource {
    tenant_id: String,
    client_id: String,
    token_file: String,
}

impl AzureWorkloadSource {
    fn valid(&self) -> bool {
        Uuid::parse_str(&self.tenant_id).is_ok()
            && Uuid::parse_str(&self.client_id).is_ok()
            && !self.token_file.is_empty()
            && self.token_file.len() <= 4096
            && std::path::Path::new(&self.token_file).is_absolute()
    }
}

fn validate_safe_metadata(value: &Value) -> Result<(), ApplicationError> {
    let object = value.as_object().ok_or_else(|| {
        ApplicationError::Validation("safe_metadata must be an object".to_owned())
    })?;
    if object.len() > 32
        || object.iter().any(|(key, value)| {
            key.is_empty()
                || key.len() > 128
                || matches!(
                    key.to_ascii_lowercase().as_str(),
                    "secret" | "token" | "password" | "api_key" | "authorization" | "credential"
                )
                || !matches!(value, Value::String(_) | Value::Bool(_) | Value::Number(_))
                || value.as_str().is_some_and(|value| value.len() > 512)
        })
    {
        return Err(ApplicationError::Validation(
            "safe_metadata must contain only bounded non-secret scalar fields".to_owned(),
        ));
    }
    Ok(())
}

fn authorize_credentials(
    application: &Application,
    identity: &RequestIdentity,
    scope: &ResourceScope,
    write: bool,
    organization_capability: Capability,
) -> Result<(), ApplicationError> {
    let required = &[if write {
        ManagementScope::Write
    } else {
        ManagementScope::Read
    }];
    match scope {
        ResourceScope::Deployment => application.authorize(
            identity,
            required,
            AuthorizationTarget::System {
                capability: Capability::ManageGatewayCatalog,
            },
        ),
        ResourceScope::Organization { organization_id } => application.authorize(
            identity,
            required,
            AuthorizationTarget::Organization {
                organization_id: *organization_id,
                capability: organization_capability,
            },
        ),
    }
}

async fn commit_credential(
    application: &Application,
    transaction: Transaction<'_, Postgres>,
    identity: &RequestIdentity,
    scope: &ResourceScope,
    credential_id: CredentialId,
    operation_id: &'static str,
    changed_fields: &[&str],
    tightening: bool,
) -> Result<(), ApplicationError> {
    let organization_id = match scope {
        ResourceScope::Deployment => None,
        ResourceScope::Organization { organization_id } => Some(*organization_id),
    };
    application
        .store
        .commit_command(
            transaction,
            &AuditRecord {
                actor: Some(Actor::from(&identity.principal)),
                authentication_evidence: json!({
                    "method": identity.principal.authentication_method,
                    "session_id": identity.principal.session_id,
                    "external_issuer_id": identity.principal.external_issuer_id,
                }),
                organization_id,
                target_resource_kind: "upstream_credential".to_owned(),
                target_resource_id: Some(credential_id.to_string()),
                operation_id: operation_id.to_owned(),
                outcome: "accepted",
                request_id: identity.request_id.clone(),
                changed_fields: changed_fields
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                safe_details: json!({"resource_scope": scope}),
            },
            Some(&RuntimeEvent {
                event_kind: "upstream_credential.changed".to_owned(),
                affected_scope: json!({"resource_scope": scope, "credential_id": credential_id}),
                security_tightening: tightening,
            }),
        )
        .await?;
    Ok(())
}

fn credential_operation_id(scope: &ResourceScope, action: &str) -> &'static str {
    match (scope, action) {
        (ResourceScope::Deployment, "create") => "system.upstream_credentials.create",
        (ResourceScope::Deployment, "update") => "system.upstream_credentials.update",
        (ResourceScope::Deployment, "replace_secret") => {
            "system.upstream_credentials.replace_secret"
        }
        (ResourceScope::Deployment, "reload_source") => "system.upstream_credentials.reload_source",
        (ResourceScope::Deployment, "validate") => "system.upstream_credentials.validate",
        (ResourceScope::Deployment, "codex_login_start") => {
            "system.upstream_credentials.codex_login.start"
        }
        (ResourceScope::Deployment, "codex_login_complete") => {
            "system.upstream_credentials.codex_login.complete"
        }
        (ResourceScope::Deployment, "codex_login_cancel") => {
            "system.upstream_credentials.codex_login.cancel"
        }
        (ResourceScope::Deployment, "refresh") => "system.upstream_credentials.refresh",
        (ResourceScope::Deployment, "revoke") => "system.upstream_credentials.revoke",
        (ResourceScope::Organization { .. }, "create") => {
            "organization.upstream_credentials.create"
        }
        (ResourceScope::Organization { .. }, "update") => {
            "organization.upstream_credentials.update"
        }
        (ResourceScope::Organization { .. }, "replace_secret") => {
            "organization.upstream_credentials.replace_secret"
        }
        (ResourceScope::Organization { .. }, "validate") => {
            "organization.upstream_credentials.validate"
        }
        _ => unreachable!("closed upstream credential action"),
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

fn parse_credential_kind(value: &str) -> Result<CredentialKind, ApplicationError> {
    match value {
        "static_api_key" => Ok(CredentialKind::StaticApiKey),
        "oauth_openai_codex" => Ok(CredentialKind::OauthOpenaiCodex),
        "aws_default_chain" => Ok(CredentialKind::AwsDefaultChain),
        "aws_assume_role" => Ok(CredentialKind::AwsAssumeRole),
        "google_application_default" => Ok(CredentialKind::GoogleApplicationDefault),
        "google_service_account" => Ok(CredentialKind::GoogleServiceAccount),
        "azure_api_key" => Ok(CredentialKind::AzureApiKey),
        "azure_workload_identity" => Ok(CredentialKind::AzureWorkloadIdentity),
        _ => Err(ApplicationError::Internal),
    }
}

fn parse_source_kind(value: &str) -> Result<CredentialSourceKind, ApplicationError> {
    match value {
        "encrypted_database" => Ok(CredentialSourceKind::EncryptedDatabase),
        "environment_reference" => Ok(CredentialSourceKind::EnvironmentReference),
        "mounted_file_reference" => Ok(CredentialSourceKind::MountedFileReference),
        "workload_identity" => Ok(CredentialSourceKind::WorkloadIdentity),
        _ => Err(ApplicationError::Internal),
    }
}

fn parse_status(value: &str) -> Result<KeyStatus, ApplicationError> {
    match value {
        "active" => Ok(KeyStatus::Active),
        "disabled" => Ok(KeyStatus::Disabled),
        "revoked" => Ok(KeyStatus::Revoked),
        _ => Err(ApplicationError::Internal),
    }
}

fn validate_name(value: &str) -> Result<(), ApplicationError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 160 || value.chars().any(char::is_control) {
        return Err(ApplicationError::Validation(
            "name must contain 1 to 160 printable characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_sharing(value: &str) -> Result<(), ApplicationError> {
    if matches!(value, "exclusive" | "same_scope_reusable") {
        Ok(())
    } else {
        Err(ApplicationError::Validation(
            "sharing_policy is not supported".to_owned(),
        ))
    }
}

fn validate_object(value: &Value, field: &str) -> Result<(), ApplicationError> {
    if value.is_object() {
        Ok(())
    } else {
        Err(ApplicationError::Validation(format!(
            "{field} must be an object"
        )))
    }
}

fn actor_value(identity: &RequestIdentity) -> Result<Value, ApplicationError> {
    serde_json::to_value(Actor::from(&identity.principal)).map_err(|_| ApplicationError::Internal)
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

fn null_error(field: &str) -> ApplicationError {
    ApplicationError::Validation(format!("{field} cannot be null"))
}

fn map_database_conflict(error: sqlx::Error) -> ApplicationError {
    if error.as_database_error().is_some() {
        ApplicationError::Conflict(
            "the upstream credential conflicts with current state".to_owned(),
        )
    } else {
        error.into()
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::*;
    use crate::{
        adapters::postgres::{
            PgStore,
            test_support::{connect_from_environment, shared_database_test_lock},
        },
        config::ServerConfig,
        domain::generate_management_key,
        runtime::RuntimePublisher,
        secrets::{CustodyPair, CustodyRegistry, SecretService},
    };

    #[test]
    fn organization_byok_is_closed_to_encrypted_api_keys() {
        let scope = ResourceScope::Organization {
            organization_id: OrganizationId::new(),
        };
        let mut input = CreateUpstreamCredential {
            name: "key".to_owned(),
            credential_kind: CredentialKind::StaticApiKey,
            secret_source_kind: CredentialSourceKind::EncryptedDatabase,
            source_configuration: json!({}),
            injection_kind: "bearer".to_owned(),
            sharing_policy: "same_scope_reusable".to_owned(),
            secret: Some("secret".to_owned()),
            safe_metadata: json!({}),
        };
        assert!(validate_create(&scope, &input).is_ok());
        input.secret_source_kind = CredentialSourceKind::EnvironmentReference;
        input.secret = None;
        assert!(validate_create(&scope, &input).is_err());
    }

    #[test]
    fn default_cloud_chains_require_exact_workload_identity_sources() {
        for (credential_kind, injection_kind) in [
            (CredentialKind::AwsDefaultChain, "aws_sigv4"),
            (CredentialKind::GoogleApplicationDefault, "google_oauth"),
        ] {
            let mut input = CreateUpstreamCredential {
                name: "default-chain".to_owned(),
                credential_kind,
                secret_source_kind: CredentialSourceKind::WorkloadIdentity,
                source_configuration: json!({}),
                injection_kind: injection_kind.to_owned(),
                sharing_policy: "exclusive".to_owned(),
                secret: None,
                safe_metadata: json!({}),
            };
            assert!(validate_create(&ResourceScope::Deployment, &input).is_ok());

            input.source_configuration = json!({"path":"/tmp/not-a-default-chain"});
            assert!(validate_create(&ResourceScope::Deployment, &input).is_err());

            input.source_configuration = json!({});
            input.secret_source_kind = CredentialSourceKind::MountedFileReference;
            assert!(validate_create(&ResourceScope::Deployment, &input).is_err());
        }
    }

    #[test]
    fn replace_secret_idempotency_input_is_resource_qualified() {
        let input = ReplaceUpstreamCredentialSecret {
            secret: "same-secret".to_owned(),
        };
        let first_id = CredentialId::new();
        let second_id = CredentialId::new();
        let first = serde_json::to_vec(&ReplaceSecretIdempotencyInput {
            credential_id: &first_id,
            input: &input,
        })
        .unwrap();
        let second = serde_json::to_vec(&ReplaceSecretIdempotencyInput {
            credential_id: &second_id,
            input: &input,
        })
        .unwrap();
        assert_ne!(first, second);
        assert!(
            String::from_utf8(first)
                .unwrap()
                .contains(&first_id.to_string())
        );
    }

    async fn test_application(
        test_name: &str,
    ) -> Option<(PgStore, Arc<RuntimePublisher>, Application, String)> {
        let store = connect_from_environment().await?;
        let redis_url = std::env::var("OWLRORA_TEST_REDIS_URL").ok()?;
        let seed_key = generate_management_key().expose_once();
        let config = Arc::new(
            ServerConfig::from_values(&BTreeMap::from([
                (
                    "OWLRORA_DATABASE_URL".to_owned(),
                    std::env::var("OWLRORA_TEST_DATABASE_URL").unwrap(),
                ),
                (
                    "OWLRORA_PUBLIC_ORIGIN".to_owned(),
                    "http://127.0.0.1:8080".to_owned(),
                ),
                ("OWLRORA_REDIS_URL".to_owned(), redis_url),
                (
                    "OWLRORA_NODE_INSTANCE_ID".to_owned(),
                    format!("{test_name}-{}", Uuid::now_v7()),
                ),
                ("OWLRORA_SEED_ADMIN_API_KEY".to_owned(), seed_key.clone()),
                (
                    "OWLRORA_SECRET_ROOT".to_owned(),
                    URL_SAFE_NO_PAD.encode([37_u8; 32]),
                ),
            ]))
            .unwrap(),
        );
        let secrets = Arc::new(
            SecretService::new(
                config.secret_root.clone(),
                CustodyRegistry::default(),
                CustodyPair::software(),
            )
            .unwrap(),
        );
        let runtime = RuntimePublisher::start(
            store.clone(),
            Arc::clone(&secrets),
            format!("{test_name}-{}", Uuid::now_v7()),
        )
        .await
        .unwrap();
        let application = Application::new(
            store.clone(),
            Arc::clone(&runtime),
            config,
            Arc::clone(&secrets),
        )
        .unwrap();
        Some((store, runtime, application, seed_key))
    }

    #[tokio::test]
    async fn credential_create_replays_with_a_keyed_request_fingerprint() {
        let _database_guard = shared_database_test_lock().await;
        let Some((store, _runtime, application, seed_key)) =
            test_application("credential-create-idempotency-test").await
        else {
            return;
        };
        let identity = application
            .authenticate_management_key(&seed_key, "credential-create-idempotency-test".to_owned())
            .unwrap();
        let name = format!("create-idempotency-test-{}", Uuid::now_v7());
        let input = CreateUpstreamCredential {
            name: name.clone(),
            credential_kind: CredentialKind::StaticApiKey,
            secret_source_kind: CredentialSourceKind::EncryptedDatabase,
            source_configuration: json!({}),
            injection_kind: "bearer".to_owned(),
            sharing_policy: "exclusive".to_owned(),
            secret: Some("initial-secret".to_owned()),
            safe_metadata: json!({}),
        };
        let key = format!("create-{}", Uuid::now_v7());
        let first = application
            .create_upstream_credential(
                &identity,
                ResourceScope::Deployment,
                input.clone(),
                Some(&key),
            )
            .await
            .unwrap();
        let IdempotentCommand::Executed((created, etag)) = first else {
            panic!("first credential create must execute");
        };
        let replay = application
            .create_upstream_credential(
                &identity,
                ResourceScope::Deployment,
                input.clone(),
                Some(&key),
            )
            .await
            .unwrap();
        let IdempotentCommand::Replay(replay) = replay else {
            panic!("second credential create must replay");
        };
        assert_eq!(replay.status, 200);
        assert_eq!(replay.body, serde_json::to_value(&created).unwrap());
        assert_eq!(replay.etag.as_deref(), Some(etag.as_str()));

        let mut conflicting = input;
        conflicting.secret = Some("different-secret".to_owned());
        assert!(matches!(
            application
                .create_upstream_credential(
                    &identity,
                    ResourceScope::Deployment,
                    conflicting,
                    Some(&key),
                )
                .await,
            Err(ApplicationError::IdempotencyConflict)
        ));
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM upstream_credentials WHERE organization_id IS NULL AND name=$1",
        )
        .bind(name)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn static_secret_replacement_commits_and_deletes_retired_ciphertext() {
        let _database_guard = shared_database_test_lock().await;
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter("error")
            .try_init();
        let Some((store, runtime, application, seed_key)) =
            test_application("credential-replace-test").await
        else {
            return;
        };
        let identity = application
            .authenticate_management_key(&seed_key, "credential-replace-test".to_owned())
            .unwrap();
        let IdempotentCommand::Executed((created, _)) = application
            .create_upstream_credential(
                &identity,
                ResourceScope::Deployment,
                CreateUpstreamCredential {
                    name: format!("replace-test-{}", Uuid::now_v7()),
                    credential_kind: CredentialKind::StaticApiKey,
                    secret_source_kind: CredentialSourceKind::EncryptedDatabase,
                    source_configuration: json!({}),
                    injection_kind: "bearer".to_owned(),
                    sharing_policy: "exclusive".to_owned(),
                    secret: Some("initial-secret".to_owned()),
                    safe_metadata: json!({}),
                },
                None,
            )
            .await
            .unwrap()
        else {
            panic!("credential fixture create must execute");
        };
        let initial_protected_id = created.current_secret_version_id.unwrap().as_uuid();

        let idempotency_key = format!("replace-{}", Uuid::now_v7());
        let result = application
            .replace_upstream_credential_secret(
                &identity,
                ResourceScope::Deployment,
                created.id,
                ReplaceUpstreamCredentialSecret {
                    secret: "replacement-secret".to_owned(),
                },
                Some(&idempotency_key),
            )
            .await
            .unwrap();
        let IdempotentCommand::Executed((replaced, _)) = result else {
            panic!("first replacement must execute");
        };
        assert_eq!(replaced.current_secret_version, Some(2));
        assert_eq!(replaced.state_identity_version, 2);
        let replay = application
            .replace_upstream_credential_secret(
                &identity,
                ResourceScope::Deployment,
                created.id,
                ReplaceUpstreamCredentialSecret {
                    secret: "replacement-secret".to_owned(),
                },
                Some(&idempotency_key),
            )
            .await
            .unwrap();
        assert!(matches!(replay, IdempotentCommand::Replay(_)));

        let IdempotentCommand::Executed((other, _)) = application
            .create_upstream_credential(
                &identity,
                ResourceScope::Deployment,
                CreateUpstreamCredential {
                    name: format!("replace-other-test-{}", Uuid::now_v7()),
                    credential_kind: CredentialKind::StaticApiKey,
                    secret_source_kind: CredentialSourceKind::EncryptedDatabase,
                    source_configuration: json!({}),
                    injection_kind: "bearer".to_owned(),
                    sharing_policy: "exclusive".to_owned(),
                    secret: Some("other-initial-secret".to_owned()),
                    safe_metadata: json!({}),
                },
                None,
            )
            .await
            .unwrap()
        else {
            panic!("credential fixture create must execute");
        };
        let cross_resource = application
            .replace_upstream_credential_secret(
                &identity,
                ResourceScope::Deployment,
                other.id,
                ReplaceUpstreamCredentialSecret {
                    secret: "replacement-secret".to_owned(),
                },
                Some(&idempotency_key),
            )
            .await;
        assert!(matches!(
            cross_resource,
            Err(ApplicationError::IdempotencyConflict)
        ));
        assert_ne!(
            replaced.current_secret_version_id.unwrap().as_uuid(),
            initial_protected_id
        );
        let old_ciphertext_count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM protected_secret_versions WHERE id=$1",
        )
        .bind(initial_protected_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(old_ciphertext_count, 0);
        let retired = sqlx::query(
            "SELECT state,protected_secret_version_id
             FROM upstream_credential_secret_versions
             WHERE credential_id=$1 AND version=1",
        )
        .bind(created.id.as_uuid())
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(retired.try_get::<String, _>("state").unwrap(), "retired");
        assert!(
            retired
                .try_get::<Option<Uuid>, _>("protected_secret_version_id")
                .unwrap()
                .is_none()
        );
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn expired_codex_refresh_lease_is_terminalized_without_replay() {
        let _database_guard = shared_database_test_lock().await;
        let Some((store, runtime, application, _)) =
            test_application("codex-refresh-reconcile-test").await
        else {
            return;
        };
        let credential_id = Uuid::now_v7();
        let secret_id = Uuid::now_v7();
        let fingerprint = vec![19_u8; 32];
        let mut transaction = store.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO upstream_credentials(
                id,resource_scope_kind,name,credential_kind,secret_source_kind,injection_kind,
                sharing_policy,administrative_status,authentication_status,current_secret_version,
                state_identity_version,created_by_principal,etag_token)
             VALUES ($1,'deployment',$2,'oauth_openai_codex','encrypted_database','bearer',
                'exclusive','active','refreshing',1,1,'{}',$3)",
        )
        .bind(credential_id)
        .bind(format!("reconcile-{credential_id}"))
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO protected_secret_versions(
                id,scope_kind,owner_kind,owner_id,owner_generation,secret_version,
                field_purpose,custody_provider_id,provider_format_version,context_version,opaque_envelope)
             VALUES ($1,'system','upstream_credential',$2,1,1,
                'upstream_credential_material',$3,1,1,'\\x01')",
        )
        .bind(secret_id)
        .bind(credential_id)
        .bind(crate::secrets::SOFTWARE_PROVIDER_ID)
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO upstream_credential_secret_versions(
                id,credential_id,version,credential_state_identity_version,
                protected_secret_version_id,safe_fingerprint,state)
             VALUES ($1,$2,1,1,$1,$3,'current')",
        )
        .bind(secret_id)
        .bind(credential_id)
        .bind(&fingerprint)
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO upstream_credential_auth_state(
                credential_id,credential_state_identity_version,token_fingerprint,refresh_fence)
             VALUES ($1,1,$2,1)",
        )
        .bind(credential_id)
        .bind(&fingerprint)
        .execute(&mut *transaction)
        .await
        .unwrap();
        let lease_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO upstream_credential_refresh_leases(
                id,credential_id,credential_state_identity_version,secret_version,
                token_fingerprint,refresh_fence,attempt_token,state,lease_owner,
                lease_expires_at,network_deadline)
             VALUES ($1,$2,1,1,$3,1,$4,'refreshing','test',now()-interval '1 second',
                now()-interval '2 seconds')",
        )
        .bind(lease_id)
        .bind(credential_id)
        .bind(&fingerprint)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        transaction.commit().await.unwrap();

        assert_eq!(
            application
                .reconcile_expired_codex_refresh_leases(100)
                .await
                .unwrap(),
            1
        );
        let state = sqlx::query(
            "SELECT credential.authentication_status,lease.state,lease.safe_outcome,
                    auth.refresh_due_at,auth.last_safe_error
             FROM upstream_credentials credential
             JOIN upstream_credential_refresh_leases lease ON lease.credential_id=credential.id
             JOIN upstream_credential_auth_state auth ON auth.credential_id=credential.id
             WHERE credential.id=$1 AND lease.id=$2",
        )
        .bind(credential_id)
        .bind(lease_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(
            state.try_get::<String, _>("authentication_status").unwrap(),
            "refresh_outcome_unknown"
        );
        assert_eq!(
            state.try_get::<String, _>("state").unwrap(),
            "outcome_unknown"
        );
        assert_eq!(
            state.try_get::<Value, _>("safe_outcome").unwrap()["reason"],
            "lease_expired"
        );
        assert!(
            state
                .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("refresh_due_at")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            state.try_get::<Value, _>("last_safe_error").unwrap()["reason"],
            "refresh_lease_expired"
        );
        assert_eq!(
            application
                .reconcile_expired_codex_refresh_leases(100)
                .await
                .unwrap(),
            0
        );
        runtime.shutdown().await;
    }
}
