use std::net::IpAddr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row as _;
use uuid::Uuid;

use crate::{
    adapters::postgres::AuditRecord,
    domain::{Actor, Capability, ManagementScope, SessionId},
};

use super::{
    Application, ApplicationError, AuditEntry, AuditQuery, AuthorizationTarget, Page,
    ReadinessView, RequestIdentity, SessionView,
};

impl Application {
    pub fn require_operator_network(
        &self,
        source_address: Option<IpAddr>,
    ) -> Result<(), ApplicationError> {
        let source_address = source_address.ok_or(ApplicationError::Forbidden)?;
        if self
            .config
            .operator_networks
            .iter()
            .any(|network| network.contains(&source_address))
        {
            Ok(())
        } else {
            Err(ApplicationError::Forbidden)
        }
    }

    pub async fn list_system_audit(
        &self,
        identity: &RequestIdentity,
        query: &AuditQuery,
    ) -> Result<Page<AuditEntry>, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read],
            AuthorizationTarget::System {
                capability: Capability::ReadAudit,
            },
        )?;
        self.list_audit(None, query).await
    }

    pub async fn list_organization_audit(
        &self,
        identity: &RequestIdentity,
        organization_id: crate::domain::OrganizationId,
        query: &AuditQuery,
    ) -> Result<Page<AuditEntry>, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read],
            AuthorizationTarget::Organization {
                organization_id,
                capability: Capability::ReadAudit,
            },
        )?;
        self.list_audit(Some(organization_id.as_uuid()), query)
            .await
    }

    async fn list_audit(
        &self,
        organization_id: Option<Uuid>,
        query: &AuditQuery,
    ) -> Result<Page<AuditEntry>, ApplicationError> {
        validate_audit_query(query)?;
        let limit = query.limit.unwrap_or(50);
        let cursor = query
            .cursor
            .as_deref()
            .map(decode_audit_cursor)
            .transpose()?;
        if let Some(cursor) = &cursor {
            let expected = AuditCursorContext::new(organization_id, query);
            if cursor.context != expected {
                return Err(ApplicationError::Validation(
                    "audit cursor does not match the requested scope or filters".to_owned(),
                ));
            }
        }
        let cursor_created_at = cursor.as_ref().map(|cursor| cursor.created_at);
        let cursor_id = cursor.as_ref().map(|cursor| cursor.id);
        let mut rows = sqlx::query(
            "SELECT id, actor, authentication_evidence, organization_id,
                    target_resource_kind, target_resource_id, operation_id, outcome,
                    request_id, changed_fields, safe_details, created_at
             FROM audit_entries
             WHERE ($1::uuid IS NULL OR organization_id=$1)
               AND ($2::timestamptz IS NULL OR created_at >= $2)
               AND ($3::timestamptz IS NULL OR created_at < $3)
               AND ($4::text IS NULL OR operation_id=$4)
               AND ($5::text IS NULL OR outcome=$5)
               AND ($6::text IS NULL OR target_resource_kind=$6)
               AND ($7::timestamptz IS NULL OR (created_at, id) < ($7, $8))
             ORDER BY created_at DESC, id DESC LIMIT $9",
        )
        .bind(organization_id)
        .bind(query.since)
        .bind(query.before)
        .bind(query.operation_id.as_deref())
        .bind(query.outcome.as_deref())
        .bind(query.target_resource_kind.as_deref())
        .bind(cursor_created_at)
        .bind(cursor_id)
        .bind(i64::from(limit) + 1)
        .fetch_all(self.store.pool())
        .await?;
        let has_more = rows.len() > limit as usize;
        rows.truncate(limit as usize);
        let next_cursor = if has_more {
            let last = rows.last().ok_or(ApplicationError::Internal)?;
            Some(encode_audit_cursor(&AuditCursor {
                context: AuditCursorContext::new(organization_id, query),
                created_at: last.try_get("created_at")?,
                id: last.try_get("id")?,
            })?)
        } else {
            None
        };
        let items = rows
            .iter()
            .map(audit_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Page { items, next_cursor })
    }

    pub async fn operations_readiness(
        &self,
        identity: &RequestIdentity,
    ) -> Result<ReadinessView, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read, ManagementScope::Operations],
            AuthorizationTarget::Operations { write: false },
        )?;
        self.readiness_view().await
    }

    pub async fn operations_view(
        &self,
        identity: &RequestIdentity,
        view: &str,
    ) -> Result<Value, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read, ManagementScope::Operations],
            AuthorizationTarget::Operations { write: false },
        )?;
        match view {
            "overview" => {
                let readiness = self.readiness_view().await?;
                let counts = sqlx::query(
                    "SELECT
                        (SELECT count(*) FROM users WHERE status='active') AS active_users,
                        (SELECT count(*) FROM organizations WHERE status='active') AS active_organizations,
                        (SELECT count(*) FROM web_sessions WHERE status='active' AND expires_at > now()) AS active_sessions,
                        (SELECT count(*) FROM external_identity_issuers WHERE status='active') AS active_identity_issuers",
                )
                .fetch_one(self.store.pool())
                .await?;
                Ok(json!({
                    "readiness": readiness,
                    "module": "identity_and_management_plane",
                    "counts": {
                        "active_users": counts.try_get::<i64, _>("active_users")?,
                        "active_organizations": counts.try_get::<i64, _>("active_organizations")?,
                        "active_sessions": counts.try_get::<i64, _>("active_sessions")?,
                        "active_identity_issuers": counts.try_get::<i64, _>("active_identity_issuers")?,
                    }
                }))
            }
            "runtime" => {
                let status = self.runtime.status();
                let journal = sqlx::query(
                    "SELECT revision, event_kind, affected_scope, security_classification, committed_at
                     FROM configuration_journal ORDER BY revision DESC LIMIT 50",
                )
                .fetch_all(self.store.pool())
                .await?;
                let watermarks = sqlx::query(
                    "SELECT node_id, applied_revision, applied_security_revision,
                            last_success_at, last_failure_at, safe_failure_class, heartbeat_at
                     FROM node_watermarks ORDER BY node_id LIMIT 100",
                )
                .fetch_all(self.store.pool())
                .await?;
                Ok(json!({
                    "publication": &*status,
                    "journal": journal.into_iter().map(|row| json!({
                        "revision": row.get::<i64, _>("revision"),
                        "event_kind": row.get::<String, _>("event_kind"),
                        "affected_scope": row.get::<Value, _>("affected_scope"),
                        "security_classification": row.get::<String, _>("security_classification"),
                        "committed_at": row.get::<chrono::DateTime<Utc>, _>("committed_at"),
                    })).collect::<Vec<_>>(),
                    "node_watermarks": watermarks.into_iter().map(|row| json!({
                        "node_id": row.get::<String, _>("node_id"),
                        "applied_revision": row.get::<i64, _>("applied_revision"),
                        "applied_security_revision": row.get::<i64, _>("applied_security_revision"),
                        "last_success_at": row.get::<Option<chrono::DateTime<Utc>>, _>("last_success_at"),
                        "last_failure_at": row.get::<Option<chrono::DateTime<Utc>>, _>("last_failure_at"),
                        "safe_failure_class": row.get::<Option<String>, _>("safe_failure_class"),
                        "heartbeat_at": row.get::<chrono::DateTime<Utc>, _>("heartbeat_at"),
                    })).collect::<Vec<_>>(),
                }))
            }
            "coordination" => {
                let leases = sqlx::query(
                    "SELECT worker_kind, item_id, fencing_token, owner, lease_expires_at, attempt
                     FROM worker_leases WHERE lease_expires_at > now()
                     ORDER BY worker_kind, item_id LIMIT 100",
                )
                .fetch_all(self.store.pool())
                .await?;
                Ok(json!({
                    "redis": {"status":"not_applicable_in_module_i"},
                    "active_worker_leases": leases.into_iter().map(|row| json!({
                        "worker_kind": row.get::<String, _>("worker_kind"),
                        "item_id": row.get::<String, _>("item_id"),
                        "fencing_token": row.get::<i64, _>("fencing_token"),
                        "owner": row.get::<String, _>("owner"),
                        "lease_expires_at": row.get::<chrono::DateTime<Utc>, _>("lease_expires_at"),
                        "attempt": row.get::<i32, _>("attempt"),
                    })).collect::<Vec<_>>(),
                }))
            }
            "recoveries" => {
                let due_outbox = sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM transactional_outbox
                     WHERE state IN ('pending','failed') AND next_attempt_at <= now()",
                )
                .fetch_one(self.store.pool())
                .await?;
                Ok(json!({
                    "available_actions": ["reconcile_runtime", "cleanup_expired_identity_state"],
                    "due_outbox_items": due_outbox,
                }))
            }
            "secret-custody" => {
                let protected_records =
                    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM protected_secret_versions")
                        .fetch_one(self.store.pool())
                        .await?;
                Ok(json!({
                    "status": "ready",
                    "provider": "owlrora.software.v1",
                    "envelope_format_version": 1,
                    "protected_record_count": protected_records,
                }))
            }
            "telemetry" => Ok(json!({
                "status": "not_configured",
                "export": "standard_opentelemetry",
                "required_for_readiness": false,
            })),
            _ => Err(ApplicationError::NotFound),
        }
    }

    pub async fn reconcile_runtime(
        &self,
        identity: &RequestIdentity,
    ) -> Result<Value, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Write, ManagementScope::Operations],
            AuthorizationTarget::Operations { write: true },
        )?;
        let applied_revision = self.runtime.refresh_now(&self.store).await?;
        let transaction = self.store.begin().await?;
        self.store
            .commit_command(
                transaction,
                &AuditRecord {
                    actor: Some(Actor::from(&identity.principal)),
                    authentication_evidence: json!({"method":identity.principal.authentication_method}),
                    organization_id: None,
                    target_resource_kind: "runtime_generation".to_owned(),
                    target_resource_id: None,
                    operation_id: "system.operations.runtime.reconcile".to_owned(),
                    outcome: "accepted",
                    request_id: identity.request_id.clone(),
                    changed_fields: vec!["applied_revision".to_owned()],
                    safe_details: json!({"applied_revision": applied_revision}),
                },
                None,
            )
            .await?;
        Ok(json!({"applied_revision": applied_revision}))
    }

    pub async fn public_ready(&self) -> bool {
        self.readiness_view().await.is_ok_and(|view| view.ready)
    }

    pub async fn list_principal_sessions(
        &self,
        identity: &RequestIdentity,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<SessionView>, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read],
            AuthorizationTarget::CurrentPrincipal,
        )?;
        let family = "me_sessions";
        let (cursor, limit) = super::resources::page_parameters(family, cursor, limit)?;
        let principal = serde_json::to_value(&identity.principal.principal)
            .map_err(|_| ApplicationError::Internal)?;
        let rows = sqlx::query(
            "SELECT id, principal, authentication_method, created_at, expires_at
             FROM web_sessions
             WHERE principal=$1 AND status='active' AND expires_at > now()
               AND ($2::uuid IS NULL OR id < $2)
             ORDER BY id DESC LIMIT $3",
        )
        .bind(principal)
        .bind(cursor)
        .bind(i64::from(limit) + 1)
        .fetch_all(self.store.pool())
        .await?;
        let mut page =
            super::resources::page_from_rows(rows, limit, family, session_view_from_row)?;
        for session in &mut page.items {
            session.current = identity.principal.session_id == Some(session.id);
        }
        Ok(page)
    }

    pub async fn revoke_principal_session(
        &self,
        identity: &RequestIdentity,
        session_id: SessionId,
    ) -> Result<(), ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Write],
            AuthorizationTarget::CurrentPrincipal,
        )?;
        let principal = serde_json::to_value(&identity.principal.principal)
            .map_err(|_| ApplicationError::Internal)?;
        let mut transaction = self.store.begin().await?;
        let changed = sqlx::query(
            "UPDATE web_sessions SET status='revoked', revoked_at=now()
             WHERE id=$1 AND principal=$2 AND status='active'",
        )
        .bind(session_id.as_uuid())
        .bind(principal)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed == 0 {
            return Err(ApplicationError::NotFound);
        }
        self.store
            .commit_command(
                transaction,
                &AuditRecord {
                    actor: Some(Actor::from(&identity.principal)),
                    authentication_evidence: json!({"method":identity.principal.authentication_method}),
                    organization_id: None,
                    target_resource_kind: "web_session".to_owned(),
                    target_resource_id: Some(session_id.to_string()),
                    operation_id: "sessions.revoke".to_owned(),
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

    pub async fn cleanup_expired_identity_state(
        &self,
        identity: &RequestIdentity,
    ) -> Result<u64, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Write, ManagementScope::Operations],
            AuthorizationTarget::Operations { write: true },
        )?;
        let mut transaction = self.store.begin().await?;
        let oidc_states = sqlx::query(
            "DELETE FROM oidc_login_states
             WHERE id IN (
                 SELECT state.id
                 FROM oidc_login_states state
                 JOIN (
                     (SELECT id FROM oidc_login_states WHERE expires_at < now()
                      ORDER BY expires_at, id LIMIT 500)
                     UNION
                     (SELECT id FROM oidc_login_states
                      WHERE consumed_at < now()-interval '1 hour'
                      ORDER BY consumed_at, id LIMIT 500)
                 ) candidate USING (id)
                 ORDER BY state.expires_at, state.id
                 LIMIT 500 FOR UPDATE OF state SKIP LOCKED
             )",
        )
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let web_sessions = sqlx::query(
            "DELETE FROM web_sessions
             WHERE id IN (
                 SELECT session.id
                 FROM web_sessions session
                 JOIN (
                     (SELECT id FROM web_sessions
                      WHERE expires_at < now()-interval '7 days'
                      ORDER BY expires_at, id LIMIT 500)
                     UNION
                     (SELECT id FROM web_sessions
                      WHERE revoked_at < now()-interval '7 days'
                      ORDER BY revoked_at, id LIMIT 500)
                 ) candidate USING (id)
                 ORDER BY session.expires_at, session.id
                 LIMIT 500 FOR UPDATE OF session SKIP LOCKED
             )",
        )
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let idempotency_records = sqlx::query(
            "DELETE FROM idempotency_records
             WHERE (actor_fingerprint, scope_fingerprint, operation_id, idempotency_key) IN (
                 SELECT actor_fingerprint, scope_fingerprint, operation_id, idempotency_key
                 FROM idempotency_records
                 WHERE state='completed' AND expires_at < now()
                 ORDER BY expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED
             )",
        )
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let changed = oidc_states
            .checked_add(web_sessions)
            .and_then(|value| value.checked_add(idempotency_records))
            .ok_or(ApplicationError::Internal)?;
        self.store
            .commit_command(
                transaction,
                &AuditRecord {
                    actor: Some(Actor::from(&identity.principal)),
                    authentication_evidence: json!({"method":identity.principal.authentication_method}),
                    organization_id: None,
                    target_resource_kind: "expired_identity_state".to_owned(),
                    target_resource_id: None,
                    operation_id: "system.operations.identity_state.cleanup".to_owned(),
                    outcome: "accepted",
                    request_id: identity.request_id.clone(),
                    changed_fields: vec!["expired_records".to_owned()],
                    safe_details: json!({"changed":changed}),
                },
                None,
            )
            .await?;
        Ok(changed)
    }

    async fn readiness_view(&self) -> Result<ReadinessView, ApplicationError> {
        let database_revision = self.store.current_revision().await?;
        let status = self.runtime.status();
        let runtime_age_seconds = Utc::now()
            .signed_duration_since(status.confirmed_at)
            .num_seconds()
            .max(0);
        let ready = status.applied_revision >= database_revision
            && runtime_age_seconds
                <= i64::try_from(self.config.max_security_snapshot_age.as_secs())
                    .unwrap_or(i64::MAX);
        Ok(ReadinessView {
            ready,
            database: "available".to_owned(),
            runtime_revision: status.applied_revision,
            database_revision,
            runtime_age_seconds,
            publication_error: status.last_error.clone(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct AuditCursorContext {
    organization_id: Option<Uuid>,
    since: Option<DateTime<Utc>>,
    before: Option<DateTime<Utc>>,
    operation_id: Option<String>,
    outcome: Option<String>,
    target_resource_kind: Option<String>,
}

impl AuditCursorContext {
    fn new(organization_id: Option<Uuid>, query: &AuditQuery) -> Self {
        Self {
            organization_id,
            since: query.since,
            before: query.before,
            operation_id: query.operation_id.clone(),
            outcome: query.outcome.clone(),
            target_resource_kind: query.target_resource_kind.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AuditCursor {
    context: AuditCursorContext,
    created_at: DateTime<Utc>,
    id: Uuid,
}

fn validate_audit_query(query: &AuditQuery) -> Result<(), ApplicationError> {
    if !(1..=100).contains(&query.limit.unwrap_or(50)) {
        return Err(ApplicationError::Validation(
            "audit limit must be between 1 and 100".to_owned(),
        ));
    }
    if query
        .since
        .zip(query.before)
        .is_some_and(|(since, before)| since >= before)
    {
        return Err(ApplicationError::Validation(
            "audit since must be earlier than before".to_owned(),
        ));
    }
    if query.operation_id.as_deref().is_some_and(|value| {
        value.is_empty() || value.len() > 160 || value.chars().any(char::is_control)
    }) {
        return Err(ApplicationError::Validation(
            "audit operation_id filter is invalid".to_owned(),
        ));
    }
    if query.target_resource_kind.as_deref().is_some_and(|value| {
        value.is_empty() || value.len() > 96 || value.chars().any(char::is_control)
    }) {
        return Err(ApplicationError::Validation(
            "audit target_resource_kind filter is invalid".to_owned(),
        ));
    }
    if query
        .outcome
        .as_deref()
        .is_some_and(|value| !matches!(value, "accepted" | "rejected" | "failed"))
    {
        return Err(ApplicationError::Validation(
            "audit outcome filter is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn decode_audit_cursor(value: &str) -> Result<AuditCursor, ApplicationError> {
    if value.is_empty() || value.len() > 2048 {
        return Err(ApplicationError::Validation(
            "audit cursor is invalid".to_owned(),
        ));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApplicationError::Validation("audit cursor is invalid".to_owned()))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| ApplicationError::Validation("audit cursor is invalid".to_owned()))
}

fn encode_audit_cursor(cursor: &AuditCursor) -> Result<String, ApplicationError> {
    let bytes = serde_json::to_vec(cursor).map_err(|_| ApplicationError::Internal)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn session_view_from_row(row: sqlx::postgres::PgRow) -> Result<SessionView, ApplicationError> {
    let authentication_method = match row.try_get::<String, _>("authentication_method")?.as_str() {
        "management_api_key_session" => {
            crate::domain::AuthenticationMethod::ManagementApiKeySession
        }
        "external_session" => crate::domain::AuthenticationMethod::ExternalSession,
        _ => return Err(ApplicationError::Internal),
    };
    Ok(SessionView {
        id: SessionId::from_uuid(row.try_get("id")?),
        principal: serde_json::from_value(row.try_get("principal")?)
            .map_err(|_| ApplicationError::Internal)?,
        authentication_method,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        current: false,
    })
}

fn audit_from_row(row: &sqlx::postgres::PgRow) -> Result<AuditEntry, ApplicationError> {
    Ok(AuditEntry {
        id: row.try_get::<uuid::Uuid, _>("id")?.to_string(),
        actor: row.try_get("actor")?,
        authentication_evidence: row.try_get("authentication_evidence")?,
        organization_id: row
            .try_get::<Option<uuid::Uuid>, _>("organization_id")?
            .map(crate::domain::OrganizationId::from_uuid),
        target_resource_kind: row.try_get("target_resource_kind")?,
        target_resource_id: row.try_get("target_resource_id")?,
        operation_id: row.try_get("operation_id")?,
        outcome: row.try_get("outcome")?,
        request_id: row.try_get("request_id")?,
        changed_fields: serde_json::from_value::<Vec<String>>(
            row.try_get::<Value, _>("changed_fields")?,
        )
        .map_err(|_| ApplicationError::Internal)?,
        safe_details: row.try_get("safe_details")?,
        created_at: row.try_get("created_at")?,
    })
}
