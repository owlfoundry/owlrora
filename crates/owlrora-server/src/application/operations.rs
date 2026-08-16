use std::net::IpAddr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row as _;
use uuid::Uuid;

use crate::{
    adapters::{
        coordinator::{CoordinatorRecoveryInstall, PolicyCoordinatorConfig},
        postgres::{AuditRecord, RuntimeEvent},
    },
    domain::{
        Actor, BudgetAllowancePolicy, BudgetRecoveryPolicy, Capability, ManagementScope,
        OrganizationId, PolicyKind, SessionId, TargetId,
    },
    gateway::UsageStatus,
};

use super::{
    Application, ApplicationError, AuditEntry, AuditQuery, AuthorizationTarget, Page,
    ReadinessView, RequestIdentity, SessionView,
};

#[derive(Clone, Debug, Deserialize)]
pub struct CleanupStateOrigins {
    pub organization_id: OrganizationId,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ProbeTargets {
    pub target_ids: Vec<Uuid>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPolicyKind {
    GatewayKeyBudget,
    OrganizationOriginBudget,
}

impl RecoveryPolicyKind {
    const fn as_policy_kind(self) -> PolicyKind {
        match self {
            Self::GatewayKeyBudget => PolicyKind::GatewayKeyBudget,
            Self::OrganizationOriginBudget => PolicyKind::OrganizationOriginBudget,
        }
    }

    const fn as_str(self) -> &'static str {
        self.as_policy_kind().as_str()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CoordinatorRecoveryAllocation {
    pub organization_id: OrganizationId,
    pub policy_kind: RecoveryPolicyKind,
    pub policy_id: Uuid,
    pub authorized_allowance_nanos: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateCoordinatorRecoveries {
    pub incident_reference: String,
    pub reason: String,
    pub safe_evidence: Value,
    pub allocations: Vec<CoordinatorRecoveryAllocation>,
}

#[derive(Clone, Debug)]
struct RecoveryPlan {
    install: CoordinatorRecoveryInstall,
    cumulative_epoch_allowance_nanos: u128,
    recovery_epoch_cap_nanos: u128,
}

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
                let redis_status = if let Some(coordinator) = &self.coordinator {
                    if coordinator.ping().await.is_ok() {
                        "ready"
                    } else {
                        "unavailable"
                    }
                } else {
                    "not_configured"
                };
                let recovery_counts = sqlx::query(
                    "SELECT
                        count(*) FILTER (WHERE status='installed') AS installed,
                        count(*) FILTER (WHERE status='pending') AS pending,
                        count(*) FILTER (WHERE status='failed') AS failed
                     FROM coordinator_recovery_installations",
                )
                .fetch_one(self.store.pool())
                .await?;
                Ok(json!({
                    "redis": {"status":redis_status},
                    "recovery_installations":{
                        "installed":recovery_counts.get::<i64, _>("installed"),
                        "pending":recovery_counts.get::<i64, _>("pending"),
                        "failed":recovery_counts.get::<i64, _>("failed"),
                    },
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
            "activations" => {
                let rows = sqlx::query(
                    "SELECT id, organization_id, policy_kind, policy_id, desired_epoch,
                            desired_version_id, desired_generation, active_epoch, active_version_id,
                            active_generation, prior_epoch, prior_version_id, prior_generation,
                            state, tightening_deadline, prior_cutoff_at, safe_error,
                            created_at, updated_at
                     FROM policy_activations
                     ORDER BY updated_at DESC, id DESC LIMIT 100",
                )
                .fetch_all(self.store.pool())
                .await?;
                Ok(json!({
                    "scope":"latest_100_durable_policy_activations",
                    "items":rows.into_iter().map(|row| json!({
                        "id":row.get::<Uuid, _>("id"),
                        "organization_id":row.get::<Uuid, _>("organization_id"),
                        "policy_kind":row.get::<String, _>("policy_kind"),
                        "policy_id":row.get::<Uuid, _>("policy_id"),
                        "desired_epoch":row.get::<String, _>("desired_epoch"),
                        "desired_version_id":row.get::<Uuid, _>("desired_version_id"),
                        "desired_generation":row.get::<i64, _>("desired_generation"),
                        "active_epoch":row.get::<Option<String>, _>("active_epoch"),
                        "active_version_id":row.get::<Option<Uuid>, _>("active_version_id"),
                        "active_generation":row.get::<Option<i64>, _>("active_generation"),
                        "prior_epoch":row.get::<Option<String>, _>("prior_epoch"),
                        "prior_version_id":row.get::<Option<Uuid>, _>("prior_version_id"),
                        "prior_generation":row.get::<Option<i64>, _>("prior_generation"),
                        "state":row.get::<String, _>("state"),
                        "tightening_deadline":row.get::<Option<chrono::DateTime<Utc>>, _>("tightening_deadline"),
                        "prior_cutoff_at":row.get::<Option<chrono::DateTime<Utc>>, _>("prior_cutoff_at"),
                        "safe_error":row.get::<Option<Value>, _>("safe_error"),
                        "created_at":row.get::<chrono::DateTime<Utc>, _>("created_at"),
                        "updated_at":row.get::<chrono::DateTime<Utc>, _>("updated_at"),
                    })).collect::<Vec<_>>()
                }))
            }
            "state-origins" => {
                let generation = self.runtime.capture();
                let mut routes = generation
                    .snapshot
                    .catalog
                    .routes
                    .values()
                    .filter(|route| route.ingress_protocol_family.as_str() == "openai_responses")
                    .map(|route| {
                        json!({
                            "route_id":route.id,
                            "protocol_family":route.ingress_protocol_family,
                            "ttl_seconds":route.request_policy.state_origin_ttl_seconds,
                            "cleanup":"automatic_redis_ttl",
                        })
                    })
                    .collect::<Vec<_>>();
                routes.sort_by_key(|route| route["route_id"].to_string());
                let coordinator_status = if let Some(coordinator) = &self.coordinator {
                    if coordinator.ping().await.is_ok() {
                        "ready"
                    } else {
                        "unavailable"
                    }
                } else {
                    "not_configured"
                };
                Ok(json!({
                    "scope":"configured_stateful_routes_and_coordinator_status",
                    "coordinator_status":coordinator_status,
                    "binding_inventory":"not_enumerable_by_design",
                    "routes":routes,
                }))
            }
            "upstream-credentials" => {
                let auth_states = sqlx::query(
                    "SELECT credential_id, credential_state_identity_version, refresh_due_at,
                            refresh_backoff_until, refresh_failure_count, last_safe_error,
                            refresh_fence, updated_at
                     FROM upstream_credential_auth_state
                     WHERE refresh_due_at IS NOT NULL OR refresh_failure_count > 0
                     ORDER BY COALESCE(refresh_due_at, updated_at), credential_id LIMIT 100",
                )
                .fetch_all(self.store.pool())
                .await?;
                let login_sessions = sqlx::query(
                    "SELECT id, credential_id, credential_state_identity_version, state,
                            claim_expires_at, poll_interval_seconds, expires_at, next_poll_at,
                            terminal_cleanup_at, updated_at
                     FROM upstream_credential_login_sessions
                     WHERE state IN ('pending','polling','exchanging','failed')
                     ORDER BY updated_at, id LIMIT 100",
                )
                .fetch_all(self.store.pool())
                .await?;
                let refresh_leases = sqlx::query(
                    "SELECT id, credential_id, credential_state_identity_version, secret_version,
                            refresh_fence, state, lease_owner, lease_expires_at, network_deadline,
                            safe_outcome, created_at, completed_at
                     FROM upstream_credential_refresh_leases
                     WHERE state IN ('refreshing','outcome_unknown')
                     ORDER BY lease_expires_at, id LIMIT 100",
                )
                .fetch_all(self.store.pool())
                .await?;
                Ok(json!({
                    "scope":"bounded_due_and_fenced_controller_state",
                    "auth_states":auth_states.into_iter().map(|row| json!({
                        "credential_id":row.get::<Uuid, _>("credential_id"),
                        "credential_state_identity_version":row.get::<i64, _>("credential_state_identity_version"),
                        "refresh_due_at":row.get::<Option<chrono::DateTime<Utc>>, _>("refresh_due_at"),
                        "refresh_backoff_until":row.get::<Option<chrono::DateTime<Utc>>, _>("refresh_backoff_until"),
                        "refresh_failure_count":row.get::<i32, _>("refresh_failure_count"),
                        "last_safe_error":row.get::<Option<Value>, _>("last_safe_error"),
                        "refresh_fence":row.get::<i64, _>("refresh_fence"),
                        "updated_at":row.get::<chrono::DateTime<Utc>, _>("updated_at"),
                    })).collect::<Vec<_>>(),
                    "login_sessions":login_sessions.into_iter().map(|row| json!({
                        "id":row.get::<Uuid, _>("id"),
                        "credential_id":row.get::<Uuid, _>("credential_id"),
                        "credential_state_identity_version":row.get::<i64, _>("credential_state_identity_version"),
                        "state":row.get::<String, _>("state"),
                        "claim_expires_at":row.get::<Option<chrono::DateTime<Utc>>, _>("claim_expires_at"),
                        "poll_interval_seconds":row.get::<i32, _>("poll_interval_seconds"),
                        "expires_at":row.get::<chrono::DateTime<Utc>, _>("expires_at"),
                        "next_poll_at":row.get::<Option<chrono::DateTime<Utc>>, _>("next_poll_at"),
                        "terminal_cleanup_at":row.get::<Option<chrono::DateTime<Utc>>, _>("terminal_cleanup_at"),
                        "updated_at":row.get::<chrono::DateTime<Utc>, _>("updated_at"),
                    })).collect::<Vec<_>>(),
                    "refresh_leases":refresh_leases.into_iter().map(|row| json!({
                        "id":row.get::<Uuid, _>("id"),
                        "credential_id":row.get::<Uuid, _>("credential_id"),
                        "credential_state_identity_version":row.get::<i64, _>("credential_state_identity_version"),
                        "secret_version":row.get::<i64, _>("secret_version"),
                        "refresh_fence":row.get::<i64, _>("refresh_fence"),
                        "state":row.get::<String, _>("state"),
                        "lease_owner":row.get::<String, _>("lease_owner"),
                        "lease_expires_at":row.get::<chrono::DateTime<Utc>, _>("lease_expires_at"),
                        "network_deadline":row.get::<chrono::DateTime<Utc>, _>("network_deadline"),
                        "safe_outcome":row.get::<Option<Value>, _>("safe_outcome"),
                        "created_at":row.get::<chrono::DateTime<Utc>, _>("created_at"),
                        "completed_at":row.get::<Option<chrono::DateTime<Utc>>, _>("completed_at"),
                    })).collect::<Vec<_>>(),
                }))
            }
            "recoveries" => {
                let rows = sqlx::query(
                    "SELECT recovery.id,recovery.organization_id,recovery.policy_kind,
                            recovery.policy_id,recovery.policy_version_id,recovery.epoch,
                            recovery.policy_generation,recovery.recovery_generation,
                            recovery.authorized_allowance_nanos::text AS allowance,
                            recovery.cumulative_epoch_allowance_nanos::text AS cumulative,
                            recovery.incident_reference,recovery.reason,recovery.safe_evidence,
                            recovery.created_at,
                            version.recovery_incident_cap_nanos::text AS incident_cap,
                            version.recovery_epoch_cap_nanos::text AS epoch_cap,
                            installation.status AS installation_status,
                            installation.attempt_count,installation.last_attempt_at,
                            installation.installed_at,installation.safe_error,
                            installation.updated_at
                     FROM coordinator_recoveries recovery
                     JOIN budget_policy_versions version ON version.id=recovery.policy_version_id
                     JOIN coordinator_recovery_installations installation
                       ON installation.recovery_id=recovery.id
                     ORDER BY recovery.created_at DESC,recovery.id DESC LIMIT 100",
                )
                .fetch_all(self.store.pool())
                .await?;
                Ok(json!({
                    "scope":"latest_100_durable_coordinator_recoveries",
                    "items":rows.into_iter().map(|row| json!({
                        "id":row.get::<Uuid, _>("id"),
                        "organization_id":row.get::<Uuid, _>("organization_id"),
                        "policy_kind":row.get::<String, _>("policy_kind"),
                        "policy_id":row.get::<Uuid, _>("policy_id"),
                        "policy_version_id":row.get::<Uuid, _>("policy_version_id"),
                        "epoch":row.get::<String, _>("epoch"),
                        "policy_generation":row.get::<i64, _>("policy_generation"),
                        "recovery_generation":row.get::<i64, _>("recovery_generation"),
                        "authorized_allowance_nanos":row.get::<String, _>("allowance"),
                        "cumulative_epoch_allowance_nanos":row.get::<String, _>("cumulative"),
                        "incident_cap_nanos":row.get::<String, _>("incident_cap"),
                        "epoch_cap_nanos":row.get::<String, _>("epoch_cap"),
                        "incident_reference":row.get::<String, _>("incident_reference"),
                        "reason":row.get::<String, _>("reason"),
                        "safe_evidence":row.get::<Value, _>("safe_evidence"),
                        "installation":{
                            "status":row.get::<String, _>("installation_status"),
                            "attempt_count":row.get::<i32, _>("attempt_count"),
                            "last_attempt_at":row.get::<Option<chrono::DateTime<Utc>>, _>("last_attempt_at"),
                            "installed_at":row.get::<Option<chrono::DateTime<Utc>>, _>("installed_at"),
                            "safe_error":row.get::<Option<Value>, _>("safe_error"),
                            "updated_at":row.get::<chrono::DateTime<Utc>, _>("updated_at"),
                        },
                        "calculated_exposure":{
                            "recovery_epoch_cap_nanos":row.get::<String, _>("epoch_cap"),
                            "in_flight_actual_cost_excess_nanos":Value::Null,
                            "upper_bound_nanos":Value::Null,
                            "status":"unavailable_without_a_finite_per_attempt_excess_bound",
                        },
                        "created_at":row.get::<chrono::DateTime<Utc>, _>("created_at"),
                    })).collect::<Vec<_>>(),
                }))
            }
            "secret-custody" => {
                let protected_records =
                    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM protected_secret_versions")
                        .fetch_one(self.store.pool())
                        .await?;
                let persisted_pairs = sqlx::query(
                    "SELECT custody_provider_id,provider_format_version,count(*) AS record_count
                     FROM protected_secret_versions
                     GROUP BY custody_provider_id,provider_format_version
                     ORDER BY custody_provider_id,provider_format_version",
                )
                .fetch_all(self.store.pool())
                .await?;
                let configured_pairs = self
                    .secrets
                    .configured_pairs()
                    .into_iter()
                    .map(|pair| {
                        json!({
                            "provider_id": pair.provider_id().as_str(),
                            "format_version": pair.format_version().get(),
                            "active_for_writes": &pair == self.secrets.write_pair(),
                            "open_ready": self.secrets.supports_open_pair(&pair),
                        })
                    })
                    .collect::<Vec<_>>();
                let persisted_pairs = persisted_pairs
                    .into_iter()
                    .map(|row| {
                        let provider_id = row.get::<String, _>("custody_provider_id");
                        let format_version = row.get::<i32, _>("provider_format_version");
                        json!({
                            "provider_id": provider_id,
                            "format_version": format_version,
                            "record_count": row.get::<i64, _>("record_count"),
                        })
                    })
                    .collect::<Vec<_>>();
                Ok(json!({
                    "status": "ready",
                    "active_write_pair": {
                        "provider_id": self.secrets.write_pair().provider_id().as_str(),
                        "format_version": self.secrets.write_pair().format_version().get(),
                    },
                    "configured_pairs": configured_pairs,
                    "persisted_pairs": persisted_pairs,
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
        let applied_revision = self.runtime.refresh_now().await?;
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

    pub async fn create_coordinator_recoveries(
        &self,
        identity: &RequestIdentity,
        input: &CreateCoordinatorRecoveries,
    ) -> Result<Value, ApplicationError> {
        self.authorize_operations_command(identity)?;
        validate_recovery_request(input)?;
        let mut allocations = input.allocations.clone();
        allocations.sort_by_key(|allocation| {
            (
                allocation.organization_id,
                allocation.policy_kind,
                allocation.policy_id,
            )
        });
        for pair in allocations.windows(2) {
            if pair[0].organization_id == pair[1].organization_id
                && pair[0].policy_kind == pair[1].policy_kind
                && pair[0].policy_id == pair[1].policy_id
            {
                return Err(ApplicationError::Validation(
                    "recovery allocations must identify distinct policies".to_owned(),
                ));
            }
        }

        let actor = serde_json::to_value(Actor::from(&identity.principal))
            .map_err(|_| ApplicationError::Internal)?;
        let mut transaction = self.store.begin().await?;
        let mut plans = Vec::with_capacity(allocations.len());
        for allocation in &allocations {
            let allowance = parse_recovery_nanos(
                &allocation.authorized_allowance_nanos,
                "authorized_allowance_nanos",
            )?;
            let policy = load_recovery_policy(
                &mut transaction,
                allocation.organization_id,
                allocation.policy_kind,
                allocation.policy_id,
            )
            .await?;
            if policy.recovery_policy.require_verified_state_loss
                && input.safe_evidence.get("verified_state_loss") != Some(&Value::Bool(true))
            {
                return Err(ApplicationError::Validation(
                    "verified_state_loss evidence is required by the policy".to_owned(),
                ));
            }
            let incident_exists = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(
                    SELECT 1 FROM coordinator_recoveries
                    WHERE policy_kind=$1 AND policy_id=$2 AND epoch=$3
                      AND incident_reference=$4
                 )",
            )
            .bind(allocation.policy_kind.as_str())
            .bind(allocation.policy_id)
            .bind(&policy.epoch)
            .bind(input.incident_reference.trim())
            .fetch_one(&mut *transaction)
            .await?;
            if incident_exists {
                return Err(ApplicationError::Conflict(
                    "the incident is already authorized for a selected policy epoch".to_owned(),
                ));
            }
            let recovery_generation = policy
                .prior_recovery_generation
                .checked_add(1)
                .ok_or(ApplicationError::Internal)?;
            let cumulative = policy
                .prior_cumulative_allowance_nanos
                .checked_add(allowance)
                .ok_or_else(|| {
                    ApplicationError::Validation(
                        "cumulative recovery allowance exceeds numeric range".to_owned(),
                    )
                })?;
            if allowance > policy.incident_cap_nanos || cumulative > policy.epoch_cap_nanos {
                return Err(ApplicationError::Validation(
                    "recovery allowance exceeds the current incident or epoch cap".to_owned(),
                ));
            }
            let recovery_id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO coordinator_recoveries(
                    id,organization_id,policy_kind,policy_id,policy_version_id,epoch,
                    policy_generation,recovery_generation,authorized_allowance_nanos,
                    cumulative_epoch_allowance_nanos,incident_reference,
                    authorized_by_principal,safe_evidence,reason
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::numeric,$10::numeric,$11,$12,$13,$14)",
            )
            .bind(recovery_id)
            .bind(allocation.organization_id.as_uuid())
            .bind(allocation.policy_kind.as_str())
            .bind(allocation.policy_id)
            .bind(policy.version_id)
            .bind(&policy.epoch)
            .bind(i64::try_from(policy.policy_generation).map_err(|_| ApplicationError::Internal)?)
            .bind(i64::try_from(recovery_generation).map_err(|_| ApplicationError::Internal)?)
            .bind(allowance.to_string())
            .bind(cumulative.to_string())
            .bind(input.incident_reference.trim())
            .bind(&actor)
            .bind(&input.safe_evidence)
            .bind(input.reason.trim())
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "INSERT INTO coordinator_recovery_installations(recovery_id,status)
                 VALUES ($1,'pending')",
            )
            .bind(recovery_id)
            .execute(&mut *transaction)
            .await?;
            plans.push(RecoveryPlan {
                install: CoordinatorRecoveryInstall {
                    recovery_id,
                    organization_id: allocation.organization_id,
                    kind: allocation.policy_kind.as_policy_kind(),
                    policy_id: allocation.policy_id,
                    version_id: policy.version_id,
                    epoch: policy.epoch,
                    policy_generation: policy.policy_generation,
                    recovery_generation,
                    authorized_allowance_nanos: allowance,
                    limit_cost_nanos: policy.limit_cost_nanos,
                    config: PolicyCoordinatorConfig::Budget {
                        version_id: policy.version_id,
                        mode: "enforce".to_owned(),
                        limit_cost_nanos: policy.limit_cost_nanos.to_string(),
                        max_slice_nanos: policy.allowance_policy.max_slice_nanos.to_string(),
                        grant_seconds: policy.allowance_policy.grant_seconds,
                    },
                },
                cumulative_epoch_allowance_nanos: cumulative,
                recovery_epoch_cap_nanos: policy.epoch_cap_nanos,
            });
        }
        self.store
            .commit_command(
                transaction,
                &AuditRecord {
                    actor: Some(Actor::from(&identity.principal)),
                    authentication_evidence: json!({"method":identity.principal.authentication_method}),
                    organization_id: None,
                    target_resource_kind: "coordinator_recovery".to_owned(),
                    target_resource_id: None,
                    operation_id: "system.operations.coordination.recoveries.create".to_owned(),
                    outcome: "accepted",
                    request_id: identity.request_id.clone(),
                    changed_fields: vec!["recovery_generation".to_owned(), "authorized_allowance".to_owned()],
                    safe_details: json!({
                        "incident_reference":input.incident_reference.trim(),
                        "reason":input.reason.trim(),
                        "allocation_count":plans.len(),
                        "recovery_ids":plans.iter().map(|plan| plan.install.recovery_id).collect::<Vec<_>>(),
                    }),
                },
                Some(&RuntimeEvent {
                    event_kind: "coordinator.recovery_authorized".to_owned(),
                    affected_scope: json!({
                        "incident_reference":input.incident_reference.trim(),
                        "recovery_ids":plans.iter().map(|plan| plan.install.recovery_id).collect::<Vec<_>>(),
                    }),
                    security_tightening: true,
                }),
            )
            .await?;
        self.publish_committed_runtime(
            &identity.request_id,
            "system.operations.coordination.recoveries.create",
        )
        .await;

        let mut items = Vec::with_capacity(plans.len());
        for plan in &plans {
            let installed = self.install_coordinator_recovery(plan).await;
            items.push(recovery_plan_json(plan, installed));
        }
        Ok(json!({
            "incident_reference":input.incident_reference.trim(),
            "items":items,
        }))
    }

    pub(crate) async fn reconcile_coordinator_recoveries(
        &self,
        limit: u32,
    ) -> Result<u64, ApplicationError> {
        let rows = sqlx::query(
            "SELECT recovery.id,recovery.organization_id,recovery.policy_kind,
                    recovery.policy_id,recovery.policy_version_id,recovery.epoch,
                    recovery.policy_generation,recovery.recovery_generation,
                    recovery.authorized_allowance_nanos::text AS allowance,
                    recovery.cumulative_epoch_allowance_nanos::text AS cumulative_allowance,
                    version.limit_cost_nanos::text AS budget_limit,
                    version.recovery_epoch_cap_nanos::text AS epoch_cap,
                    version.mode,version.allowance_policy
             FROM coordinator_recoveries recovery
             JOIN coordinator_recovery_installations installation
               ON installation.recovery_id=recovery.id
             JOIN budget_policy_versions version ON version.id=recovery.policy_version_id
             WHERE installation.status IN ('pending','failed')
               AND (installation.last_attempt_at IS NULL
                    OR installation.last_attempt_at <= now()-interval '5 seconds')
             ORDER BY recovery.created_at,recovery.id LIMIT $1",
        )
        .bind(i64::from(limit.clamp(1, 100)))
        .fetch_all(self.store.pool())
        .await?;
        let mut installed = 0_u64;
        for row in rows {
            let plan = recovery_plan_from_row(&row)?;
            if self.install_coordinator_recovery(&plan).await {
                installed = installed.checked_add(1).ok_or(ApplicationError::Internal)?;
            }
        }
        Ok(installed)
    }

    async fn install_coordinator_recovery(&self, plan: &RecoveryPlan) -> bool {
        let result = if let Some(coordinator) = &self.coordinator {
            coordinator
                .install_coordinator_recovery(&plan.install)
                .await
        } else {
            Err(crate::adapters::coordinator::CoordinatorError::PoolUnavailable)
        };
        let installed = result.is_ok();
        let (status, installed_at, safe_error) = match result {
            Ok(()) => ("installed", Some(Utc::now()), None),
            Err(error) => {
                tracing::warn!(recovery_id=%plan.install.recovery_id, %error, "coordinator recovery installation remains pending");
                (
                    "failed",
                    None,
                    Some(json!({"class":"coordinator_installation_failed"})),
                )
            }
        };
        if let Err(error) = sqlx::query(
            "UPDATE coordinator_recovery_installations
             SET status=$2,attempt_count=attempt_count+1,last_attempt_at=now(),
                 installed_at=$3,safe_error=$4,updated_at=now()
             WHERE recovery_id=$1 AND status IN ('pending','failed')",
        )
        .bind(plan.install.recovery_id)
        .bind(status)
        .bind(installed_at)
        .bind(safe_error)
        .execute(self.store.pool())
        .await
        {
            tracing::error!(recovery_id=%plan.install.recovery_id, %error, "failed to persist coordinator recovery installation status");
            return false;
        }
        installed
    }

    pub async fn reconcile_policy_activations_now(
        &self,
        identity: &RequestIdentity,
    ) -> Result<Value, ApplicationError> {
        self.authorize_operations_command(identity)?;
        let reconciled = self.reconcile_policy_activations().await?;
        let details = json!({"reconciled":reconciled});
        self.audit_operations_command(
            identity,
            "policy_activation",
            "system.operations.coordination.activations.reconcile",
            vec!["activation_state".to_owned()],
            details.clone(),
        )
        .await?;
        Ok(details)
    }

    pub async fn reconcile_upstream_credentials(
        &self,
        identity: &RequestIdentity,
    ) -> Result<Value, ApplicationError> {
        self.authorize_operations_command(identity)?;
        let login_credentials_changed = self.reconcile_codex_login_sessions(100).await?;
        let expired_refresh_credentials_changed =
            self.reconcile_expired_codex_refresh_leases(100).await?;
        let due_refreshes_processed = self.refresh_due_codex_credentials(10).await?;
        if login_credentials_changed > 0
            || expired_refresh_credentials_changed > 0
            || due_refreshes_processed > 0
        {
            self.publish_committed_runtime(
                &identity.request_id,
                "system.operations.upstream_credentials.reconcile",
            )
            .await;
        }
        let details = json!({
            "login_credentials_changed":login_credentials_changed,
            "expired_refresh_credentials_changed":expired_refresh_credentials_changed,
            "due_refreshes_processed":due_refreshes_processed,
        });
        self.audit_operations_command(
            identity,
            "upstream_credential_controller",
            "system.operations.upstream_credentials.reconcile",
            vec!["controller_state".to_owned()],
            details.clone(),
        )
        .await?;
        Ok(details)
    }

    pub async fn cleanup_state_origins(
        &self,
        identity: &RequestIdentity,
        input: &CleanupStateOrigins,
    ) -> Result<Value, ApplicationError> {
        self.authorize_operations_command(identity)?;
        let cursor = match input.cursor.as_deref() {
            None | Some("") => 0,
            Some(value) if value.len() <= 20 && value.bytes().all(|byte| byte.is_ascii_digit()) => {
                value.parse::<u64>().map_err(|_| {
                    ApplicationError::Validation("state-origin cursor is invalid".to_owned())
                })?
            }
            Some(_) => {
                return Err(ApplicationError::Validation(
                    "state-origin cursor is invalid".to_owned(),
                ));
            }
        };
        let limit = input.limit.unwrap_or(100);
        if !(1..=500).contains(&limit) {
            return Err(ApplicationError::Validation(
                "state-origin cleanup limit must be between 1 and 500".to_owned(),
            ));
        }
        let exists =
            sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1)")
                .bind(input.organization_id.as_uuid())
                .fetch_one(self.store.pool())
                .await?;
        if !exists {
            return Err(ApplicationError::NotFound);
        }
        let coordinator = self
            .coordinator
            .as_ref()
            .ok_or(ApplicationError::DependencyUnavailable)?;
        let page = coordinator
            .cleanup_state_origins(input.organization_id, cursor, limit)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "state-origin cleanup failed");
                ApplicationError::DependencyUnavailable
            })?;
        let details = json!({
            "organization_id":input.organization_id,
            "deleted":page.deleted,
            "next_cursor":page.next_cursor,
        });
        self.audit_operations_command(
            identity,
            "state_origin_binding",
            "system.operations.state_origins.cleanup",
            vec!["bindings".to_owned()],
            details.clone(),
        )
        .await?;
        Ok(details)
    }

    pub async fn probe_targets_now(
        &self,
        identity: &RequestIdentity,
        input: &ProbeTargets,
    ) -> Result<Value, ApplicationError> {
        self.authorize_operations_command(identity)?;
        if input.target_ids.is_empty() || input.target_ids.len() > 64 {
            return Err(ApplicationError::Validation(
                "target_ids must contain between 1 and 64 IDs".to_owned(),
            ));
        }
        let unique = input
            .target_ids
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>();
        if unique.len() != input.target_ids.len() {
            return Err(ApplicationError::Validation(
                "target_ids must not contain duplicates".to_owned(),
            ));
        }
        let target_ids = input
            .target_ids
            .iter()
            .copied()
            .map(TargetId::from_uuid)
            .collect::<Vec<_>>();
        let worker = self
            .target_probes
            .as_ref()
            .ok_or(ApplicationError::DependencyUnavailable)?;
        let run = worker.probe_now(&target_ids).await;
        let details = json!({
            "requested":run.requested,
            "eligible":run.eligible,
            "completed":run.completed,
        });
        self.audit_operations_command(
            identity,
            "target_health_probe",
            "system.operations.target_health.probe",
            vec!["observations".to_owned()],
            details.clone(),
        )
        .await?;
        Ok(details)
    }

    pub async fn flush_usage_pipeline(
        &self,
        identity: &RequestIdentity,
    ) -> Result<Value, ApplicationError> {
        self.authorize_operations_command(identity)?;
        let (before, after) = self.usage.flush_now().await;
        let details = json!({
            "before":usage_status_json(&before),
            "after":usage_status_json(&after),
            "complete":after.active_logical_keys == 0
                && after.active_attempt_keys == 0
                && after.pending_batches == 0,
        });
        self.audit_operations_command(
            identity,
            "usage_aggregate_pipeline",
            "system.operations.usage_pipeline.flush",
            vec!["aggregate_batches".to_owned()],
            details.clone(),
        )
        .await?;
        Ok(details)
    }

    pub async fn reconcile_codex_refresh_leases(
        &self,
        identity: &RequestIdentity,
    ) -> Result<Value, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Write, ManagementScope::Operations],
            AuthorizationTarget::Operations { write: true },
        )?;
        let changed = self.reconcile_expired_codex_refresh_leases(100).await?;
        if changed > 0 {
            self.publish_committed_runtime(
                &identity.request_id,
                "system.operations.codex_refresh_leases.reconcile",
            )
            .await;
        }
        let transaction = self.store.begin().await?;
        self.store
            .commit_command(
                transaction,
                &AuditRecord {
                    actor: Some(Actor::from(&identity.principal)),
                    authentication_evidence: json!({"method":identity.principal.authentication_method}),
                    organization_id: None,
                    target_resource_kind: "codex_refresh_lease".to_owned(),
                    target_resource_id: None,
                    operation_id: "system.operations.codex_refresh_leases.reconcile".to_owned(),
                    outcome: "accepted",
                    request_id: identity.request_id.clone(),
                    changed_fields: vec!["expired_leases".to_owned()],
                    safe_details: json!({"changed_credentials":changed}),
                },
                None,
            )
            .await?;
        Ok(json!({"changed_credentials":changed}))
    }

    fn authorize_operations_command(
        &self,
        identity: &RequestIdentity,
    ) -> Result<(), ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Write, ManagementScope::Operations],
            AuthorizationTarget::Operations { write: true },
        )
    }

    async fn audit_operations_command(
        &self,
        identity: &RequestIdentity,
        target_resource_kind: &str,
        operation_id: &str,
        changed_fields: Vec<String>,
        safe_details: Value,
    ) -> Result<(), ApplicationError> {
        let transaction = self.store.begin().await?;
        self.store
            .commit_command(
                transaction,
                &AuditRecord {
                    actor: Some(Actor::from(&identity.principal)),
                    authentication_evidence: json!({"method":identity.principal.authentication_method}),
                    organization_id: None,
                    target_resource_kind: target_resource_kind.to_owned(),
                    target_resource_id: None,
                    operation_id: operation_id.to_owned(),
                    outcome: "accepted",
                    request_id: identity.request_id.clone(),
                    changed_fields,
                    safe_details,
                },
                None,
            )
            .await?;
        Ok(())
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
        let now = Utc::now();
        let runtime_age_seconds = now
            .signed_duration_since(status.confirmed_at)
            .num_seconds()
            .max(0);
        let generation = self.runtime.capture();
        let pending_tightening_due = generation
            .snapshot
            .organizations
            .values()
            .filter_map(|organization| organization.pending_tightening_deadline)
            .any(|deadline| deadline <= now);
        let ready = status.applied_revision >= database_revision
            && runtime_age_seconds
                <= i64::try_from(self.config.max_security_snapshot_age.as_secs())
                    .unwrap_or(i64::MAX)
            && !pending_tightening_due;
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

fn usage_status_json(status: &UsageStatus) -> Value {
    json!({
        "active_logical_keys":status.active_logical_keys,
        "active_attempt_keys":status.active_attempt_keys,
        "pending_batches":status.pending_batches,
        "lost_logical_facts":status.lost_logical_facts,
        "lost_attempt_facts":status.lost_attempt_facts,
        "last_flush_error":status.last_flush_error,
    })
}

#[derive(Debug)]
struct RecoveryPolicyAuthority {
    version_id: Uuid,
    epoch: String,
    policy_generation: u64,
    prior_recovery_generation: u64,
    prior_cumulative_allowance_nanos: u128,
    limit_cost_nanos: u128,
    incident_cap_nanos: u128,
    epoch_cap_nanos: u128,
    allowance_policy: BudgetAllowancePolicy,
    recovery_policy: BudgetRecoveryPolicy,
}

async fn load_recovery_policy(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: OrganizationId,
    kind: RecoveryPolicyKind,
    policy_id: Uuid,
) -> Result<RecoveryPolicyAuthority, ApplicationError> {
    let row =
        match kind {
            RecoveryPolicyKind::GatewayKeyBudget => sqlx::query(
                "SELECT policy.status,version.id AS version_id,version.epoch,version.generation,
                    version.mode,version.limit_cost_nanos::text AS budget_limit,
                    LEAST(version.recovery_incident_cap_nanos,
                          ceilings.max_recovery_incident_cap_nanos)::text AS incident_cap,
                    LEAST(version.recovery_epoch_cap_nanos,
                          ceilings.max_recovery_epoch_cap_nanos)::text AS epoch_cap,
                    version.allowance_policy,version.recovery_policy,
                    COALESCE((SELECT MAX(recovery.recovery_generation)
                              FROM coordinator_recoveries recovery
                              WHERE recovery.policy_kind='gateway_key_budget'
                                AND recovery.policy_id=policy.id
                                AND recovery.epoch=version.epoch),0) AS prior_recovery_generation,
                    COALESCE((SELECT MAX(recovery.cumulative_epoch_allowance_nanos)
                              FROM coordinator_recoveries recovery
                              WHERE recovery.policy_kind='gateway_key_budget'
                                AND recovery.policy_id=policy.id
                                AND recovery.epoch=version.epoch),0)::text AS prior_cumulative
             FROM gateway_key_budget_policies policy
             JOIN budget_policy_versions version
               ON version.id=policy.active_version_id
              AND version.gateway_key_budget_policy_id=policy.id
             CROSS JOIN gateway_policy_ceilings ceilings
             WHERE policy.id=$1 AND policy.organization_id=$2 AND ceilings.singleton=true
             FOR UPDATE OF policy",
            )
            .bind(policy_id)
            .bind(organization_id.as_uuid())
            .fetch_optional(&mut **transaction)
            .await?,
            RecoveryPolicyKind::OrganizationOriginBudget => sqlx::query(
                "SELECT policy.status,version.id AS version_id,version.epoch,version.generation,
                    version.mode,version.limit_cost_nanos::text AS budget_limit,
                    LEAST(version.recovery_incident_cap_nanos,
                          ceilings.max_recovery_incident_cap_nanos)::text AS incident_cap,
                    LEAST(version.recovery_epoch_cap_nanos,
                          ceilings.max_recovery_epoch_cap_nanos)::text AS epoch_cap,
                    version.allowance_policy,version.recovery_policy,
                    COALESCE((SELECT MAX(recovery.recovery_generation)
                              FROM coordinator_recoveries recovery
                              WHERE recovery.policy_kind='organization_origin_budget'
                                AND recovery.policy_id=policy.id
                                AND recovery.epoch=version.epoch),0) AS prior_recovery_generation,
                    COALESCE((SELECT MAX(recovery.cumulative_epoch_allowance_nanos)
                              FROM coordinator_recoveries recovery
                              WHERE recovery.policy_kind='organization_origin_budget'
                                AND recovery.policy_id=policy.id
                                AND recovery.epoch=version.epoch),0)::text AS prior_cumulative
             FROM organization_origin_budget_policies policy
             JOIN budget_policy_versions version
               ON version.id=policy.active_version_id
              AND version.organization_origin_budget_policy_id=policy.id
             CROSS JOIN gateway_policy_ceilings ceilings
             WHERE policy.id=$1 AND policy.organization_id=$2 AND ceilings.singleton=true
             FOR UPDATE OF policy",
            )
            .bind(policy_id)
            .bind(organization_id.as_uuid())
            .fetch_optional(&mut **transaction)
            .await?,
        }
        .ok_or(ApplicationError::NotFound)?;
    if row.try_get::<String, _>("status")? != "active"
        || row.try_get::<String, _>("mode")? != "enforce"
    {
        return Err(ApplicationError::Conflict(
            "coordinator recovery requires an active enforcing budget policy".to_owned(),
        ));
    }
    Ok(RecoveryPolicyAuthority {
        version_id: row.try_get("version_id")?,
        epoch: row.try_get("epoch")?,
        policy_generation: positive_recovery_generation(row.try_get("generation")?)?,
        prior_recovery_generation: nonnegative_recovery_generation(
            row.try_get("prior_recovery_generation")?,
        )?,
        prior_cumulative_allowance_nanos: parse_persisted_nanos(row.try_get("prior_cumulative")?)?,
        limit_cost_nanos: parse_persisted_nanos(row.try_get("budget_limit")?)?,
        incident_cap_nanos: parse_persisted_nanos(row.try_get("incident_cap")?)?,
        epoch_cap_nanos: parse_persisted_nanos(row.try_get("epoch_cap")?)?,
        allowance_policy: serde_json::from_value(row.try_get("allowance_policy")?)
            .map_err(|_| ApplicationError::Internal)?,
        recovery_policy: serde_json::from_value(row.try_get("recovery_policy")?)
            .map_err(|_| ApplicationError::Internal)?,
    })
}

fn recovery_plan_from_row(row: &sqlx::postgres::PgRow) -> Result<RecoveryPlan, ApplicationError> {
    let kind = match row.try_get::<String, _>("policy_kind")?.as_str() {
        "gateway_key_budget" => PolicyKind::GatewayKeyBudget,
        "organization_origin_budget" => PolicyKind::OrganizationOriginBudget,
        _ => return Err(ApplicationError::Internal),
    };
    if row.try_get::<String, _>("mode")? != "enforce" {
        return Err(ApplicationError::Internal);
    }
    let allowance_policy: BudgetAllowancePolicy =
        serde_json::from_value(row.try_get("allowance_policy")?)
            .map_err(|_| ApplicationError::Internal)?;
    let version_id = row.try_get("policy_version_id")?;
    let limit_cost_nanos = parse_persisted_nanos(row.try_get("budget_limit")?)?;
    Ok(RecoveryPlan {
        install: CoordinatorRecoveryInstall {
            recovery_id: row.try_get("id")?,
            organization_id: OrganizationId::from_uuid(row.try_get("organization_id")?),
            kind,
            policy_id: row.try_get("policy_id")?,
            version_id,
            epoch: row.try_get("epoch")?,
            policy_generation: positive_recovery_generation(row.try_get("policy_generation")?)?,
            recovery_generation: positive_recovery_generation(row.try_get("recovery_generation")?)?,
            authorized_allowance_nanos: parse_persisted_nanos(row.try_get("allowance")?)?,
            limit_cost_nanos,
            config: PolicyCoordinatorConfig::Budget {
                version_id,
                mode: "enforce".to_owned(),
                limit_cost_nanos: limit_cost_nanos.to_string(),
                max_slice_nanos: allowance_policy.max_slice_nanos.to_string(),
                grant_seconds: allowance_policy.grant_seconds,
            },
        },
        cumulative_epoch_allowance_nanos: parse_persisted_nanos(
            row.try_get("cumulative_allowance")?,
        )?,
        recovery_epoch_cap_nanos: parse_persisted_nanos(row.try_get("epoch_cap")?)?,
    })
}

fn recovery_plan_json(plan: &RecoveryPlan, installed: bool) -> Value {
    json!({
        "recovery_id":plan.install.recovery_id,
        "organization_id":plan.install.organization_id,
        "policy_kind":plan.install.kind.as_str(),
        "policy_id":plan.install.policy_id,
        "policy_version_id":plan.install.version_id,
        "epoch":plan.install.epoch,
        "policy_generation":plan.install.policy_generation,
        "recovery_generation":plan.install.recovery_generation,
        "authorized_allowance_nanos":plan.install.authorized_allowance_nanos.to_string(),
        "cumulative_epoch_allowance_nanos":plan.cumulative_epoch_allowance_nanos.to_string(),
        "recovery_epoch_cap_nanos":plan.recovery_epoch_cap_nanos.to_string(),
        "installation_status":if installed { "installed" } else { "pending" },
    })
}

fn validate_recovery_request(input: &CreateCoordinatorRecoveries) -> Result<(), ApplicationError> {
    let incident = input.incident_reference.trim();
    if incident.is_empty()
        || incident.chars().count() > 512
        || incident.chars().any(char::is_control)
    {
        return Err(ApplicationError::Validation(
            "incident_reference must contain between 1 and 512 safe characters".to_owned(),
        ));
    }
    let reason = input.reason.trim();
    if reason.is_empty() || reason.chars().count() > 2048 || reason.chars().any(char::is_control) {
        return Err(ApplicationError::Validation(
            "reason must contain between 1 and 2048 safe characters".to_owned(),
        ));
    }
    if !input.safe_evidence.is_object() {
        return Err(ApplicationError::Validation(
            "safe_evidence must be an object".to_owned(),
        ));
    }
    if input.allocations.is_empty() || input.allocations.len() > 64 {
        return Err(ApplicationError::Validation(
            "allocations must contain between 1 and 64 policies".to_owned(),
        ));
    }
    Ok(())
}

fn parse_recovery_nanos(value: &str, field: &str) -> Result<u128, ApplicationError> {
    if value.is_empty() || value.len() > 38 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ApplicationError::Validation(format!(
            "{field} must be a non-negative decimal with at most 38 digits"
        )));
    }
    value.parse().map_err(|_| {
        ApplicationError::Validation(format!("{field} exceeds the supported numeric range"))
    })
}

fn parse_persisted_nanos(value: String) -> Result<u128, ApplicationError> {
    value.parse().map_err(|_| ApplicationError::Internal)
}

fn positive_recovery_generation(value: i64) -> Result<u64, ApplicationError> {
    if value <= 0 {
        return Err(ApplicationError::Internal);
    }
    u64::try_from(value).map_err(|_| ApplicationError::Internal)
}

fn nonnegative_recovery_generation(value: i64) -> Result<u64, ApplicationError> {
    u64::try_from(value).map_err(|_| ApplicationError::Internal)
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
