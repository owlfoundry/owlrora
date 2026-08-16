use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Row as _, Transaction, postgres::PgPoolOptions};
use thiserror::Error;
use uuid::Uuid;

use crate::domain::{Actor, OrganizationId};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("src/adapters/postgres/migrations");

#[derive(Clone)]
pub struct PgStore {
    pool: PgPool,
    installation_id: Uuid,
}

impl std::fmt::Debug for PgStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PgStore")
            .field("installation_id", &self.installation_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database operation failed")]
    Database(#[from] sqlx::Error),
    #[error("database migration failed")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("database invariant failed: {0}")]
    Invariant(&'static str),
}

#[derive(Clone, Debug)]
pub struct AuditRecord {
    pub actor: Option<Actor>,
    pub authentication_evidence: Value,
    pub organization_id: Option<OrganizationId>,
    pub target_resource_kind: String,
    pub target_resource_id: Option<String>,
    pub operation_id: String,
    pub outcome: &'static str,
    pub request_id: String,
    pub changed_fields: Vec<String>,
    pub safe_details: Value,
}

#[derive(Clone, Debug)]
pub struct RuntimeEvent {
    pub event_kind: String,
    pub affected_scope: Value,
    pub security_tightening: bool,
}

impl PgStore {
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(10))
            .connect(database_url)
            .await?;
        MIGRATOR.run(&pool).await?;
        let installation_id = initialize_installation(&pool).await?;
        initialize_deployment_management_key_policy(&pool).await?;
        Ok(Self {
            pool,
            installation_id,
        })
    }

    #[must_use]
    pub const fn installation_id(&self) -> Uuid {
        self.installation_id
    }

    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn begin(&self) -> Result<Transaction<'_, Postgres>, StoreError> {
        Ok(self.pool.begin().await?)
    }

    pub async fn commit_command(
        &self,
        mut transaction: Transaction<'_, Postgres>,
        audit: &AuditRecord,
        event: Option<&RuntimeEvent>,
    ) -> Result<Option<i64>, StoreError> {
        insert_audit(&mut transaction, audit).await?;
        let revision = if let Some(event) = event {
            Some(allocate_runtime_revision(&mut transaction, event).await?)
        } else {
            None
        };
        transaction.commit().await?;
        Ok(revision)
    }

    pub async fn current_revision(&self) -> Result<i64, StoreError> {
        let revision = sqlx::query_scalar::<_, i64>(
            "SELECT current_revision FROM runtime_revision_counter WHERE singleton = true",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(revision)
    }

    pub async fn database_time(&self) -> Result<DateTime<Utc>, StoreError> {
        Ok(sqlx::query_scalar("SELECT now()")
            .fetch_one(&self.pool)
            .await?)
    }
}

async fn initialize_installation(pool: &PgPool) -> Result<Uuid, StoreError> {
    let mut transaction = pool.begin().await?;
    sqlx::query("LOCK TABLE system_installation IN EXCLUSIVE MODE")
        .execute(&mut *transaction)
        .await?;
    let existing = sqlx::query_scalar::<_, Uuid>(
        "SELECT installation_id FROM system_installation WHERE singleton = true",
    )
    .fetch_optional(&mut *transaction)
    .await?;
    let installation_id = if let Some(existing) = existing {
        existing
    } else {
        let installation_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO system_installation(singleton, installation_id) VALUES (true, $1)",
        )
        .bind(installation_id)
        .execute(&mut *transaction)
        .await?;
        installation_id
    };
    transaction.commit().await?;
    Ok(installation_id)
}

async fn initialize_deployment_management_key_policy(pool: &PgPool) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO deployment_management_key_policy(singleton, policy, etag_token)
         VALUES (true, $1, $2) ON CONFLICT (singleton) DO NOTHING",
    )
    .bind(serde_json::json!({
        "management": {
            "allowed_scopes": ["management:read", "management:write", "management:secrets", "management:operations", "management:authority"],
            "allowed_capabilities": [
                "system_administration", "manage_identity", "manage_system_keys",
                "manage_system_organizations", "manage_system_users", "manage_administrators",
                "manage_gateway_catalog", "read_gateway_keys", "create_gateway_keys",
                "manage_gateway_keys", "manage_byok", "configure_routes",
                "configure_budgets", "read_usage", "read_operations", "recover_operations", "read_organization",
                "update_organization", "read_members", "manage_members", "manage_owners",
                "read_management_keys", "create_management_keys", "manage_management_keys",
                "update_api_key_policy", "read_audit"
            ],
            "max_active_keys": 1000,
            "max_expiry_days": 365,
            "max_overlap_seconds": 3600
        }
    }))
    .bind(Uuid::now_v7())
    .execute(pool)
    .await?;
    Ok(())
}

async fn insert_audit(
    transaction: &mut Transaction<'_, Postgres>,
    audit: &AuditRecord,
) -> Result<(), StoreError> {
    let actor = audit
        .actor
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| StoreError::Invariant("audit actor serialization"))?;
    sqlx::query(
        "INSERT INTO audit_entries(
            id, actor, authentication_evidence, organization_id, target_resource_kind,
            target_resource_id, operation_id, outcome, request_id, changed_fields, safe_details
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(Uuid::now_v7())
    .bind(actor)
    .bind(&audit.authentication_evidence)
    .bind(audit.organization_id.map(OrganizationId::as_uuid))
    .bind(&audit.target_resource_kind)
    .bind(&audit.target_resource_id)
    .bind(&audit.operation_id)
    .bind(audit.outcome)
    .bind(&audit.request_id)
    .bind(
        serde_json::to_value(&audit.changed_fields)
            .map_err(|_| StoreError::Invariant("changed field serialization"))?,
    )
    .bind(&audit.safe_details)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn allocate_runtime_revision(
    transaction: &mut Transaction<'_, Postgres>,
    event: &RuntimeEvent,
) -> Result<i64, StoreError> {
    let row = sqlx::query(
        "SELECT current_revision FROM runtime_revision_counter
         WHERE singleton = true FOR UPDATE",
    )
    .fetch_one(&mut **transaction)
    .await?;
    let current: i64 = row.try_get("current_revision")?;
    let revision = current
        .checked_add(1)
        .ok_or(StoreError::Invariant("runtime revision overflow"))?;
    sqlx::query("UPDATE runtime_revision_counter SET current_revision = $1 WHERE singleton = true")
        .bind(revision)
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        "INSERT INTO configuration_journal(
            revision, event_kind, affected_scope, security_classification
         ) VALUES ($1,$2,$3,$4)",
    )
    .bind(revision)
    .bind(&event.event_kind)
    .bind(&event.affected_scope)
    .bind(if event.security_tightening {
        "tightening"
    } else {
        "ordinary"
    })
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "INSERT INTO transactional_outbox(id, revision, event_kind, payload)
         VALUES ($1,$2,'runtime_revision_committed',$3)",
    )
    .bind(Uuid::now_v7())
    .bind(revision)
    .bind(serde_json::json!({ "revision": revision }))
    .execute(&mut **transaction)
    .await?;
    Ok(revision)
}

#[cfg(test)]
pub mod test_support {
    use super::*;

    static SHARED_DATABASE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    pub async fn shared_database_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
        SHARED_DATABASE_TEST_LOCK.lock().await
    }

    pub async fn connect_from_environment() -> Option<PgStore> {
        let url = std::env::var("OWLRORA_TEST_DATABASE_URL").ok()?;
        Some(
            PgStore::connect(&url, 4)
                .await
                .expect("test database should connect"),
        )
    }

    pub fn valid_reliability_components() -> [Value; 8] {
        [
            serde_json::json!({
                "max_total_attempts": 3,
                "max_same_target_retries": 1,
                "max_distinct_failover_targets": 2
            }),
            serde_json::json!({
                "overall_timeout_ms": 120_000,
                "connect_timeout_ms": 10_000,
                "response_header_timeout_ms": 60_000,
                "body_timeout_ms": 120_000,
                "stream_idle_timeout_ms": 60_000,
                "pre_commit_classification_timeout_ms": 5_000
            }),
            serde_json::json!({
                "conditions": [
                    "connect_failure", "connect_timeout", "provider_overloaded",
                    "provider_rate_limited", "provider_5xx"
                ],
                "initial_backoff_ms": 100,
                "max_backoff_ms": 5_000,
                "jitter_ratio_millis": 200,
                "honor_retry_after": true
            }),
            serde_json::json!({"enabled": true, "require_replay_safe_request": true}),
            serde_json::json!({
                "stream_precommit_buffer_bytes": 262_144,
                "stream_precommit_buffer_events": 128
            }),
            serde_json::json!({
                "shared_summary_ttl_ms": 30_000,
                "stale_after_ms": 60_000
            }),
            serde_json::json!({
                "failure_threshold": 5,
                "success_threshold": 2,
                "open_duration_ms": 30_000,
                "max_open_duration_ms": 300_000,
                "half_open_max_requests": 1,
                "recovery_duration_ms": 60_000
            }),
            serde_json::json!({
                "enabled": false,
                "interval_ms": 30_000,
                "timeout_ms": 5_000,
                "path": "/health"
            }),
        ]
    }

    #[tokio::test]
    async fn migrations_create_one_stable_installation() {
        let Some(first) = connect_from_environment().await else {
            return;
        };
        let url = std::env::var("OWLRORA_TEST_DATABASE_URL").unwrap();
        let second = PgStore::connect(&url, 4).await.unwrap();
        assert_eq!(first.installation_id(), second.installation_id());
        assert!(first.current_revision().await.unwrap() >= 0);
        let policy_exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM deployment_management_key_policy WHERE singleton=true)",
        )
        .fetch_one(first.pool())
        .await
        .unwrap();
        assert!(policy_exists);
    }

    #[tokio::test]
    async fn module_ii_schema_backfills_and_creates_origin_policies() {
        let Some(store) = connect_from_environment().await else {
            return;
        };
        let organization_id = Uuid::now_v7();
        let mut transaction = store.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO organizations(
                id, kind, status, name, created_by_principal, etag_token
             ) VALUES ($1, 'ordinary', 'suspended', $2, '{}'::jsonb, $3)",
        )
        .bind(organization_id)
        .bind(format!("schema-test-{organization_id}"))
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        let policies = sqlx::query(
            "SELECT origin, status, desired_version_id, active_version_id
             FROM organization_origin_budget_policies
             WHERE organization_id = $1 ORDER BY origin",
        )
        .bind(organization_id)
        .fetch_all(&mut *transaction)
        .await
        .unwrap();
        assert_eq!(policies.len(), 2);
        for row in policies {
            assert_eq!(row.try_get::<String, _>("status").unwrap(), "suspended");
            assert!(
                row.try_get::<Option<Uuid>, _>("desired_version_id")
                    .unwrap()
                    .is_none()
            );
            assert!(
                row.try_get::<Option<Uuid>, _>("active_version_id")
                    .unwrap()
                    .is_none()
            );
        }
        transaction.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn module_ii_schema_rejects_cross_scope_credentials_and_empty_active_keys() {
        let Some(store) = connect_from_environment().await else {
            return;
        };
        let mut transaction = store.begin().await.unwrap();
        let organization_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO organizations(
                id, kind, status, name, created_by_principal, etag_token
             ) VALUES ($1, 'ordinary', 'suspended', $2, '{}'::jsonb, $3)",
        )
        .bind(organization_id)
        .bind(format!("constraint-test-{organization_id}"))
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();

        sqlx::query("SAVEPOINT invalid_credential")
            .execute(&mut *transaction)
            .await
            .unwrap();
        let credential_error = sqlx::query(
            "INSERT INTO upstream_credentials(
                id, resource_scope_kind, organization_id, name, credential_kind,
                secret_source_kind, injection_kind, sharing_policy,
                administrative_status, authentication_status,
                created_by_principal, etag_token
             ) VALUES (
                $1, 'organization', $2, 'invalid-env-source', 'static_api_key',
                'environment_reference', 'bearer', 'exclusive', 'active', 'unvalidated',
                '{}'::jsonb, $3
             )",
        )
        .bind(Uuid::now_v7())
        .bind(organization_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap_err();
        assert!(credential_error.as_database_error().is_some());
        sqlx::query("ROLLBACK TO SAVEPOINT invalid_credential")
            .execute(&mut *transaction)
            .await
            .unwrap();

        sqlx::query("SET CONSTRAINTS ALL DEFERRED")
            .execute(&mut *transaction)
            .await
            .unwrap();
        let key_id = Uuid::now_v7();
        let budget_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO gateway_api_keys(
                id, organization_id, issuance_policy_class, created_by_principal,
                name, key_prefix, lookup_id, scopes, budget_policy_id, status, etag_token
             ) VALUES (
                $1, $2, 'standard', '{}'::jsonb, 'empty-key', 'owlrora_llm_v1',
                'AAAAAAAAAAAAAAAAAAAAAA', '[\"llm:invoke\"]'::jsonb, $3, 'active', $4
             )",
        )
        .bind(key_id)
        .bind(organization_id)
        .bind(budget_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO gateway_key_budget_policies(
                id, organization_id, gateway_api_key_id, status, etag_token
             ) VALUES ($1, $2, $3, 'suspended', $4)",
        )
        .bind(budget_id)
        .bind(organization_id)
        .bind(key_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        let key_error = sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
            .execute(&mut *transaction)
            .await
            .unwrap_err();
        assert!(key_error.as_database_error().is_some());
        drop(transaction);
    }

    async fn insert_suspended_organization(
        transaction: &mut Transaction<'_, Postgres>,
        label: &str,
    ) -> Uuid {
        let organization_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO organizations(
                id, kind, status, name, created_by_principal, etag_token
             ) VALUES ($1, 'ordinary', 'suspended', $2, '{}'::jsonb, $3)",
        )
        .bind(organization_id)
        .bind(format!("{label}-{organization_id}"))
        .bind(Uuid::now_v7())
        .execute(&mut **transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO organization_api_key_policies(organization_id,policy,etag_token)
             VALUES ($1,$2,$3)",
        )
        .bind(organization_id)
        .bind(crate::application::default_organization_api_key_policy())
        .bind(Uuid::now_v7())
        .execute(&mut **transaction)
        .await
        .unwrap();
        organization_id
    }

    #[tokio::test]
    async fn module_ii_schema_rejects_cross_key_policy_reference() {
        let Some(store) = connect_from_environment().await else {
            return;
        };
        let mut transaction = store.begin().await.unwrap();
        sqlx::query("SET CONSTRAINTS ALL DEFERRED")
            .execute(&mut *transaction)
            .await
            .unwrap();
        let organization_id = insert_suspended_organization(&mut transaction, "cross-key").await;
        let key_a = Uuid::now_v7();
        let key_b = Uuid::now_v7();
        let budget_a = Uuid::now_v7();
        let budget_b = Uuid::now_v7();
        for (key, budget, lookup, name) in [
            (key_a, budget_b, "BBBBBBBBBBBBBBBBBBBBBB", "key-a"),
            (key_b, budget_b, "CCCCCCCCCCCCCCCCCCCCCC", "key-b"),
        ] {
            sqlx::query(
                "INSERT INTO gateway_api_keys(
                    id, organization_id, issuance_policy_class, created_by_principal,
                    name, key_prefix, lookup_id, scopes, budget_policy_id, status, etag_token
                 ) VALUES (
                    $1,$2,'standard','{}'::jsonb,$3,'owlrora_llm_v1',$4,
                    '[\"llm:invoke\"]'::jsonb,$5,'disabled',$6
                 )",
            )
            .bind(key)
            .bind(organization_id)
            .bind(name)
            .bind(lookup)
            .bind(budget)
            .bind(Uuid::now_v7())
            .execute(&mut *transaction)
            .await
            .unwrap();
        }
        for (budget, key) in [(budget_a, key_a), (budget_b, key_b)] {
            sqlx::query(
                "INSERT INTO gateway_key_budget_policies(
                    id, organization_id, gateway_api_key_id, status, etag_token
                 ) VALUES ($1,$2,$3,'suspended',$4)",
            )
            .bind(budget)
            .bind(organization_id)
            .bind(key)
            .bind(Uuid::now_v7())
            .execute(&mut *transaction)
            .await
            .unwrap();
        }
        let error = sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
            .execute(&mut *transaction)
            .await
            .unwrap_err();
        assert!(error.as_database_error().is_some());
        drop(transaction);
    }

    #[tokio::test]
    async fn module_ii_schema_rejects_protected_secret_owner_substitution() {
        let Some(store) = connect_from_environment().await else {
            return;
        };
        let mut transaction = store.begin().await.unwrap();
        sqlx::query("SET CONSTRAINTS ALL DEFERRED")
            .execute(&mut *transaction)
            .await
            .unwrap();
        let organization_id = insert_suspended_organization(&mut transaction, "secret-owner").await;
        let credential_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO upstream_credentials(
                id, resource_scope_kind, organization_id, name, credential_kind,
                secret_source_kind, injection_kind, sharing_policy,
                administrative_status, authentication_status, created_by_principal, etag_token
             ) VALUES (
                $1,'organization',$2,'credential','static_api_key','encrypted_database',
                'bearer','exclusive','active','unvalidated','{}'::jsonb,$3
             )",
        )
        .bind(credential_id)
        .bind(organization_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        let protected_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO protected_secret_versions(
                id, scope_kind, organization_id, owner_kind, owner_id, owner_generation,
                secret_version, field_purpose, custody_provider_id, provider_format_version,
                context_version, opaque_envelope
             ) VALUES (
                $1,'organization',$2,'upstream_credential',$3,1,1,
                'upstream_credential_material','software-xchacha20-poly1305',1,1,'\\x01'::bytea
             )",
        )
        .bind(protected_id)
        .bind(organization_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO upstream_credential_secret_versions(
                id, credential_id, version, credential_state_identity_version,
                protected_secret_version_id, safe_fingerprint, state
             ) VALUES ($1,$2,1,1,$3,decode(repeat('00',32),'hex'),'current')",
        )
        .bind(Uuid::now_v7())
        .bind(credential_id)
        .bind(protected_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
        let error = sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
            .execute(&mut *transaction)
            .await
            .unwrap_err();
        assert!(error.as_database_error().is_some());
        drop(transaction);
    }

    #[tokio::test]
    async fn module_ii_schema_rejects_immutable_credential_scope_update() {
        let Some(store) = connect_from_environment().await else {
            return;
        };
        let mut transaction = store.begin().await.unwrap();
        let organization_id = insert_suspended_organization(&mut transaction, "immutable").await;
        let credential_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO upstream_credentials(
                id, resource_scope_kind, name, credential_kind, secret_source_kind,
                injection_kind, sharing_policy, administrative_status, authentication_status,
                created_by_principal, etag_token
             ) VALUES (
                $1,'deployment','immutable-credential','static_api_key','encrypted_database',
                'bearer','exclusive','active','unvalidated','{}'::jsonb,$2
             )",
        )
        .bind(credential_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        let error = sqlx::query(
            "UPDATE upstream_credentials
             SET resource_scope_kind='organization', organization_id=$2 WHERE id=$1",
        )
        .bind(credential_id)
        .bind(organization_id)
        .execute(&mut *transaction)
        .await
        .unwrap_err();
        assert!(error.as_database_error().is_some());
        drop(transaction);
    }

    #[tokio::test]
    async fn module_ii_schema_allows_removed_route_owner_for_runtime_fail_closed() {
        let Some(store) = connect_from_environment().await else {
            return;
        };
        let mut transaction = store.begin().await.unwrap();
        sqlx::query("SET CONSTRAINTS ALL DEFERRED")
            .execute(&mut *transaction)
            .await
            .unwrap();
        let organization_id = insert_suspended_organization(&mut transaction, "owner-latch").await;
        let user_id = Uuid::now_v7();
        let membership_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO users(id,kind,status,display_name,created_by_principal,etag_token)
             VALUES ($1,'human','active','Owner','{}'::jsonb,$2)",
        )
        .bind(user_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO memberships(
                id,organization_id,user_id,role,status,created_by_principal,etag_token
             ) VALUES ($1,$2,$3,'owner','active','{}'::jsonb,$4)",
        )
        .bind(membership_id)
        .bind(organization_id)
        .bind(user_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        let reliability_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO reliability_policies(
                id,name,attempt_policy,deadline_policy,retry_policy,failover_policy,
                commitment_policy,health_policy,circuit_policy,probe_policy,status,
                created_by_principal,etag_token
             ) VALUES (
                $1,$2,'{}','{}','{}','{}','{}','{}','{}','{}','active','{}',$3
             )",
        )
        .bind(reliability_id)
        .bind(format!("reliability-{reliability_id}"))
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO model_routes(
                id,resource_scope_kind,organization_id,owner_user_id,owner_membership_id,
                model_key,ingress_protocol_family,required_base_capabilities,selection_policy,
                reliability_policy_id,request_policy,status,created_by_principal,etag_token
             ) VALUES (
                $1,'organization',$2,$3,$4,'model','openai_responses','[]','{}',$5,'{}',
                'draft','{}',$6
             )",
        )
        .bind(Uuid::now_v7())
        .bind(organization_id)
        .bind(user_id)
        .bind(membership_id)
        .bind(reliability_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::query("SET CONSTRAINTS ALL DEFERRED")
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::query("UPDATE memberships SET status='removed', removed_at=now() WHERE id=$1")
            .bind(membership_id)
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
            .execute(&mut *transaction)
            .await
            .unwrap();
        transaction.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn module_ii_schema_rejects_activation_version_epoch_mismatch() {
        let Some(store) = connect_from_environment().await else {
            return;
        };
        let mut transaction = store.begin().await.unwrap();
        sqlx::query("SET CONSTRAINTS ALL DEFERRED")
            .execute(&mut *transaction)
            .await
            .unwrap();
        let organization_id = insert_suspended_organization(&mut transaction, "activation").await;
        let policy_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM organization_origin_budget_policies
             WHERE organization_id=$1 AND origin='system_provided'",
        )
        .bind(organization_id)
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
        let version_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO budget_policy_versions(
                id,policy_kind,organization_origin_budget_policy_id,generation,
                limit_cost_nanos,recovery_incident_cap_nanos,recovery_epoch_cap_nanos,
                epoch,mode,estimate_policy,allowance_policy,failure_policy,recovery_policy,
                created_by_principal
             ) VALUES (
                $1,'organization_origin_budget',$2,1,100,5,10,'epoch-1','enforce',
                '{}','{}','{}','{}','{}'
             )",
        )
        .bind(version_id)
        .bind(policy_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO policy_activations(
                id,organization_id,policy_kind,policy_id,desired_epoch,desired_version_id,
                desired_generation,candidate_fence,state
             ) VALUES (
                $1,$2,'organization_origin_budget',$3,'wrong-epoch',$4,1,$5,'desired'
             )",
        )
        .bind(Uuid::now_v7())
        .bind(organization_id)
        .bind(policy_id)
        .bind(version_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        let error = sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
            .execute(&mut *transaction)
            .await
            .unwrap_err();
        assert!(error.as_database_error().is_some());
        drop(transaction);
    }

    #[tokio::test]
    async fn module_ii_schema_rejects_organization_resource_grants() {
        let Some(store) = connect_from_environment().await else {
            return;
        };
        let mut transaction = store.begin().await.unwrap();
        let organization_id = insert_suspended_organization(&mut transaction, "grant-scope").await;
        let user_id = Uuid::now_v7();
        let membership_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO users(id,kind,status,display_name,created_by_principal,etag_token)
             VALUES ($1,'human','active','Grant owner','{}',$2)",
        )
        .bind(user_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO memberships(
                id,organization_id,user_id,role,status,created_by_principal,etag_token
             ) VALUES ($1,$2,$3,'owner','active','{}',$4)",
        )
        .bind(membership_id)
        .bind(organization_id)
        .bind(user_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        let reliability_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO reliability_policies(
                id,name,attempt_policy,deadline_policy,retry_policy,failover_policy,
                commitment_policy,health_policy,circuit_policy,probe_policy,status,
                created_by_principal,etag_token
             ) VALUES ($1,$2,'{}','{}','{}','{}','{}','{}','{}','{}','active','{}',$3)",
        )
        .bind(reliability_id)
        .bind(format!("grant-reliability-{reliability_id}"))
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        let route_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO model_routes(
                id,resource_scope_kind,organization_id,owner_user_id,owner_membership_id,
                model_key,ingress_protocol_family,required_base_capabilities,selection_policy,
                reliability_policy_id,request_policy,status,created_by_principal,etag_token
             ) VALUES ($1,'organization',$2,$3,$4,'grant-model','openai_responses',
                '[]','{}',$5,'{}','draft','{}',$6)",
        )
        .bind(route_id)
        .bind(organization_id)
        .bind(user_id)
        .bind(membership_id)
        .bind(reliability_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        let error = sqlx::query(
            "INSERT INTO organization_route_grants(
                organization_id,route_id,ceilings,status,created_by_principal,etag_token
             ) VALUES ($1,$2,'{}','active','{}',$3)",
        )
        .bind(organization_id)
        .bind(route_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap_err();
        assert!(error.as_database_error().is_some());
        transaction.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn module_ii_schema_rejects_stale_credential_state_identity() {
        let Some(store) = connect_from_environment().await else {
            return;
        };
        let mut transaction = store.begin().await.unwrap();
        sqlx::query("SET CONSTRAINTS ALL DEFERRED")
            .execute(&mut *transaction)
            .await
            .unwrap();
        let credential_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO upstream_credentials(
                id,resource_scope_kind,name,credential_kind,secret_source_kind,injection_kind,
                sharing_policy,administrative_status,authentication_status,
                created_by_principal,etag_token
             ) VALUES ($1,'deployment','state-identity','static_api_key','encrypted_database',
                'bearer','exclusive','active','ready','{}',$2)",
        )
        .bind(credential_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        let protected_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO protected_secret_versions(
                id,scope_kind,owner_kind,owner_id,owner_generation,secret_version,
                field_purpose,custody_provider_id,provider_format_version,context_version,
                opaque_envelope
             ) VALUES ($1,'system','upstream_credential',$2,1,1,
                'upstream_credential_material','software-xchacha20-poly1305',1,1,'\\x01')",
        )
        .bind(protected_id)
        .bind(credential_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO upstream_credential_secret_versions(
                id,credential_id,version,credential_state_identity_version,
                protected_secret_version_id,safe_fingerprint,state
             ) VALUES ($1,$2,1,1,$3,decode(repeat('00',32),'hex'),'current')",
        )
        .bind(Uuid::now_v7())
        .bind(credential_id)
        .bind(protected_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query("UPDATE upstream_credentials SET current_secret_version=1 WHERE id=$1")
            .bind(credential_id)
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::query("SET CONSTRAINTS ALL DEFERRED")
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::query("UPDATE upstream_credentials SET state_identity_version=2 WHERE id=$1")
            .bind(credential_id)
            .execute(&mut *transaction)
            .await
            .unwrap();
        let error = sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
            .execute(&mut *transaction)
            .await
            .unwrap_err();
        assert!(error.as_database_error().is_some());
        drop(transaction);
    }

    #[tokio::test]
    async fn module_ii_schema_serializes_and_caps_coordinator_recovery() {
        let Some(store) = connect_from_environment().await else {
            return;
        };
        let organization_id = {
            let mut transaction = store.begin().await.unwrap();
            let organization_id =
                insert_suspended_organization(&mut transaction, "recovery-cap").await;
            transaction.commit().await.unwrap();
            organization_id
        };
        let policy_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM organization_origin_budget_policies
             WHERE organization_id=$1 AND origin='system_provided'",
        )
        .bind(organization_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
        let version_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO budget_policy_versions(
                id,policy_kind,organization_origin_budget_policy_id,generation,
                limit_cost_nanos,recovery_incident_cap_nanos,recovery_epoch_cap_nanos,
                epoch,mode,estimate_policy,allowance_policy,failure_policy,recovery_policy,
                created_by_principal
             ) VALUES ($1,'organization_origin_budget',$2,1,100,6,10,'epoch-cap','enforce',
                '{}','{}','{}','{}','{}')",
        )
        .bind(version_id)
        .bind(policy_id)
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "UPDATE organization_origin_budget_policies
             SET status='active',active_version_id=$2,etag_token=$3,updated_at=now()
             WHERE id=$1",
        )
        .bind(policy_id)
        .bind(version_id)
        .bind(Uuid::now_v7())
        .execute(store.pool())
        .await
        .unwrap();
        let incident_cap_error = sqlx::query(
            "INSERT INTO coordinator_recoveries(
                id,organization_id,policy_kind,policy_id,policy_version_id,epoch,
                policy_generation,recovery_generation,authorized_allowance_nanos,
                cumulative_epoch_allowance_nanos,incident_reference,
                authorized_by_principal,safe_evidence,reason
             ) VALUES ($1,$2,'organization_origin_budget',$3,$4,'epoch-cap',1,1,7,7,
                'incident-cap','{}','{}','schema test')",
        )
        .bind(Uuid::now_v7())
        .bind(organization_id)
        .bind(policy_id)
        .bind(version_id)
        .execute(store.pool())
        .await
        .unwrap_err();
        assert!(incident_cap_error.as_database_error().is_some());

        let mut first = store.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO coordinator_recoveries(
                id,organization_id,policy_kind,policy_id,policy_version_id,epoch,
                policy_generation,recovery_generation,authorized_allowance_nanos,
                cumulative_epoch_allowance_nanos,incident_reference,
                authorized_by_principal,safe_evidence,reason
             ) VALUES ($1,$2,'organization_origin_budget',$3,$4,'epoch-cap',1,1,6,6,
                'incident-a','{}','{}','schema test')",
        )
        .bind(Uuid::now_v7())
        .bind(organization_id)
        .bind(policy_id)
        .bind(version_id)
        .execute(&mut *first)
        .await
        .unwrap();
        let second_store = store.clone();
        let second = tokio::spawn(async move {
            sqlx::query(
                "INSERT INTO coordinator_recoveries(
                    id,organization_id,policy_kind,policy_id,policy_version_id,epoch,
                    policy_generation,recovery_generation,authorized_allowance_nanos,
                    cumulative_epoch_allowance_nanos,incident_reference,
                    authorized_by_principal,safe_evidence,reason
                 ) VALUES ($1,$2,'organization_origin_budget',$3,$4,'epoch-cap',1,2,5,11,
                    'incident-b','{}','{}','schema test')",
            )
            .bind(Uuid::now_v7())
            .bind(organization_id)
            .bind(policy_id)
            .bind(version_id)
            .execute(second_store.pool())
            .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!second.is_finished());
        first.commit().await.unwrap();
        let error = second.await.unwrap().unwrap_err();
        assert!(error.as_database_error().is_some());
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM coordinator_recoveries
             WHERE policy_id=$1 AND epoch='epoch-cap'",
        )
        .bind(policy_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(count, 1);

        let duplicate_incident_error = sqlx::query(
            "INSERT INTO coordinator_recoveries(
                id,organization_id,policy_kind,policy_id,policy_version_id,epoch,
                policy_generation,recovery_generation,authorized_allowance_nanos,
                cumulative_epoch_allowance_nanos,incident_reference,
                authorized_by_principal,safe_evidence,reason
             ) VALUES ($1,$2,'organization_origin_budget',$3,$4,'epoch-cap',1,2,1,7,
                'incident-a','{}','{}','schema test')",
        )
        .bind(Uuid::now_v7())
        .bind(organization_id)
        .bind(policy_id)
        .bind(version_id)
        .execute(store.pool())
        .await
        .unwrap_err();
        assert!(duplicate_incident_error.as_database_error().is_some());
    }

    #[tokio::test]
    async fn module_ii_schema_rejects_selected_secret_reverse_mutation() {
        let Some(store) = connect_from_environment().await else {
            return;
        };
        let mut transaction = store.begin().await.unwrap();
        sqlx::query("SET CONSTRAINTS ALL DEFERRED")
            .execute(&mut *transaction)
            .await
            .unwrap();
        let credential_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO upstream_credentials(
                id,resource_scope_kind,name,credential_kind,secret_source_kind,
                source_configuration,injection_kind,sharing_policy,administrative_status,
                authentication_status,created_by_principal,etag_token
             ) VALUES ($1,'deployment','reverse-secret','static_api_key',
                'environment_reference','{}','bearer','exclusive','active','ready','{}',$2)",
        )
        .bind(credential_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        let secret_version_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO upstream_credential_secret_versions(
                id,credential_id,version,credential_state_identity_version,
                source_configuration,safe_fingerprint,state
             ) VALUES ($1,$2,1,1,'{\"environment_variable\":\"TEST_KEY\"}',
                decode(repeat('00',32),'hex'),'current')",
        )
        .bind(secret_version_id)
        .bind(credential_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query("UPDATE upstream_credentials SET current_secret_version=1 WHERE id=$1")
            .bind(credential_id)
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::query("SET CONSTRAINTS ALL DEFERRED")
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE upstream_credential_secret_versions SET state='retired', retired_at=now()
             WHERE id=$1",
        )
        .bind(secret_version_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
        let error = sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
            .execute(&mut *transaction)
            .await
            .unwrap_err();
        assert!(error.as_database_error().is_some());
        drop(transaction);
    }

    #[tokio::test]
    async fn module_ii_schema_rejects_cross_organization_usage_principal() {
        let Some(store) = connect_from_environment().await else {
            return;
        };
        let mut transaction = store.begin().await.unwrap();
        sqlx::query("SET CONSTRAINTS ALL DEFERRED")
            .execute(&mut *transaction)
            .await
            .unwrap();
        let organization_a = insert_suspended_organization(&mut transaction, "usage-a").await;
        let organization_b = insert_suspended_organization(&mut transaction, "usage-b").await;
        let user_id = Uuid::now_v7();
        let membership_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO users(id,kind,status,display_name,created_by_principal,etag_token)
             VALUES ($1,'human','active','Usage owner','{}',$2)",
        )
        .bind(user_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO memberships(
                id,organization_id,user_id,role,status,created_by_principal,etag_token
             ) VALUES ($1,$2,$3,'owner','active','{}',$4)",
        )
        .bind(membership_id)
        .bind(organization_a)
        .bind(user_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        let reliability_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO reliability_policies(
                id,name,attempt_policy,deadline_policy,retry_policy,failover_policy,
                commitment_policy,health_policy,circuit_policy,probe_policy,status,
                created_by_principal,etag_token
             ) VALUES ($1,$2,'{}','{}','{}','{}','{}','{}','{}','{}','active','{}',$3)",
        )
        .bind(reliability_id)
        .bind(format!("usage-reliability-{reliability_id}"))
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        let route_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO model_routes(
                id,resource_scope_kind,organization_id,owner_user_id,owner_membership_id,
                model_key,ingress_protocol_family,required_base_capabilities,selection_policy,
                reliability_policy_id,request_policy,status,created_by_principal,etag_token
             ) VALUES ($1,'organization',$2,$3,$4,'usage-model','openai_responses',
                '[]','{}',$5,'{}','draft','{}',$6)",
        )
        .bind(route_id)
        .bind(organization_a)
        .bind(user_id)
        .bind(membership_id)
        .bind(reliability_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        let key_id = Uuid::now_v7();
        let budget_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO gateway_api_keys(
                id,organization_id,issuance_policy_class,created_by_principal,name,key_prefix,
                lookup_id,scopes,budget_policy_id,status,etag_token
             ) VALUES ($1,$2,'standard','{}','usage-key','owlrora_llm_v1',
                'DDDDDDDDDDDDDDDDDDDDDD','[\"llm:invoke\"]',$3,'disabled',$4)",
        )
        .bind(key_id)
        .bind(organization_b)
        .bind(budget_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO gateway_key_budget_policies(
                id,organization_id,gateway_api_key_id,status,etag_token
             ) VALUES ($1,$2,$3,'suspended',$4)",
        )
        .bind(budget_id)
        .bind(organization_b)
        .bind(key_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO gateway_api_key_secret_versions(
                id,gateway_api_key_id,lookup_id,secret_digest,state
             ) VALUES ($1,$2,'DDDDDDDDDDDDDDDDDDDDDD',$3,'current')",
        )
        .bind(Uuid::now_v7())
        .bind(key_id)
        .bind(vec![7_u8; 32])
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
            .execute(&mut *transaction)
            .await
            .unwrap();
        let error = sqlx::query(
            "INSERT INTO logical_usage_hourly(
                bucket_start,organization_id,principal_kind,gateway_api_key_id,route_id,
                ingress_protocol_family,outcome_class,request_count,input_units,output_units,
                cached_input_units,cost_nanos,unknown_cost_count,duration_millis
             ) VALUES (date_trunc('hour',now()),$1,'gateway_api_key',$2,$3,
                'openai_responses','success',1,1,1,0,1,0,1)",
        )
        .bind(organization_a)
        .bind(key_id)
        .bind(route_id)
        .execute(&mut *transaction)
        .await
        .unwrap_err();
        assert!(error.as_database_error().is_some());
        transaction.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn module_ii_migration_preserves_legacy_issuer_authority() {
        let Some(store) = connect_from_environment().await else {
            return;
        };
        let mut transaction = store.begin().await.unwrap();
        let schema = format!("module_ii_upgrade_{}", Uuid::now_v7().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::query(&format!("SET LOCAL search_path TO {schema}, pg_catalog"))
            .execute(&mut *transaction)
            .await
            .unwrap();
        for migration in [
            include_str!("migrations/0001_module_i.sql"),
            include_str!("migrations/0002_external_session_subject.sql"),
            include_str!("migrations/0003_identity_authority_hardening.sql"),
            include_str!("migrations/0004_owner_invariant_trigger_fix.sql"),
            include_str!("migrations/0005_verifier_material_delete_guard.sql"),
            include_str!("migrations/0006_session_and_rotation_hardening.sql"),
            include_str!("migrations/0007_identity_cleanup_indexes.sql"),
        ] {
            sqlx::raw_sql(migration)
                .execute(&mut *transaction)
                .await
                .unwrap();
        }
        sqlx::query(
            "INSERT INTO external_identity_issuers(
                id,name,display_name,issuer,status,jwks_source,allowed_algorithms,
                accepted_audiences,subject_claim,claim_mapping,jwt_capability_ceiling,
                management_scope_ceiling,management_organization_ceiling,
                capability_claim_policy,jwt_route_ceiling,organization_selector,
                clock_skew_seconds,key_cache_policy,created_by_principal,etag_token
             ) VALUES (
                $1,'legacy','Legacy','https://legacy.example','active',
                '{\"kind\":\"static\",\"jwks\":{\"keys\":[]}}',
                '[\"RS256\"]','[\"owlrora\"]','sub','{}',
                '[\"management:access\",\"llm:invoke\",\"llm:stream\"]',
                '[\"management:read\"]','{\"kind\":\"all_authorized\"}',
                'ignore','{\"kind\":\"all_organization_granted\"}',
                '{\"kind\":\"header\"}',60,
                '{\"refresh_interval_seconds\":3600,
                   \"material_acceptance_seconds\":86400,
                   \"max_keys\":32,\"max_token_bytes\":16384}',
                '{}',$2)",
        )
        .bind(Uuid::now_v7())
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        transaction.commit().await.unwrap();

        let mut transaction = store.begin().await.unwrap();
        sqlx::query(&format!("SET LOCAL search_path TO {schema}, pg_catalog"))
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::raw_sql(include_str!("migrations/0008_module_ii_gateway_plane.sql"))
            .execute(&mut *transaction)
            .await
            .unwrap();
        let row = sqlx::query(
            "SELECT management_capability_ceiling, jwt_capability_ceiling,
                    llm_scope_ceiling
             FROM external_identity_issuers WHERE name='legacy'",
        )
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
        let management: serde_json::Value = row.try_get("management_capability_ceiling").unwrap();
        assert!(
            management
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "read_operations")
        );
        assert!(
            management
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "manage_identity")
        );
        assert_eq!(
            row.try_get::<serde_json::Value, _>("jwt_capability_ceiling")
                .unwrap(),
            serde_json::json!(["llm:access", "management:access"])
        );
        assert_eq!(
            row.try_get::<serde_json::Value, _>("llm_scope_ceiling")
                .unwrap(),
            serde_json::json!(["llm:invoke", "llm:stream"])
        );
        transaction.rollback().await.unwrap();
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(store.pool())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn overlap_hardening_migration_accepts_legacy_rotation_history() {
        let Some(store) = connect_from_environment().await else {
            return;
        };
        let mut transaction = store.begin().await.unwrap();
        sqlx::raw_sql(
            "CREATE TEMP TABLE management_api_key_secret_versions (
                 state text NOT NULL,
                 created_at timestamptz NOT NULL,
                 overlap_until timestamptz
             );
             CREATE TEMP TABLE system_administrator_grants (
                 id uuid NOT NULL,
                 created_at timestamptz NOT NULL
             );
             INSERT INTO management_api_key_secret_versions(state, created_at, overlap_until)
             VALUES
                 ('retired', now()-interval '30 days', now()-interval '1 day'),
                 ('overlap', now()-interval '30 days', now()+interval '1 hour');",
        )
        .execute(&mut *transaction)
        .await
        .unwrap();

        sqlx::raw_sql(include_str!(
            "migrations/0006_session_and_rotation_hardening.sql"
        ))
        .execute(&mut *transaction)
        .await
        .unwrap();

        let retired_is_normalized = sqlx::query_scalar::<_, bool>(
            "SELECT overlap_until IS NULL AND overlap_started_at IS NULL
             FROM management_api_key_secret_versions WHERE state='retired'",
        )
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
        assert!(retired_is_normalized);
        let overlap_uses_upgrade_time = sqlx::query_scalar::<_, bool>(
            "SELECT overlap_started_at > created_at
                 AND overlap_started_at <= CURRENT_TIMESTAMP
                 AND overlap_until >= overlap_started_at
             FROM management_api_key_secret_versions WHERE state='overlap'",
        )
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
        assert!(overlap_uses_upgrade_time);
        transaction.rollback().await.unwrap();
    }
}
