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
                "read_operations", "recover_operations", "read_organization",
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

    pub async fn connect_from_environment() -> Option<PgStore> {
        let url = std::env::var("OWLRORA_TEST_DATABASE_URL").ok()?;
        Some(
            PgStore::connect(&url, 4)
                .await
                .expect("test database should connect"),
        )
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
