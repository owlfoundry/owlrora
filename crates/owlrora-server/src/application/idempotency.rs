use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row as _, Transaction, postgres::PgRow};

use crate::domain::{Actor, ResourceScope};

use super::{Application, ApplicationError, RequestIdentity};

const IDEMPOTENCY_TTL_HOURS: i64 = 24;

#[derive(Clone, Debug)]
pub(crate) struct IdempotencyHandle {
    actor_fingerprint: String,
    scope_fingerprint: String,
    operation_id: String,
    idempotency_key: String,
    request_fingerprint: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct IdempotencyReplay {
    pub status: u16,
    pub body: Value,
    pub etag: Option<String>,
}

#[derive(Clone, Debug)]
pub enum IdempotentCommand<T> {
    Executed(T),
    Replay(IdempotencyReplay),
}

#[derive(Clone, Debug)]
pub(crate) enum IdempotencyDecision {
    Execute(Option<IdempotencyHandle>),
    Replay(IdempotencyReplay),
}

impl Application {
    pub(crate) async fn begin_idempotent_command<T: Serialize>(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        identity: &RequestIdentity,
        scope: &ResourceScope,
        operation_id: &str,
        idempotency_key: Option<&str>,
        request: &T,
    ) -> Result<IdempotencyDecision, ApplicationError> {
        let Some(idempotency_key) = idempotency_key else {
            return Ok(IdempotencyDecision::Execute(None));
        };
        let handle = idempotency_handle(identity, scope, operation_id, idempotency_key, request)?;
        let inserted = sqlx::query(
            "INSERT INTO idempotency_records(
                actor_fingerprint, scope_fingerprint, operation_id, idempotency_key,
                request_fingerprint, state, expires_at
             ) VALUES ($1,$2,$3,$4,$5,'in_progress',now()+make_interval(hours => $6))
             ON CONFLICT DO NOTHING",
        )
        .bind(&handle.actor_fingerprint)
        .bind(&handle.scope_fingerprint)
        .bind(&handle.operation_id)
        .bind(&handle.idempotency_key)
        .bind(handle.request_fingerprint.to_vec())
        .bind(i32::try_from(IDEMPOTENCY_TTL_HOURS).map_err(|_| ApplicationError::Internal)?)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
        if inserted == 1 {
            return Ok(IdempotencyDecision::Execute(Some(handle)));
        }
        let row = sqlx::query(
            "SELECT request_fingerprint, state, response_status, response_body
             FROM idempotency_records
             WHERE actor_fingerprint=$1 AND scope_fingerprint=$2
               AND operation_id=$3 AND idempotency_key=$4",
        )
        .bind(&handle.actor_fingerprint)
        .bind(&handle.scope_fingerprint)
        .bind(&handle.operation_id)
        .bind(&handle.idempotency_key)
        .fetch_one(&mut **transaction)
        .await?;
        Ok(IdempotencyDecision::Replay(replay_from_row(&row, &handle)?))
    }

    pub(crate) async fn replay_completed_idempotent_command<T: Serialize>(
        &self,
        identity: &RequestIdentity,
        scope: &ResourceScope,
        operation_id: &str,
        idempotency_key: Option<&str>,
        request: &T,
    ) -> Result<Option<IdempotencyReplay>, ApplicationError> {
        let Some(idempotency_key) = idempotency_key else {
            return Ok(None);
        };
        let handle = idempotency_handle(identity, scope, operation_id, idempotency_key, request)?;
        let row = sqlx::query(
            "SELECT request_fingerprint, state, response_status, response_body
             FROM idempotency_records
             WHERE actor_fingerprint=$1 AND scope_fingerprint=$2
               AND operation_id=$3 AND idempotency_key=$4",
        )
        .bind(&handle.actor_fingerprint)
        .bind(&handle.scope_fingerprint)
        .bind(&handle.operation_id)
        .bind(&handle.idempotency_key)
        .fetch_optional(self.store.pool())
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        if row.try_get::<Vec<u8>, _>("request_fingerprint")?
            != handle.request_fingerprint.as_slice()
        {
            return Err(ApplicationError::IdempotencyConflict);
        }
        if row.try_get::<String, _>("state")? != "completed" {
            return Ok(None);
        }
        replay_from_row(&row, &handle).map(Some)
    }

    pub(crate) async fn cleanup_expired_idempotency_records(
        &self,
    ) -> Result<u64, ApplicationError> {
        const BATCH_SIZE: u64 = 1_000;
        let mut total = 0_u64;
        loop {
            let deleted = sqlx::query(
                "DELETE FROM idempotency_records
                 WHERE (actor_fingerprint, scope_fingerprint, operation_id, idempotency_key) IN (
                     SELECT actor_fingerprint, scope_fingerprint, operation_id, idempotency_key
                     FROM idempotency_records
                     WHERE state='completed' AND expires_at < now()
                     ORDER BY expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED
                 )",
            )
            .execute(self.store.pool())
            .await?
            .rows_affected();
            total = total
                .checked_add(deleted)
                .ok_or(ApplicationError::Internal)?;
            if deleted < BATCH_SIZE {
                return Ok(total);
            }
            tokio::task::yield_now().await;
        }
    }

    pub(crate) async fn complete_idempotent_command<T: Serialize>(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        handle: Option<IdempotencyHandle>,
        status: u16,
        body: &T,
        etag: Option<&str>,
    ) -> Result<(), ApplicationError> {
        let Some(handle) = handle else {
            return Ok(());
        };
        let body = serde_json::to_value(body).map_err(|_| ApplicationError::Internal)?;
        let changed = sqlx::query(
            "UPDATE idempotency_records
             SET state='completed', response_status=$6, response_body=$7
             WHERE actor_fingerprint=$1 AND scope_fingerprint=$2
               AND operation_id=$3 AND idempotency_key=$4
               AND request_fingerprint=$5 AND state='in_progress'",
        )
        .bind(&handle.actor_fingerprint)
        .bind(&handle.scope_fingerprint)
        .bind(&handle.operation_id)
        .bind(&handle.idempotency_key)
        .bind(handle.request_fingerprint.to_vec())
        .bind(i32::from(status))
        .bind(json!({"body":body, "etag":etag}))
        .execute(&mut **transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(ApplicationError::Internal);
        }
        Ok(())
    }
}

fn idempotency_handle<T: Serialize>(
    identity: &RequestIdentity,
    scope: &ResourceScope,
    operation_id: &str,
    idempotency_key: &str,
    request: &T,
) -> Result<IdempotencyHandle, ApplicationError> {
    validate_idempotency_key(idempotency_key)?;
    let actor = serde_json::to_vec(&Actor::from(&identity.principal))
        .map_err(|_| ApplicationError::Internal)?;
    let actor_fingerprint = fingerprint_text(b"owlrora:idempotency:actor:v1\0", &actor);
    let scope_bytes = serde_json::to_vec(scope).map_err(|_| ApplicationError::Internal)?;
    let scope_fingerprint = fingerprint_text(b"owlrora:idempotency:scope:v1\0", &scope_bytes);
    let request_bytes = serde_json::to_vec(request).map_err(|_| ApplicationError::Internal)?;
    let request_fingerprint = fingerprint(b"owlrora:idempotency:request:v1\0", &request_bytes);
    Ok(IdempotencyHandle {
        actor_fingerprint,
        scope_fingerprint,
        operation_id: operation_id.to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        request_fingerprint,
    })
}

fn replay_from_row(
    row: &PgRow,
    handle: &IdempotencyHandle,
) -> Result<IdempotencyReplay, ApplicationError> {
    if row.try_get::<Vec<u8>, _>("request_fingerprint")? != handle.request_fingerprint.as_slice() {
        return Err(ApplicationError::IdempotencyConflict);
    }
    if row.try_get::<String, _>("state")? != "completed" {
        return Err(ApplicationError::Internal);
    }
    let status = row
        .try_get::<Option<i32>, _>("response_status")?
        .and_then(|value| u16::try_from(value).ok())
        .ok_or(ApplicationError::Internal)?;
    let stored = row
        .try_get::<Option<Value>, _>("response_body")?
        .ok_or(ApplicationError::Internal)?;
    let body = stored
        .get("body")
        .cloned()
        .ok_or(ApplicationError::Internal)?;
    let etag = stored
        .get("etag")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(IdempotencyReplay { status, body, etag })
}

fn validate_idempotency_key(value: &str) -> Result<(), ApplicationError> {
    if value.is_empty()
        || value.len() > 200
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(ApplicationError::Validation(
            "Idempotency-Key must contain 1 to 200 visible ASCII characters without spaces"
                .to_owned(),
        ));
    }
    Ok(())
}

fn fingerprint(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(value);
    digest.finalize().into()
}

fn fingerprint_text(domain: &[u8], value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(fingerprint(domain, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idempotency_keys_are_bounded_and_request_fingerprints_are_domain_separated() {
        assert!(validate_idempotency_key("retry-123").is_ok());
        assert!(validate_idempotency_key("").is_err());
        assert!(validate_idempotency_key("contains space").is_err());
        assert_ne!(
            fingerprint(b"domain-a\0", b"same"),
            fingerprint(b"domain-b\0", b"same")
        );
    }
}
