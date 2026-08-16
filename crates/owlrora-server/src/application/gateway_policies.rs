use std::{collections::BTreeSet, sync::Arc, time::Duration};

use chrono::Utc;
use serde_json::{Value, json};
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::{
    adapters::{
        coordinator::{PolicyCandidate, PolicyCoordinatorConfig, RedisCoordinator},
        postgres::{AuditRecord, RuntimeEvent},
    },
    domain::{
        AccountingOrigin, Actor, BudgetAllowancePolicy, BudgetEstimatePolicy, BudgetFailurePolicy,
        BudgetMode, BudgetRecoveryPolicy, Capability, CoordinationFailureMode, GatewayKeyId,
        ManagementScope, OrganizationId, PolicyKind, RateGrantPolicy, ResourceScope,
        UnknownEstimateMode,
    },
};

use super::{
    Application, ApplicationError, AuthorizationTarget, BeginBudgetEpoch, BudgetPolicyVersionView,
    BudgetPolicyView, CatalogStatus, EntityTag, GatewayBudgetInput, GatewayPolicyCeilings,
    GatewayRequestLimitsInput, GatewayRequestLimitsView, IdempotencyDecision, IdempotentCommand,
    RequestIdentity, UpdateBudgetPolicy, UpdateField, UpdateGatewayPolicyCeilings,
    UpdateGatewayRequestLimits,
};

impl Application {
    pub async fn get_gateway_policy_ceilings(
        &self,
        identity: &RequestIdentity,
    ) -> Result<(GatewayPolicyCeilings, EntityTag), ApplicationError> {
        authorize_system_policy(self, identity, false)?;
        load_gateway_ceilings_pool(self).await
    }

    pub async fn update_gateway_policy_ceilings(
        &self,
        identity: &RequestIdentity,
        if_match: Option<&str>,
        input: UpdateGatewayPolicyCeilings,
    ) -> Result<(GatewayPolicyCeilings, EntityTag), ApplicationError> {
        authorize_system_policy(self, identity, true)?;
        if ceiling_update_is_empty(&input) {
            return Err(ApplicationError::Validation(
                "at least one gateway policy ceiling is required".to_owned(),
            ));
        }
        let mut transaction = self.store.begin().await?;
        let row = lock_gateway_ceilings(&mut transaction).await?;
        let current_etag = EntityTag::for_resource(
            "gateway_policy_ceilings",
            self.store.installation_id(),
            row.try_get("etag_token")?,
        );
        require_if_match(if_match, &current_etag)?;
        let mut candidate = gateway_ceilings_from_row(&row)?;
        apply_required(
            &mut candidate.key_budget_max_limit_cost_nanos,
            input.key_budget_max_limit_cost_nanos,
            "key_budget_max_limit_cost_nanos",
        )?;
        apply_required(
            &mut candidate.byok_origin_budget_max_limit_cost_nanos,
            input.byok_origin_budget_max_limit_cost_nanos,
            "byok_origin_budget_max_limit_cost_nanos",
        )?;
        apply_required(
            &mut candidate.max_recovery_incident_cap_nanos,
            input.max_recovery_incident_cap_nanos,
            "max_recovery_incident_cap_nanos",
        )?;
        apply_required(
            &mut candidate.max_recovery_epoch_cap_nanos,
            input.max_recovery_epoch_cap_nanos,
            "max_recovery_epoch_cap_nanos",
        )?;
        apply_required(
            &mut candidate.max_requests_per_minute,
            input.max_requests_per_minute,
            "max_requests_per_minute",
        )?;
        apply_required(
            &mut candidate.max_input_units_per_minute,
            input.max_input_units_per_minute,
            "max_input_units_per_minute",
        )?;
        apply_required(
            &mut candidate.max_concurrency,
            input.max_concurrency,
            "max_concurrency",
        )?;
        apply_required(
            &mut candidate.max_stream_seconds,
            input.max_stream_seconds,
            "max_stream_seconds",
        )?;
        apply_required(
            &mut candidate.allowed_budget_modes,
            input.allowed_budget_modes,
            "allowed_budget_modes",
        )?;
        apply_required(
            &mut candidate.allowed_rate_grant_modes,
            input.allowed_rate_grant_modes,
            "allowed_rate_grant_modes",
        )?;
        apply_required(
            &mut candidate.allowed_concurrency_modes,
            input.allowed_concurrency_modes,
            "allowed_concurrency_modes",
        )?;
        validate_gateway_ceilings(&candidate)?;
        ensure_active_policies_fit_ceilings(&mut transaction, &candidate).await?;
        sqlx::query(
            "UPDATE gateway_policy_ceilings SET
                key_budget_max_limit_cost_nanos=$1,
                byok_origin_budget_max_limit_cost_nanos=$2,
                max_recovery_incident_cap_nanos=$3,
                max_recovery_epoch_cap_nanos=$4,
                max_requests_per_minute=$5,
                max_input_units_per_minute=$6,
                max_concurrency=$7,
                max_stream_seconds=$8,
                allowed_budget_modes=$9,
                allowed_rate_grant_modes=$10,
                allowed_concurrency_modes=$11,
                etag_token=$12,updated_at=now()
             WHERE singleton=true",
        )
        .bind(&candidate.key_budget_max_limit_cost_nanos)
        .bind(&candidate.byok_origin_budget_max_limit_cost_nanos)
        .bind(&candidate.max_recovery_incident_cap_nanos)
        .bind(&candidate.max_recovery_epoch_cap_nanos)
        .bind(
            i32::try_from(candidate.max_requests_per_minute)
                .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(
            i64::try_from(candidate.max_input_units_per_minute)
                .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(i32::try_from(candidate.max_concurrency).map_err(|_| ApplicationError::Internal)?)
        .bind(i32::try_from(candidate.max_stream_seconds).map_err(|_| ApplicationError::Internal)?)
        .bind(json!(candidate.allowed_budget_modes))
        .bind(json!(candidate.allowed_rate_grant_modes))
        .bind(json!(candidate.allowed_concurrency_modes))
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let result =
            load_gateway_ceilings_tx(&mut transaction, self.store.installation_id()).await?;
        commit_policy(
            self,
            transaction,
            identity,
            None,
            "gateway_policy_ceilings",
            None,
            "system.gateway_policy_ceilings.update",
        )
        .await?;
        self.publish_committed_runtime(
            &identity.request_id,
            "system.gateway_policy_ceilings.update",
        )
        .await;
        Ok(result)
    }

    pub async fn get_gateway_key_budget(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        key_id: GatewayKeyId,
    ) -> Result<(BudgetPolicyView, EntityTag), ApplicationError> {
        authorize_organization_budget(self, identity, organization_id, false)?;
        load_key_budget_pool(self, organization_id, key_id).await
    }

    pub async fn update_gateway_key_budget(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        key_id: GatewayKeyId,
        if_match: Option<&str>,
        input: UpdateBudgetPolicy,
    ) -> Result<(BudgetPolicyView, EntityTag), ApplicationError> {
        authorize_organization_budget(self, identity, organization_id, true)?;
        mutate_budget(
            self,
            identity,
            BudgetOwner::Key {
                organization_id,
                key_id,
            },
            if_match,
            true,
            input,
            None,
            "organization.gateway_api_keys.budget.update",
            None,
        )
        .await
        .and_then(executed_budget_result)
    }

    pub async fn begin_gateway_key_budget_epoch(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        key_id: GatewayKeyId,
        input: BeginBudgetEpoch,
        idempotency_key: Option<&str>,
    ) -> Result<IdempotentCommand<(BudgetPolicyView, EntityTag)>, ApplicationError> {
        authorize_organization_budget(self, identity, organization_id, true)?;
        let request = json!({"gateway_api_key_id":key_id,"input":input});
        mutate_budget(
            self,
            identity,
            BudgetOwner::Key {
                organization_id,
                key_id,
            },
            None,
            false,
            UpdateBudgetPolicy::default(),
            Some(input),
            "organization.gateway_api_keys.budget.begin_epoch",
            Some(BudgetIdempotency {
                key: idempotency_key,
                request: &request,
            }),
        )
        .await
    }

    pub async fn get_provider_budget(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        origin: AccountingOrigin,
    ) -> Result<(BudgetPolicyView, EntityTag), ApplicationError> {
        authorize_provider_budget(self, identity, organization_id, origin, false)?;
        load_origin_budget_pool(self, organization_id, origin).await
    }

    pub async fn update_provider_budget(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        origin: AccountingOrigin,
        if_match: Option<&str>,
        input: UpdateBudgetPolicy,
    ) -> Result<(BudgetPolicyView, EntityTag), ApplicationError> {
        authorize_provider_budget(self, identity, organization_id, origin, true)?;
        mutate_budget(
            self,
            identity,
            BudgetOwner::Origin {
                organization_id,
                origin,
            },
            if_match,
            true,
            input,
            None,
            origin_operation(origin, false),
            None,
        )
        .await
        .and_then(executed_budget_result)
    }

    pub async fn begin_provider_budget_epoch(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        origin: AccountingOrigin,
        input: BeginBudgetEpoch,
        idempotency_key: Option<&str>,
    ) -> Result<IdempotentCommand<(BudgetPolicyView, EntityTag)>, ApplicationError> {
        authorize_provider_budget(self, identity, organization_id, origin, true)?;
        let request = json!({"origin":origin,"input":input});
        mutate_budget(
            self,
            identity,
            BudgetOwner::Origin {
                organization_id,
                origin,
            },
            None,
            false,
            UpdateBudgetPolicy::default(),
            Some(input),
            origin_operation(origin, true),
            Some(BudgetIdempotency {
                key: idempotency_key,
                request: &request,
            }),
        )
        .await
    }

    pub async fn get_gateway_key_limits(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        key_id: GatewayKeyId,
    ) -> Result<(GatewayRequestLimitsView, EntityTag), ApplicationError> {
        authorize_organization_budget(self, identity, organization_id, false)?;
        load_limits_pool(self, organization_id, key_id).await
    }

    pub async fn update_gateway_key_limits(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        key_id: GatewayKeyId,
        if_match: Option<&str>,
        input: UpdateGatewayRequestLimits,
    ) -> Result<(GatewayRequestLimitsView, EntityTag), ApplicationError> {
        authorize_organization_budget(self, identity, organization_id, true)?;
        if input.limits.is_omitted() && input.status.is_omitted() {
            return Err(ApplicationError::Validation(
                "at least one request-limits field is required".to_owned(),
            ));
        }
        let mut transaction = self.store.begin().await?;
        lock_active_organization(&mut transaction, organization_id).await?;
        lock_gateway_key(&mut transaction, organization_id, key_id).await?;
        let row = lock_limits_policy(&mut transaction, organization_id, key_id).await?;
        let token = row
            .as_ref()
            .map(|row| row.try_get("etag_token"))
            .transpose()?
            .unwrap_or_else(|| key_id.as_uuid());
        require_if_match(
            if_match,
            &EntityTag::for_resource("gateway_key_request_limits", key_id.as_uuid(), token),
        )?;
        let mut desired = match row
            .as_ref()
            .map(|row| row.try_get::<Option<Uuid>, _>("desired_version_id"))
            .transpose()?
            .flatten()
        {
            Some(id) => Some(load_rate_input_tx(&mut transaction, id).await?),
            None => None,
        };
        let mut status = row
            .as_ref()
            .map(|row| parse_policy_status(&row.try_get::<String, _>("status")?))
            .transpose()?
            .unwrap_or(CatalogStatus::Disabled);
        match input.limits {
            UpdateField::Omitted => {}
            UpdateField::Null => desired = None,
            UpdateField::Value(value) => desired = Some(value),
        }
        apply_required(&mut status, input.status, "status")?;
        if status == CatalogStatus::Active && desired.is_none() {
            return Err(ApplicationError::Validation(
                "active request limits require a policy payload".to_owned(),
            ));
        }
        let ceilings = load_gateway_ceilings_tx(&mut transaction, self.store.installation_id())
            .await?
            .0;
        if let Some(value) = &desired {
            validate_request_limits(value)?;
            validate_request_limits_against_ceilings(value, &ceilings)?;
            validate_request_limits_against_organization_policy(
                &mut transaction,
                organization_id,
                key_id,
                value,
            )
            .await?;
        }
        let policy_id = row
            .as_ref()
            .map(|row| row.try_get("id"))
            .transpose()?
            .unwrap_or_else(Uuid::now_v7);
        let desired_version_id = if let Some(value) = &desired {
            let generation = next_rate_generation(&mut transaction, policy_id).await?;
            let id = Uuid::now_v7();
            insert_rate_version(
                &mut transaction,
                policy_id,
                id,
                generation,
                value,
                actor_value(identity)?,
            )
            .await?;
            Some(id)
        } else {
            None
        };
        let active_version_id = row
            .as_ref()
            .map(|row| row.try_get::<Option<Uuid>, _>("active_version_id"))
            .transpose()?
            .flatten();
        if row.is_some() {
            sqlx::query(
                "UPDATE gateway_key_rate_policies SET desired_version_id=$3,
                        status=$4,etag_token=$5,updated_at=now()
                 WHERE organization_id=$1 AND id=$2",
            )
            .bind(organization_id.as_uuid())
            .bind(policy_id)
            .bind(desired_version_id)
            .bind(status.as_str())
            .bind(Uuid::now_v7())
            .execute(&mut *transaction)
            .await?;
        } else {
            sqlx::query(
                "INSERT INTO gateway_key_rate_policies(
                    id,organization_id,gateway_api_key_id,desired_version_id,
                    active_version_id,status,etag_token)
                 VALUES ($1,$2,$3,$4,NULL,$5,$6)",
            )
            .bind(policy_id)
            .bind(organization_id.as_uuid())
            .bind(key_id.as_uuid())
            .bind(desired_version_id)
            .bind(status.as_str())
            .bind(Uuid::now_v7())
            .execute(&mut *transaction)
            .await?;
        }
        if status == CatalogStatus::Active
            && let Some(desired_version_id) = desired_version_id
        {
            let tightening = if let Some(active_version_id) = active_version_id {
                let active = load_rate_input_tx(&mut transaction, active_version_id).await?;
                request_limits_are_tightening(&active, desired.as_ref().expect("active limits"))
            } else {
                false
            };
            create_policy_activation(
                &mut transaction,
                PolicyKind::GatewayKeyRequestLimits,
                organization_id,
                policy_id,
                desired_version_id,
                active_version_id,
                tightening,
                self.config.policy_activation_timeout,
            )
            .await?;
        }
        sqlx::query(
            "UPDATE gateway_api_keys SET rate_policy_id=$3,etag_token=$4,updated_at=now()
             WHERE organization_id=$1 AND id=$2",
        )
        .bind(organization_id.as_uuid())
        .bind(key_id.as_uuid())
        .bind(policy_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let result = load_limits_tx(&mut transaction, organization_id, key_id).await?;
        commit_policy(
            self,
            transaction,
            identity,
            Some(organization_id),
            "gateway_key_request_limits",
            Some(key_id.to_string()),
            "organization.gateway_api_keys.limits.update",
        )
        .await?;
        self.publish_committed_runtime(
            &identity.request_id,
            "organization.gateway_api_keys.limits.update",
        )
        .await;
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug)]
enum BudgetOwner {
    Key {
        organization_id: OrganizationId,
        key_id: GatewayKeyId,
    },
    Origin {
        organization_id: OrganizationId,
        origin: AccountingOrigin,
    },
}

impl BudgetOwner {
    const fn organization_id(self) -> OrganizationId {
        match self {
            Self::Key {
                organization_id, ..
            }
            | Self::Origin {
                organization_id, ..
            } => organization_id,
        }
    }
}

struct BudgetIdempotency<'a> {
    key: Option<&'a str>,
    request: &'a Value,
}

fn executed_budget_result(
    result: IdempotentCommand<(BudgetPolicyView, EntityTag)>,
) -> Result<(BudgetPolicyView, EntityTag), ApplicationError> {
    match result {
        IdempotentCommand::Executed(result) => Ok(result),
        IdempotentCommand::Replay(_) => Err(ApplicationError::Internal),
    }
}

async fn mutate_budget(
    application: &Application,
    identity: &RequestIdentity,
    owner: BudgetOwner,
    if_match: Option<&str>,
    require_match: bool,
    input: UpdateBudgetPolicy,
    begin_epoch: Option<BeginBudgetEpoch>,
    operation_id: &'static str,
    idempotency: Option<BudgetIdempotency<'_>>,
) -> Result<IdempotentCommand<(BudgetPolicyView, EntityTag)>, ApplicationError> {
    if begin_epoch.is_none() && budget_update_is_empty(&input) {
        return Err(ApplicationError::Validation(
            "at least one budget field is required".to_owned(),
        ));
    }
    let organization_id = owner.organization_id();
    let mut transaction = application.store.begin().await?;
    let idempotency_handle = if let Some(idempotency) = idempotency {
        match application
            .begin_idempotent_command(
                &mut transaction,
                identity,
                &ResourceScope::Organization { organization_id },
                operation_id,
                idempotency.key,
                idempotency.request,
            )
            .await?
        {
            IdempotencyDecision::Execute(handle) => handle,
            IdempotencyDecision::Replay(replay) => {
                return Ok(IdempotentCommand::Replay(replay));
            }
        }
    } else {
        None
    };
    lock_active_organization(&mut transaction, organization_id).await?;
    let row = lock_budget(&mut transaction, owner).await?;
    if require_match {
        require_if_match(if_match, &budget_etag(owner, row.try_get("etag_token")?))?;
    }
    let desired_id: Option<Uuid> = row.try_get("desired_version_id")?;
    let mut candidate = match desired_id {
        Some(id) => Some(load_budget_input_tx(&mut transaction, id).await?),
        None => None,
    };
    let mut status = parse_policy_status(&row.try_get::<String, _>("status")?)?;
    if let Some(begin) = begin_epoch {
        validate_epoch(&begin.epoch)?;
        let value = candidate.as_mut().ok_or_else(|| {
            ApplicationError::Conflict(
                "configure an initial budget before beginning another epoch".to_owned(),
            )
        })?;
        value.epoch = begin.epoch.trim().to_owned();
        if let Some(limit) = begin.limit_cost_nanos {
            value.limit_cost_nanos = limit;
        }
        if let Some(mode) = begin.mode {
            value.mode = mode;
        }
    } else {
        apply_budget_update(&mut candidate, &mut status, input)?;
    }
    if status == CatalogStatus::Active && candidate.is_none() {
        return Err(ApplicationError::Validation(
            "active budget policy requires a version".to_owned(),
        ));
    }
    let ceilings = load_gateway_ceilings_tx(&mut transaction, application.store.installation_id())
        .await?
        .0;
    if let Some(value) = &candidate {
        validate_budget(value)?;
        validate_budget_against_ceilings(value, owner, &ceilings)?;
        if let BudgetOwner::Key { key_id, .. } = owner {
            validate_budget_against_organization_policy(
                &mut transaction,
                organization_id,
                key_id,
                value,
            )
            .await?;
        }
    }
    let policy_id: Uuid = row.try_get("id")?;
    let next_id = if let Some(value) = &candidate {
        let generation = next_budget_generation(&mut transaction, policy_id, owner).await?;
        let id = Uuid::now_v7();
        insert_budget_version(
            &mut transaction,
            policy_id,
            id,
            generation,
            owner,
            value,
            actor_value(identity)?,
        )
        .await?;
        Some(id)
    } else {
        None
    };
    let table = match owner {
        BudgetOwner::Key { .. } => "gateway_key_budget_policies",
        BudgetOwner::Origin { .. } => "organization_origin_budget_policies",
    };
    let active_id: Option<Uuid> = row.try_get("active_version_id")?;
    let direct_record_only = match (active_id, candidate.as_ref()) {
        (Some(active_id), Some(next)) if next.mode == BudgetMode::RecordOnly => {
            load_budget_mode_tx(&mut transaction, active_id).await? == BudgetMode::RecordOnly
        }
        (None, Some(next)) => next.mode == BudgetMode::RecordOnly,
        _ => false,
    };
    let published_active = if direct_record_only {
        next_id
    } else {
        active_id
    };
    sqlx::query(&format!(
        "UPDATE {table} SET desired_version_id=$2,active_version_id=$3,
                status=$4,etag_token=$5,updated_at=now() WHERE id=$1"
    ))
    .bind(policy_id)
    .bind(next_id)
    .bind(published_active)
    .bind(status.as_str())
    .bind(Uuid::now_v7())
    .execute(&mut *transaction)
    .await?;
    if !direct_record_only
        && status == CatalogStatus::Active
        && let Some(desired_version_id) = next_id
    {
        let tightening = if let Some(active_id) = active_id {
            let active = load_budget_input_tx(&mut transaction, active_id).await?;
            budget_is_tightening(&active, candidate.as_ref().expect("active budget"))?
        } else {
            false
        };
        create_policy_activation(
            &mut transaction,
            owner_policy_kind(owner),
            organization_id,
            policy_id,
            desired_version_id,
            active_id,
            tightening,
            application.config.policy_activation_timeout,
        )
        .await?;
    }
    let result = load_budget_tx(&mut transaction, owner).await?;
    application
        .complete_idempotent_command(
            &mut transaction,
            idempotency_handle,
            200,
            &result.0,
            Some(result.1.as_str()),
        )
        .await?;
    commit_policy(
        application,
        transaction,
        identity,
        Some(organization_id),
        "budget_policy",
        Some(policy_id.to_string()),
        operation_id,
    )
    .await?;
    application
        .publish_committed_runtime(&identity.request_id, operation_id)
        .await;
    Ok(IdempotentCommand::Executed(result))
}

async fn lock_gateway_ceilings(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<sqlx::postgres::PgRow, ApplicationError> {
    Ok(sqlx::query(&gateway_ceilings_query(true))
        .fetch_one(&mut **transaction)
        .await?)
}

async fn load_gateway_ceilings_pool(
    application: &Application,
) -> Result<(GatewayPolicyCeilings, EntityTag), ApplicationError> {
    let row = sqlx::query(&gateway_ceilings_query(false))
        .fetch_one(application.store.pool())
        .await?;
    gateway_ceilings_result(&row, application.store.installation_id())
}

async fn load_gateway_ceilings_tx(
    transaction: &mut Transaction<'_, Postgres>,
    installation_id: Uuid,
) -> Result<(GatewayPolicyCeilings, EntityTag), ApplicationError> {
    let row = sqlx::query(&gateway_ceilings_query(false))
        .fetch_one(&mut **transaction)
        .await?;
    gateway_ceilings_result(&row, installation_id)
}

fn gateway_ceilings_query(for_update: bool) -> String {
    format!(
        "SELECT key_budget_max_limit_cost_nanos::text AS key_budget_max,
                byok_origin_budget_max_limit_cost_nanos::text AS byok_budget_max,
                max_recovery_incident_cap_nanos::text AS incident_cap,
                max_recovery_epoch_cap_nanos::text AS epoch_cap,
                max_requests_per_minute,max_input_units_per_minute,max_concurrency,
                max_stream_seconds,allowed_budget_modes,allowed_rate_grant_modes,
                allowed_concurrency_modes,etag_token,updated_at
         FROM gateway_policy_ceilings WHERE singleton=true{}",
        if for_update { " FOR UPDATE" } else { "" }
    )
}

fn gateway_ceilings_result(
    row: &sqlx::postgres::PgRow,
    installation_id: Uuid,
) -> Result<(GatewayPolicyCeilings, EntityTag), ApplicationError> {
    Ok((
        gateway_ceilings_from_row(row)?,
        EntityTag::for_resource(
            "gateway_policy_ceilings",
            installation_id,
            row.try_get("etag_token")?,
        ),
    ))
}

fn gateway_ceilings_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<GatewayPolicyCeilings, ApplicationError> {
    Ok(GatewayPolicyCeilings {
        key_budget_max_limit_cost_nanos: row.try_get("key_budget_max")?,
        byok_origin_budget_max_limit_cost_nanos: row.try_get("byok_budget_max")?,
        max_recovery_incident_cap_nanos: row.try_get("incident_cap")?,
        max_recovery_epoch_cap_nanos: row.try_get("epoch_cap")?,
        max_requests_per_minute: u32::try_from(row.try_get::<i32, _>("max_requests_per_minute")?)
            .map_err(|_| ApplicationError::Internal)?,
        max_input_units_per_minute: u64::try_from(
            row.try_get::<i64, _>("max_input_units_per_minute")?,
        )
        .map_err(|_| ApplicationError::Internal)?,
        max_concurrency: u32::try_from(row.try_get::<i32, _>("max_concurrency")?)
            .map_err(|_| ApplicationError::Internal)?,
        max_stream_seconds: u32::try_from(row.try_get::<i32, _>("max_stream_seconds")?)
            .map_err(|_| ApplicationError::Internal)?,
        allowed_budget_modes: serde_json::from_value(row.try_get("allowed_budget_modes")?)
            .map_err(|_| ApplicationError::Internal)?,
        allowed_rate_grant_modes: serde_json::from_value(row.try_get("allowed_rate_grant_modes")?)
            .map_err(|_| ApplicationError::Internal)?,
        allowed_concurrency_modes: serde_json::from_value(
            row.try_get("allowed_concurrency_modes")?,
        )
        .map_err(|_| ApplicationError::Internal)?,
        updated_at: row.try_get("updated_at")?,
    })
}

async fn load_key_budget_pool(
    application: &Application,
    organization_id: OrganizationId,
    key_id: GatewayKeyId,
) -> Result<(BudgetPolicyView, EntityTag), ApplicationError> {
    let row = sqlx::query(&budget_query(
        BudgetOwner::Key {
            organization_id,
            key_id,
        },
        false,
    ))
    .bind(organization_id.as_uuid())
    .bind(key_id.as_uuid())
    .fetch_optional(application.store.pool())
    .await?
    .ok_or(ApplicationError::NotFound)?;
    budget_result_from_row(&row, Some(key_id), None)
}

async fn load_origin_budget_pool(
    application: &Application,
    organization_id: OrganizationId,
    origin: AccountingOrigin,
) -> Result<(BudgetPolicyView, EntityTag), ApplicationError> {
    let row = sqlx::query(&budget_query(
        BudgetOwner::Origin {
            organization_id,
            origin,
        },
        false,
    ))
    .bind(organization_id.as_uuid())
    .bind(origin_str(origin))
    .fetch_optional(application.store.pool())
    .await?
    .ok_or(ApplicationError::NotFound)?;
    budget_result_from_row(&row, None, Some(origin))
}

async fn load_budget_tx(
    transaction: &mut Transaction<'_, Postgres>,
    owner: BudgetOwner,
) -> Result<(BudgetPolicyView, EntityTag), ApplicationError> {
    let row = match owner {
        BudgetOwner::Key {
            organization_id,
            key_id,
        } => {
            sqlx::query(&budget_query(owner, false))
                .bind(organization_id.as_uuid())
                .bind(key_id.as_uuid())
                .fetch_one(&mut **transaction)
                .await?
        }
        BudgetOwner::Origin {
            organization_id,
            origin,
        } => {
            sqlx::query(&budget_query(owner, false))
                .bind(organization_id.as_uuid())
                .bind(origin_str(origin))
                .fetch_one(&mut **transaction)
                .await?
        }
    };
    match owner {
        BudgetOwner::Key { key_id, .. } => budget_result_from_row(&row, Some(key_id), None),
        BudgetOwner::Origin { origin, .. } => budget_result_from_row(&row, None, Some(origin)),
    }
}

fn budget_query(owner: BudgetOwner, for_update: bool) -> String {
    let (table, qualifier) = match owner {
        BudgetOwner::Key { .. } => (
            "gateway_key_budget_policies",
            "policy.organization_id=$1 AND policy.gateway_api_key_id=$2",
        ),
        BudgetOwner::Origin { .. } => (
            "organization_origin_budget_policies",
            "policy.organization_id=$1 AND policy.origin=$2",
        ),
    };
    format!(
        "SELECT policy.id,policy.organization_id,policy.status,policy.desired_version_id,
                policy.active_version_id,policy.etag_token,policy.updated_at,
                desired.id AS d_id,desired.generation AS d_generation,
                desired.limit_cost_nanos::text AS d_limit,
                desired.recovery_incident_cap_nanos::text AS d_incident,
                desired.recovery_epoch_cap_nanos::text AS d_epoch_cap,
                desired.epoch AS d_epoch,desired.mode AS d_mode,
                desired.estimate_policy AS d_estimate,
                desired.allowance_policy AS d_allowance,
                desired.failure_policy AS d_failure,
                desired.recovery_policy AS d_recovery,desired.created_at AS d_created_at,
                active.id AS a_id,active.generation AS a_generation,
                active.limit_cost_nanos::text AS a_limit,
                active.recovery_incident_cap_nanos::text AS a_incident,
                active.recovery_epoch_cap_nanos::text AS a_epoch_cap,
                active.epoch AS a_epoch,active.mode AS a_mode,
                active.estimate_policy AS a_estimate,
                active.allowance_policy AS a_allowance,
                active.failure_policy AS a_failure,
                active.recovery_policy AS a_recovery,active.created_at AS a_created_at
         FROM {table} policy
         LEFT JOIN budget_policy_versions desired ON desired.id=policy.desired_version_id
         LEFT JOIN budget_policy_versions active ON active.id=policy.active_version_id
         WHERE {qualifier}{}",
        if for_update {
            " FOR UPDATE OF policy"
        } else {
            ""
        }
    )
}

fn budget_result_from_row(
    row: &sqlx::postgres::PgRow,
    key_id: Option<GatewayKeyId>,
    origin: Option<AccountingOrigin>,
) -> Result<(BudgetPolicyView, EntityTag), ApplicationError> {
    let id: Uuid = row.try_get("id")?;
    let kind = if key_id.is_some() {
        "gateway_key_budget_policy"
    } else {
        "organization_origin_budget_policy"
    };
    Ok((
        BudgetPolicyView {
            id: id.to_string(),
            organization_id: OrganizationId::from_uuid(row.try_get("organization_id")?),
            gateway_api_key_id: key_id,
            origin,
            status: parse_policy_status(&row.try_get::<String, _>("status")?)?,
            desired_version: budget_version_from_prefix(row, "d")?,
            active_version: budget_version_from_prefix(row, "a")?,
            updated_at: row.try_get("updated_at")?,
        },
        EntityTag::for_resource(kind, id, row.try_get("etag_token")?),
    ))
}

fn budget_version_from_prefix(
    row: &sqlx::postgres::PgRow,
    prefix: &str,
) -> Result<Option<BudgetPolicyVersionView>, ApplicationError> {
    let id: Option<Uuid> = row.try_get(format!("{prefix}_id").as_str())?;
    let Some(id) = id else {
        return Ok(None);
    };
    Ok(Some(BudgetPolicyVersionView {
        id: id.to_string(),
        generation: u64::try_from(row.try_get::<i64, _>(format!("{prefix}_generation").as_str())?)
            .map_err(|_| ApplicationError::Internal)?,
        limit_cost_nanos: row.try_get(format!("{prefix}_limit").as_str())?,
        recovery_incident_cap_nanos: row.try_get(format!("{prefix}_incident").as_str())?,
        recovery_epoch_cap_nanos: row.try_get(format!("{prefix}_epoch_cap").as_str())?,
        epoch: row.try_get(format!("{prefix}_epoch").as_str())?,
        mode: parse_budget_mode(&row.try_get::<String, _>(format!("{prefix}_mode").as_str())?)?,
        estimate_policy: row.try_get(format!("{prefix}_estimate").as_str())?,
        allowance_policy: row.try_get(format!("{prefix}_allowance").as_str())?,
        failure_policy: row.try_get(format!("{prefix}_failure").as_str())?,
        recovery_policy: row.try_get(format!("{prefix}_recovery").as_str())?,
        created_at: row.try_get(format!("{prefix}_created_at").as_str())?,
    }))
}

async fn lock_budget(
    transaction: &mut Transaction<'_, Postgres>,
    owner: BudgetOwner,
) -> Result<sqlx::postgres::PgRow, ApplicationError> {
    match owner {
        BudgetOwner::Key {
            organization_id,
            key_id,
        } => {
            lock_gateway_key(transaction, organization_id, key_id).await?;
            Ok(sqlx::query(
                "SELECT id,desired_version_id,active_version_id,status,etag_token
                 FROM gateway_key_budget_policies
                 WHERE organization_id=$1 AND gateway_api_key_id=$2 FOR UPDATE",
            )
            .bind(organization_id.as_uuid())
            .bind(key_id.as_uuid())
            .fetch_optional(&mut **transaction)
            .await?
            .ok_or(ApplicationError::NotFound)?)
        }
        BudgetOwner::Origin {
            organization_id,
            origin,
        } => Ok(sqlx::query(
            "SELECT id,desired_version_id,active_version_id,status,etag_token
             FROM organization_origin_budget_policies
             WHERE organization_id=$1 AND origin=$2 FOR UPDATE",
        )
        .bind(organization_id.as_uuid())
        .bind(origin_str(origin))
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?),
    }
}

async fn load_budget_input_tx(
    transaction: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<GatewayBudgetInput, ApplicationError> {
    let row = sqlx::query(
        "SELECT limit_cost_nanos::text AS limit_cost_nanos,mode,epoch,
                estimate_policy,allowance_policy,failure_policy,recovery_policy
         FROM budget_policy_versions WHERE id=$1",
    )
    .bind(id)
    .fetch_one(&mut **transaction)
    .await?;
    Ok(GatewayBudgetInput {
        limit_cost_nanos: row.try_get("limit_cost_nanos")?,
        mode: parse_budget_mode(&row.try_get::<String, _>("mode")?)?,
        epoch: row.try_get("epoch")?,
        estimate_policy: row.try_get("estimate_policy")?,
        allowance_policy: row.try_get("allowance_policy")?,
        failure_policy: row.try_get("failure_policy")?,
        recovery_policy: row.try_get("recovery_policy")?,
    })
}

async fn load_limits_pool(
    application: &Application,
    organization_id: OrganizationId,
    key_id: GatewayKeyId,
) -> Result<(GatewayRequestLimitsView, EntityTag), ApplicationError> {
    ensure_gateway_key_pool(application, organization_id, key_id).await?;
    let row = sqlx::query(&limits_query(false))
        .bind(organization_id.as_uuid())
        .bind(key_id.as_uuid())
        .fetch_optional(application.store.pool())
        .await?;
    limits_result(row.as_ref(), organization_id, key_id)
}

async fn load_limits_tx(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    key_id: GatewayKeyId,
) -> Result<(GatewayRequestLimitsView, EntityTag), ApplicationError> {
    let row = sqlx::query(&limits_query(false))
        .bind(organization_id.as_uuid())
        .bind(key_id.as_uuid())
        .fetch_optional(&mut **transaction)
        .await?;
    limits_result(row.as_ref(), organization_id, key_id)
}

fn limits_query(for_update: bool) -> String {
    format!(
        "SELECT policy.id,policy.status,policy.etag_token,policy.updated_at,
                desired.epoch AS d_epoch,desired.requests_per_minute AS d_rpm,
                desired.input_units_per_minute AS d_input,desired.grant_mode AS d_grant_mode,
                desired.grant_policy AS d_grant_policy,
                desired.concurrency_mode AS d_concurrency_mode,
                desired.concurrency_limit AS d_concurrency_limit,
                desired.lease_seconds AS d_lease,desired.max_stream_seconds AS d_stream,
                active.epoch AS a_epoch,active.requests_per_minute AS a_rpm,
                active.input_units_per_minute AS a_input,active.grant_mode AS a_grant_mode,
                active.grant_policy AS a_grant_policy,
                active.concurrency_mode AS a_concurrency_mode,
                active.concurrency_limit AS a_concurrency_limit,
                active.lease_seconds AS a_lease,active.max_stream_seconds AS a_stream
         FROM gateway_key_rate_policies policy
         LEFT JOIN gateway_key_rate_policy_versions desired ON desired.id=policy.desired_version_id
         LEFT JOIN gateway_key_rate_policy_versions active ON active.id=policy.active_version_id
         WHERE policy.organization_id=$1 AND policy.gateway_api_key_id=$2{}",
        if for_update {
            " FOR UPDATE OF policy"
        } else {
            ""
        }
    )
}

fn limits_result(
    row: Option<&sqlx::postgres::PgRow>,
    organization_id: OrganizationId,
    key_id: GatewayKeyId,
) -> Result<(GatewayRequestLimitsView, EntityTag), ApplicationError> {
    let Some(row) = row else {
        return Ok((
            GatewayRequestLimitsView {
                policy_id: None,
                organization_id,
                gateway_api_key_id: key_id,
                status: None,
                desired: None,
                active: None,
                updated_at: None,
            },
            EntityTag::for_resource(
                "gateway_key_request_limits",
                key_id.as_uuid(),
                key_id.as_uuid(),
            ),
        ));
    };
    Ok((
        GatewayRequestLimitsView {
            policy_id: Some(row.try_get::<Uuid, _>("id")?.to_string()),
            organization_id,
            gateway_api_key_id: key_id,
            status: Some(parse_policy_status(&row.try_get::<String, _>("status")?)?),
            desired: rate_input_from_prefix(row, "d")?,
            active: rate_input_from_prefix(row, "a")?,
            updated_at: row.try_get("updated_at")?,
        },
        EntityTag::for_resource(
            "gateway_key_request_limits",
            key_id.as_uuid(),
            row.try_get("etag_token")?,
        ),
    ))
}

fn rate_input_from_prefix(
    row: &sqlx::postgres::PgRow,
    prefix: &str,
) -> Result<Option<GatewayRequestLimitsInput>, ApplicationError> {
    let epoch: Option<String> = row.try_get(format!("{prefix}_epoch").as_str())?;
    let Some(epoch) = epoch else {
        return Ok(None);
    };
    Ok(Some(GatewayRequestLimitsInput {
        epoch,
        requests_per_minute: u32::try_from(
            row.try_get::<i32, _>(format!("{prefix}_rpm").as_str())?,
        )
        .map_err(|_| ApplicationError::Internal)?,
        input_units_per_minute: row
            .try_get::<Option<i64>, _>(format!("{prefix}_input").as_str())?
            .map(u64::try_from)
            .transpose()
            .map_err(|_| ApplicationError::Internal)?,
        grant_mode: row.try_get(format!("{prefix}_grant_mode").as_str())?,
        grant_policy: row.try_get(format!("{prefix}_grant_policy").as_str())?,
        concurrency_mode: row.try_get(format!("{prefix}_concurrency_mode").as_str())?,
        concurrency_limit: row
            .try_get::<Option<i32>, _>(format!("{prefix}_concurrency_limit").as_str())?
            .map(u32::try_from)
            .transpose()
            .map_err(|_| ApplicationError::Internal)?,
        lease_seconds: row
            .try_get::<Option<i32>, _>(format!("{prefix}_lease").as_str())?
            .map(u32::try_from)
            .transpose()
            .map_err(|_| ApplicationError::Internal)?,
        max_stream_seconds: u32::try_from(
            row.try_get::<i32, _>(format!("{prefix}_stream").as_str())?,
        )
        .map_err(|_| ApplicationError::Internal)?,
    }))
}

async fn lock_limits_policy(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    key_id: GatewayKeyId,
) -> Result<Option<sqlx::postgres::PgRow>, ApplicationError> {
    Ok(sqlx::query(
        "SELECT id,status,desired_version_id,active_version_id,etag_token
         FROM gateway_key_rate_policies
         WHERE organization_id=$1 AND gateway_api_key_id=$2 FOR UPDATE",
    )
    .bind(organization_id.as_uuid())
    .bind(key_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await?)
}

async fn load_rate_input_tx(
    transaction: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<GatewayRequestLimitsInput, ApplicationError> {
    let row = sqlx::query(
        "SELECT epoch,requests_per_minute,input_units_per_minute,grant_mode,grant_policy,
                concurrency_mode,concurrency_limit,lease_seconds,max_stream_seconds
         FROM gateway_key_rate_policy_versions WHERE id=$1",
    )
    .bind(id)
    .fetch_one(&mut **transaction)
    .await?;
    Ok(GatewayRequestLimitsInput {
        epoch: row.try_get("epoch")?,
        requests_per_minute: u32::try_from(row.try_get::<i32, _>("requests_per_minute")?)
            .map_err(|_| ApplicationError::Internal)?,
        input_units_per_minute: row
            .try_get::<Option<i64>, _>("input_units_per_minute")?
            .map(u64::try_from)
            .transpose()
            .map_err(|_| ApplicationError::Internal)?,
        grant_mode: row.try_get("grant_mode")?,
        grant_policy: row.try_get("grant_policy")?,
        concurrency_mode: row.try_get("concurrency_mode")?,
        concurrency_limit: row
            .try_get::<Option<i32>, _>("concurrency_limit")?
            .map(u32::try_from)
            .transpose()
            .map_err(|_| ApplicationError::Internal)?,
        lease_seconds: row
            .try_get::<Option<i32>, _>("lease_seconds")?
            .map(u32::try_from)
            .transpose()
            .map_err(|_| ApplicationError::Internal)?,
        max_stream_seconds: u32::try_from(row.try_get::<i32, _>("max_stream_seconds")?)
            .map_err(|_| ApplicationError::Internal)?,
    })
}

async fn load_budget_mode_tx(
    transaction: &mut Transaction<'_, Postgres>,
    version_id: Uuid,
) -> Result<BudgetMode, ApplicationError> {
    let mode =
        sqlx::query_scalar::<_, String>("SELECT mode FROM budget_policy_versions WHERE id=$1")
            .bind(version_id)
            .fetch_one(&mut **transaction)
            .await?;
    parse_budget_mode(&mode)
}

const fn owner_policy_kind(owner: BudgetOwner) -> PolicyKind {
    match owner {
        BudgetOwner::Key { .. } => PolicyKind::GatewayKeyBudget,
        BudgetOwner::Origin { .. } => PolicyKind::OrganizationOriginBudget,
    }
}

async fn supersede_unfinished_activation(
    transaction: &mut Transaction<'_, Postgres>,
    kind: PolicyKind,
    policy_id: Uuid,
) -> Result<(), ApplicationError> {
    let unfinished = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
            SELECT 1 FROM policy_activations
            WHERE policy_kind=$1 AND policy_id=$2
              AND state NOT IN ('finalized','superseded','failed')
         )",
    )
    .bind(kind.as_str())
    .bind(policy_id)
    .fetch_one(&mut **transaction)
    .await?;
    if unfinished {
        Err(ApplicationError::Conflict(
            "the prior policy activation has not finalized".to_owned(),
        ))
    } else {
        Ok(())
    }
}

pub(super) async fn create_policy_activation(
    transaction: &mut Transaction<'_, Postgres>,
    kind: PolicyKind,
    organization_id: OrganizationId,
    policy_id: Uuid,
    desired_version_id: Uuid,
    active_version_id: Option<Uuid>,
    tightening: bool,
    activation_timeout: Duration,
) -> Result<(), ApplicationError> {
    supersede_unfinished_activation(transaction, kind, policy_id).await?;
    let version_table = match kind {
        PolicyKind::GatewayKeyBudget | PolicyKind::OrganizationOriginBudget => {
            "budget_policy_versions"
        }
        PolicyKind::GatewayKeyRequestLimits => "gateway_key_rate_policy_versions",
    };
    let desired = sqlx::query(&format!(
        "SELECT generation,epoch FROM {version_table} WHERE id=$1"
    ))
    .bind(desired_version_id)
    .fetch_one(&mut **transaction)
    .await?;
    let (active_epoch, active_generation) = if let Some(active_version_id) = active_version_id {
        let active = sqlx::query(&format!(
            "SELECT generation,epoch FROM {version_table} WHERE id=$1"
        ))
        .bind(active_version_id)
        .fetch_one(&mut **transaction)
        .await?;
        (
            Some(active.try_get::<String, _>("epoch")?),
            Some(active.try_get::<i64, _>("generation")?),
        )
    } else {
        (None, None)
    };
    let seconds =
        i64::try_from(activation_timeout.as_secs()).map_err(|_| ApplicationError::Internal)?;
    sqlx::query(
        "INSERT INTO policy_activations(
            id,organization_id,policy_kind,policy_id,desired_epoch,desired_version_id,
            desired_generation,active_epoch,active_version_id,active_generation,
            candidate_fence,state,tightening_deadline
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'desired',
                   CASE WHEN $12 THEN now() + make_interval(secs => $13) ELSE NULL END)",
    )
    .bind(Uuid::now_v7())
    .bind(organization_id.as_uuid())
    .bind(kind.as_str())
    .bind(policy_id)
    .bind(desired.try_get::<String, _>("epoch")?)
    .bind(desired_version_id)
    .bind(desired.try_get::<i64, _>("generation")?)
    .bind(active_epoch)
    .bind(active_version_id)
    .bind(active_generation)
    .bind(Uuid::now_v7())
    .bind(tightening)
    .bind(seconds)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_budget_version(
    transaction: &mut Transaction<'_, Postgres>,
    policy_id: Uuid,
    id: Uuid,
    generation: i64,
    owner: BudgetOwner,
    input: &GatewayBudgetInput,
    actor: Value,
) -> Result<(), ApplicationError> {
    let limit = parse_nanos(&input.limit_cost_nanos, "limit_cost_nanos")?;
    let ceilings = sqlx::query(
        "SELECT max_recovery_incident_cap_nanos::text AS incident_cap,
                max_recovery_epoch_cap_nanos::text AS epoch_cap
         FROM gateway_policy_ceilings WHERE singleton=true",
    )
    .fetch_one(&mut **transaction)
    .await?;
    let maximum_incident = parse_nanos(
        &ceilings.try_get::<String, _>("incident_cap")?,
        "max_recovery_incident_cap_nanos",
    )?;
    let maximum_epoch = parse_nanos(
        &ceilings.try_get::<String, _>("epoch_cap")?,
        "max_recovery_epoch_cap_nanos",
    )?;
    let incident_cap = (limit / 100).min(maximum_incident);
    let epoch_cap = (limit / 20).min(maximum_epoch);
    let (kind, key_policy, origin_policy) = match owner {
        BudgetOwner::Key { .. } => ("gateway_key_budget", Some(policy_id), None),
        BudgetOwner::Origin { .. } => ("organization_origin_budget", None, Some(policy_id)),
    };
    sqlx::query(
        "INSERT INTO budget_policy_versions(
            id,policy_kind,gateway_key_budget_policy_id,
            organization_origin_budget_policy_id,generation,limit_cost_nanos,
            recovery_incident_cap_nanos,recovery_epoch_cap_nanos,epoch,mode,
            estimate_policy,allowance_policy,failure_policy,recovery_policy,
            created_by_principal)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
    )
    .bind(id)
    .bind(kind)
    .bind(key_policy)
    .bind(origin_policy)
    .bind(generation)
    .bind(limit.to_string())
    .bind(incident_cap.to_string())
    .bind(epoch_cap.to_string())
    .bind(input.epoch.trim())
    .bind(budget_mode_str(input.mode))
    .bind(&input.estimate_policy)
    .bind(&input.allowance_policy)
    .bind(&input.failure_policy)
    .bind(&input.recovery_policy)
    .bind(actor)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_rate_version(
    transaction: &mut Transaction<'_, Postgres>,
    policy_id: Uuid,
    id: Uuid,
    generation: i64,
    input: &GatewayRequestLimitsInput,
    actor: Value,
) -> Result<(), ApplicationError> {
    sqlx::query(
        "INSERT INTO gateway_key_rate_policy_versions(
            id,rate_policy_id,generation,epoch,requests_per_minute,
            input_units_per_minute,grant_mode,grant_policy,concurrency_mode,
            concurrency_limit,lease_seconds,max_stream_seconds,created_by_principal)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(id)
    .bind(policy_id)
    .bind(generation)
    .bind(input.epoch.trim())
    .bind(i32::try_from(input.requests_per_minute).map_err(|_| ApplicationError::Internal)?)
    .bind(
        input
            .input_units_per_minute
            .map(i64::try_from)
            .transpose()
            .map_err(|_| ApplicationError::Internal)?,
    )
    .bind(&input.grant_mode)
    .bind(&input.grant_policy)
    .bind(&input.concurrency_mode)
    .bind(
        input
            .concurrency_limit
            .map(i32::try_from)
            .transpose()
            .map_err(|_| ApplicationError::Internal)?,
    )
    .bind(
        input
            .lease_seconds
            .map(i32::try_from)
            .transpose()
            .map_err(|_| ApplicationError::Internal)?,
    )
    .bind(i32::try_from(input.max_stream_seconds).map_err(|_| ApplicationError::Internal)?)
    .bind(actor)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn next_budget_generation(
    transaction: &mut Transaction<'_, Postgres>,
    policy_id: Uuid,
    owner: BudgetOwner,
) -> Result<i64, ApplicationError> {
    let column = match owner {
        BudgetOwner::Key { .. } => "gateway_key_budget_policy_id",
        BudgetOwner::Origin { .. } => "organization_origin_budget_policy_id",
    };
    Ok(sqlx::query_scalar(&format!(
        "SELECT COALESCE(max(generation),0)+1 FROM budget_policy_versions WHERE {column}=$1"
    ))
    .bind(policy_id)
    .fetch_one(&mut **transaction)
    .await?)
}

async fn next_rate_generation(
    transaction: &mut Transaction<'_, Postgres>,
    policy_id: Uuid,
) -> Result<i64, ApplicationError> {
    Ok(sqlx::query_scalar(
        "SELECT COALESCE(max(generation),0)+1
         FROM gateway_key_rate_policy_versions WHERE rate_policy_id=$1",
    )
    .bind(policy_id)
    .fetch_one(&mut **transaction)
    .await?)
}

async fn lock_active_organization(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
) -> Result<(), ApplicationError> {
    let status =
        sqlx::query_scalar::<_, String>("SELECT status FROM organizations WHERE id=$1 FOR UPDATE")
            .bind(organization_id.as_uuid())
            .fetch_optional(&mut **transaction)
            .await?
            .ok_or(ApplicationError::NotFound)?;
    if status == "active" {
        Ok(())
    } else {
        Err(ApplicationError::Forbidden)
    }
}

async fn lock_gateway_key(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    key_id: GatewayKeyId,
) -> Result<(), ApplicationError> {
    sqlx::query("SELECT id FROM gateway_api_keys WHERE organization_id=$1 AND id=$2 FOR UPDATE")
        .bind(organization_id.as_uuid())
        .bind(key_id.as_uuid())
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
    Ok(())
}

async fn ensure_gateway_key_pool(
    application: &Application,
    organization_id: OrganizationId,
    key_id: GatewayKeyId,
) -> Result<(), ApplicationError> {
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM gateway_api_keys WHERE organization_id=$1 AND id=$2)",
    )
    .bind(organization_id.as_uuid())
    .bind(key_id.as_uuid())
    .fetch_one(application.store.pool())
    .await?;
    if exists {
        Ok(())
    } else {
        Err(ApplicationError::NotFound)
    }
}

fn apply_budget_update(
    candidate: &mut Option<GatewayBudgetInput>,
    status: &mut CatalogStatus,
    input: UpdateBudgetPolicy,
) -> Result<(), ApplicationError> {
    if candidate.is_none() {
        let UpdateField::Value(epoch) = &input.epoch else {
            return Err(ApplicationError::Validation(
                "the first budget update requires epoch".to_owned(),
            ));
        };
        let UpdateField::Value(limit) = &input.limit_cost_nanos else {
            return Err(ApplicationError::Validation(
                "the first budget update requires limit_cost_nanos".to_owned(),
            ));
        };
        let UpdateField::Value(mode) = &input.mode else {
            return Err(ApplicationError::Validation(
                "the first budget update requires mode".to_owned(),
            ));
        };
        *candidate = Some(GatewayBudgetInput {
            limit_cost_nanos: limit.clone(),
            mode: *mode,
            epoch: epoch.clone(),
            estimate_policy: json!({}),
            allowance_policy: json!({}),
            failure_policy: json!({}),
            recovery_policy: json!({}),
        });
    }
    let value = candidate.as_mut().ok_or(ApplicationError::Internal)?;
    apply_required(&mut value.epoch, input.epoch, "epoch")?;
    apply_required(
        &mut value.limit_cost_nanos,
        input.limit_cost_nanos,
        "limit_cost_nanos",
    )?;
    apply_required(&mut value.mode, input.mode, "mode")?;
    apply_required(
        &mut value.estimate_policy,
        input.estimate_policy,
        "estimate_policy",
    )?;
    apply_required(
        &mut value.allowance_policy,
        input.allowance_policy,
        "allowance_policy",
    )?;
    apply_required(
        &mut value.failure_policy,
        input.failure_policy,
        "failure_policy",
    )?;
    apply_required(
        &mut value.recovery_policy,
        input.recovery_policy,
        "recovery_policy",
    )?;
    apply_required(status, input.status, "status")?;
    Ok(())
}

fn validate_budget(value: &GatewayBudgetInput) -> Result<(), ApplicationError> {
    let limit = parse_nanos(&value.limit_cost_nanos, "limit_cost_nanos")?;
    if limit == 0 {
        return Err(ApplicationError::Validation(
            "budget limit must be positive".to_owned(),
        ));
    }
    validate_epoch(&value.epoch)?;
    let estimate: BudgetEstimatePolicy = typed_policy(&value.estimate_policy, "estimate_policy")?;
    let allowance: BudgetAllowancePolicy =
        typed_policy(&value.allowance_policy, "allowance_policy")?;
    let _: BudgetFailurePolicy = typed_policy(&value.failure_policy, "failure_policy")?;
    let _: BudgetRecoveryPolicy = typed_policy(&value.recovery_policy, "recovery_policy")?;
    if estimate.input_units_per_byte == 0
        || estimate.unknown_mode == UnknownEstimateMode::FixedUnknownReservation
            && estimate.fixed_unknown_reservation_nanos.is_none()
        || estimate.unknown_mode == UnknownEstimateMode::RequireEstimate
            && estimate.fixed_unknown_reservation_nanos.is_some()
        || estimate
            .fixed_unknown_reservation_nanos
            .is_some_and(|reservation| reservation == 0 || reservation > limit)
        || allowance.max_slice_nanos == 0
        || allowance.max_slice_nanos > limit
        || allowance.low_watermark_nanos > allowance.max_slice_nanos
        || allowance.grant_seconds == 0
        || allowance.grant_seconds > 3600
        || allowance.emergency_reserve_nanos > limit
    {
        return Err(ApplicationError::Validation(
            "budget policy values are invalid or exceed the finite limit".to_owned(),
        ));
    }
    Ok(())
}

fn budget_is_tightening(
    active: &GatewayBudgetInput,
    desired: &GatewayBudgetInput,
) -> Result<bool, ApplicationError> {
    if active.epoch != desired.epoch {
        return Ok(false);
    }
    if active.mode == BudgetMode::RecordOnly {
        return Ok(desired.mode == BudgetMode::Enforce);
    }
    if desired.mode == BudgetMode::RecordOnly {
        return Ok(false);
    }
    let active_estimate: BudgetEstimatePolicy =
        typed_policy(&active.estimate_policy, "active estimate_policy")?;
    let desired_estimate: BudgetEstimatePolicy =
        typed_policy(&desired.estimate_policy, "desired estimate_policy")?;
    let active_failure: BudgetFailurePolicy =
        typed_policy(&active.failure_policy, "active failure_policy")?;
    let desired_failure: BudgetFailurePolicy =
        typed_policy(&desired.failure_policy, "desired failure_policy")?;
    let active_recovery: BudgetRecoveryPolicy =
        typed_policy(&active.recovery_policy, "active recovery_policy")?;
    let desired_recovery: BudgetRecoveryPolicy =
        typed_policy(&desired.recovery_policy, "desired recovery_policy")?;
    Ok(
        parse_nanos(&desired.limit_cost_nanos, "desired limit_cost_nanos")?
            < parse_nanos(&active.limit_cost_nanos, "active limit_cost_nanos")?
            || active_estimate.unknown_mode == UnknownEstimateMode::FixedUnknownReservation
                && desired_estimate.unknown_mode == UnknownEstimateMode::RequireEstimate
            || active_failure.coordination_failure_mode == CoordinationFailureMode::BoundedLocal
                && desired_failure.coordination_failure_mode == CoordinationFailureMode::Deny
            || !active_recovery.require_verified_state_loss
                && desired_recovery.require_verified_state_loss,
    )
}

fn request_limits_are_tightening(
    active: &GatewayRequestLimitsInput,
    desired: &GatewayRequestLimitsInput,
) -> bool {
    if active.epoch != desired.epoch {
        return false;
    }
    desired.requests_per_minute < active.requests_per_minute
        || optional_limit_is_tightening(
            active.input_units_per_minute,
            desired.input_units_per_minute,
        )
        || active.grant_mode == "local_grants" && desired.grant_mode == "strict"
        || optional_limit_is_tightening(active.concurrency_limit, desired.concurrency_limit)
        || active.concurrency_mode.as_deref() != Some("strict")
            && desired.concurrency_mode.as_deref() == Some("strict")
        || desired.max_stream_seconds < active.max_stream_seconds
}

fn optional_limit_is_tightening<T: Ord>(active: Option<T>, desired: Option<T>) -> bool {
    match (active, desired) {
        (None, Some(_)) => true,
        (Some(active), Some(desired)) => desired < active,
        _ => false,
    }
}

fn typed_policy<T: serde::de::DeserializeOwned>(
    value: &Value,
    name: &str,
) -> Result<T, ApplicationError> {
    serde_json::from_value(value.clone())
        .map_err(|error| ApplicationError::Validation(format!("{name} is invalid: {error}")))
}

async fn organization_gateway_policy_sections(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    key_id: GatewayKeyId,
) -> Result<(Value, Value), ApplicationError> {
    let row = sqlx::query(
        "SELECT key.issuance_policy_class,policy.policy
         FROM gateway_api_keys key
         JOIN organization_api_key_policies policy
           ON policy.organization_id=key.organization_id
         WHERE key.organization_id=$1 AND key.id=$2",
    )
    .bind(organization_id.as_uuid())
    .bind(key_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    let class: String = row.try_get("issuance_policy_class")?;
    let policy: Value = row.try_get("policy")?;
    let global = policy
        .get("gateway")
        .cloned()
        .ok_or(ApplicationError::Internal)?;
    let class_name = match class.as_str() {
        "standard" => "gateway",
        "member_self_service" => "gateway_member_self_service",
        _ => return Err(ApplicationError::Internal),
    };
    let class = policy
        .get(class_name)
        .cloned()
        .ok_or(ApplicationError::Internal)?;
    Ok((global, class))
}

async fn validate_budget_against_organization_policy(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    key_id: GatewayKeyId,
    value: &GatewayBudgetInput,
) -> Result<(), ApplicationError> {
    let (global, class) =
        organization_gateway_policy_sections(transaction, organization_id, key_id).await?;
    let limit = parse_nanos(&value.limit_cost_nanos, "limit_cost_nanos")?;
    for section in [&global, &class] {
        let maximum = section["budget"]["max_limit_cost_nanos"]
            .as_str()
            .and_then(|value| value.parse::<u128>().ok())
            .ok_or(ApplicationError::Internal)?;
        let modes =
            serde_json::from_value::<Vec<BudgetMode>>(section["budget"]["allowed_modes"].clone())
                .map_err(|_| ApplicationError::Internal)?;
        if section["enabled"] != true || limit > maximum || !modes.contains(&value.mode) {
            return Err(ApplicationError::Validation(
                "budget exceeds the current organization Gateway-key policy".to_owned(),
            ));
        }
    }
    Ok(())
}

async fn validate_request_limits_against_organization_policy(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    key_id: GatewayKeyId,
    value: &GatewayRequestLimitsInput,
) -> Result<(), ApplicationError> {
    let (global, class) =
        organization_gateway_policy_sections(transaction, organization_id, key_id).await?;
    for section in [&global, &class] {
        let max_requests = section["rate"]["max_requests_per_minute"]
            .as_u64()
            .ok_or(ApplicationError::Internal)?;
        let max_input = section["rate"]["max_input_units_per_minute"]
            .as_u64()
            .ok_or(ApplicationError::Internal)?;
        let max_concurrency = section["concurrency"]["max_limit"]
            .as_u64()
            .ok_or(ApplicationError::Internal)?;
        let modes =
            serde_json::from_value::<Vec<String>>(section["concurrency"]["allowed_modes"].clone())
                .map_err(|_| ApplicationError::Internal)?;
        if section["enabled"] != true
            || u64::from(value.requests_per_minute) > max_requests
            || value
                .input_units_per_minute
                .is_some_and(|limit| limit > max_input)
            || value
                .concurrency_limit
                .is_some_and(|limit| u64::from(limit) > max_concurrency)
            || value
                .concurrency_mode
                .as_ref()
                .is_some_and(|mode| !modes.contains(mode))
        {
            return Err(ApplicationError::Validation(
                "request limits exceed the current organization Gateway-key policy".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_budget_against_ceilings(
    value: &GatewayBudgetInput,
    owner: BudgetOwner,
    ceilings: &GatewayPolicyCeilings,
) -> Result<(), ApplicationError> {
    let maximum = match owner {
        BudgetOwner::Key { .. } => parse_nanos(
            &ceilings.key_budget_max_limit_cost_nanos,
            "key budget ceiling",
        )?,
        BudgetOwner::Origin {
            origin: AccountingOrigin::OrganizationByok,
            ..
        } => parse_nanos(
            &ceilings.byok_origin_budget_max_limit_cost_nanos,
            "BYOK budget ceiling",
        )?,
        BudgetOwner::Origin {
            origin: AccountingOrigin::SystemProvided,
            ..
        } => u128::MAX,
    };
    if parse_nanos(&value.limit_cost_nanos, "limit_cost_nanos")? > maximum
        || !ceilings.allowed_budget_modes.contains(&value.mode)
    {
        return Err(ApplicationError::Validation(
            "budget exceeds deployment gateway policy ceilings".to_owned(),
        ));
    }
    Ok(())
}

fn validate_request_limits(value: &GatewayRequestLimitsInput) -> Result<(), ApplicationError> {
    validate_epoch(&value.epoch)?;
    let grant: RateGrantPolicy = typed_policy(&value.grant_policy, "grant_policy")?;
    let strict_concurrency = value.concurrency_mode.as_deref() == Some("strict");
    if value.requests_per_minute == 0
        || grant.max_request_tokens == 0
        || grant.max_request_tokens > value.requests_per_minute
        || !(1..=3600).contains(&grant.grant_seconds)
        || !matches!(value.grant_mode.as_str(), "local_grants" | "strict")
        || !(1..=86_400).contains(&value.max_stream_seconds)
        || value.concurrency_mode.is_some() != value.concurrency_limit.is_some()
        || value
            .concurrency_mode
            .as_deref()
            .is_some_and(|mode| !matches!(mode, "approximate" | "strict"))
        || strict_concurrency
            && value
                .lease_seconds
                .is_none_or(|lease| lease <= value.max_stream_seconds || lease > 90_000)
        || !strict_concurrency && value.lease_seconds.is_some()
    {
        return Err(ApplicationError::Validation(
            "request limits are invalid or incomplete".to_owned(),
        ));
    }
    Ok(())
}

fn validate_request_limits_against_ceilings(
    value: &GatewayRequestLimitsInput,
    ceilings: &GatewayPolicyCeilings,
) -> Result<(), ApplicationError> {
    if value.requests_per_minute > ceilings.max_requests_per_minute
        || value
            .input_units_per_minute
            .is_some_and(|limit| limit > ceilings.max_input_units_per_minute)
        || value
            .concurrency_limit
            .is_some_and(|limit| limit > ceilings.max_concurrency)
        || value.max_stream_seconds > ceilings.max_stream_seconds
        || !ceilings
            .allowed_rate_grant_modes
            .contains(&value.grant_mode)
        || value
            .concurrency_mode
            .as_ref()
            .is_some_and(|mode| !ceilings.allowed_concurrency_modes.contains(mode))
    {
        return Err(ApplicationError::Validation(
            "request limits exceed deployment gateway policy ceilings".to_owned(),
        ));
    }
    Ok(())
}

fn validate_gateway_ceilings(value: &GatewayPolicyCeilings) -> Result<(), ApplicationError> {
    let key = parse_nanos(
        &value.key_budget_max_limit_cost_nanos,
        "key_budget_max_limit_cost_nanos",
    )?;
    let byok = parse_nanos(
        &value.byok_origin_budget_max_limit_cost_nanos,
        "byok_origin_budget_max_limit_cost_nanos",
    )?;
    let incident = parse_nanos(
        &value.max_recovery_incident_cap_nanos,
        "max_recovery_incident_cap_nanos",
    )?;
    let epoch = parse_nanos(
        &value.max_recovery_epoch_cap_nanos,
        "max_recovery_epoch_cap_nanos",
    )?;
    if key == 0
        || byok == 0
        || incident > epoch
        || value.max_requests_per_minute == 0
        || value.max_input_units_per_minute == 0
        || value.max_concurrency == 0
        || !(1..=86_400).contains(&value.max_stream_seconds)
        || value.allowed_budget_modes.is_empty()
        || value.allowed_budget_modes.len()
            != value
                .allowed_budget_modes
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
        || !closed_string_set(&value.allowed_rate_grant_modes, &["local_grants", "strict"])
        || !closed_string_set(&value.allowed_concurrency_modes, &["approximate", "strict"])
    {
        return Err(ApplicationError::Validation(
            "gateway policy ceilings are invalid".to_owned(),
        ));
    }
    Ok(())
}

async fn ensure_active_policies_fit_ceilings(
    transaction: &mut Transaction<'_, Postgres>,
    value: &GatewayPolicyCeilings,
) -> Result<(), ApplicationError> {
    let key_max = parse_nanos(&value.key_budget_max_limit_cost_nanos, "key budget ceiling")?;
    let byok_max = parse_nanos(
        &value.byok_origin_budget_max_limit_cost_nanos,
        "BYOK budget ceiling",
    )?;
    let budget_modes = value
        .allowed_budget_modes
        .iter()
        .map(|mode| budget_mode_str(*mode).to_owned())
        .collect::<Vec<_>>();
    let budget_violations = sqlx::query_scalar::<_, i64>(
        "SELECT
            (SELECT count(*) FROM gateway_key_budget_policies policy
             JOIN budget_policy_versions version
               ON version.id IN (policy.active_version_id,policy.desired_version_id)
             WHERE version.limit_cost_nanos>$1::numeric OR NOT (version.mode=ANY($3)))
          + (SELECT count(*) FROM organization_origin_budget_policies policy
             JOIN budget_policy_versions version
               ON version.id IN (policy.active_version_id,policy.desired_version_id)
             WHERE (policy.origin='organization_byok' AND version.limit_cost_nanos>$2::numeric)
                OR NOT (version.mode=ANY($3)))",
    )
    .bind(key_max.to_string())
    .bind(byok_max.to_string())
    .bind(&budget_modes)
    .fetch_one(&mut **transaction)
    .await?;
    let rate_violations = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM gateway_key_rate_policies policy
         JOIN gateway_key_rate_policy_versions version
           ON version.id IN (policy.active_version_id,policy.desired_version_id)
         WHERE version.requests_per_minute>$1
            OR version.input_units_per_minute>$2
            OR version.concurrency_limit>$3
            OR version.max_stream_seconds>$4
            OR NOT (version.grant_mode=ANY($5))
            OR (version.concurrency_mode IS NOT NULL
                AND NOT (version.concurrency_mode=ANY($6)))",
    )
    .bind(i64::from(value.max_requests_per_minute))
    .bind(i64::try_from(value.max_input_units_per_minute).map_err(|_| ApplicationError::Internal)?)
    .bind(i64::from(value.max_concurrency))
    .bind(i64::from(value.max_stream_seconds))
    .bind(&value.allowed_rate_grant_modes)
    .bind(&value.allowed_concurrency_modes)
    .fetch_one(&mut **transaction)
    .await?;
    if budget_violations == 0 && rate_violations == 0 {
        Ok(())
    } else {
        Err(ApplicationError::Conflict(
            "existing desired or active policies exceed the proposed gateway ceilings".to_owned(),
        ))
    }
}

async fn commit_policy(
    application: &Application,
    transaction: Transaction<'_, Postgres>,
    identity: &RequestIdentity,
    organization_id: Option<OrganizationId>,
    resource_kind: &str,
    resource_id: Option<String>,
    operation_id: &'static str,
) -> Result<(), ApplicationError> {
    application
        .store
        .commit_command(
            transaction,
            &AuditRecord {
                actor: Some(Actor::from(&identity.principal)),
                authentication_evidence: json!({
                    "method": identity.principal.authentication_method
                }),
                organization_id,
                target_resource_kind: resource_kind.to_owned(),
                target_resource_id: resource_id,
                operation_id: operation_id.to_owned(),
                outcome: "accepted",
                request_id: identity.request_id.clone(),
                changed_fields: vec!["policy".to_owned()],
                safe_details: json!({}),
            },
            Some(&RuntimeEvent {
                event_kind: "gateway_policy.changed".to_owned(),
                affected_scope: json!({"organization_id":organization_id}),
                security_tightening: true,
            }),
        )
        .await?;
    Ok(())
}

fn authorize_system_policy(
    application: &Application,
    identity: &RequestIdentity,
    write: bool,
) -> Result<(), ApplicationError> {
    application.authorize(
        identity,
        &[if write {
            ManagementScope::Write
        } else {
            ManagementScope::Read
        }],
        AuthorizationTarget::System {
            capability: Capability::ManageGatewayCatalog,
        },
    )
}

fn authorize_organization_budget(
    application: &Application,
    identity: &RequestIdentity,
    organization_id: OrganizationId,
    write: bool,
) -> Result<(), ApplicationError> {
    application.authorize(
        identity,
        &[if write {
            ManagementScope::Write
        } else {
            ManagementScope::Read
        }],
        AuthorizationTarget::Organization {
            organization_id,
            capability: Capability::ConfigureBudgets,
        },
    )
}

fn authorize_provider_budget(
    application: &Application,
    identity: &RequestIdentity,
    organization_id: OrganizationId,
    origin: AccountingOrigin,
    write: bool,
) -> Result<(), ApplicationError> {
    if origin == AccountingOrigin::SystemProvided && write {
        authorize_system_policy(application, identity, true)
    } else {
        authorize_organization_budget(application, identity, organization_id, write)
    }
}

fn require_if_match(provided: Option<&str>, current: &EntityTag) -> Result<(), ApplicationError> {
    match provided {
        None => Err(ApplicationError::PreconditionRequired),
        Some(value) if current.matches(value) => Ok(()),
        Some(_) => Err(ApplicationError::Stale {
            current_etag: Some(current.to_string()),
        }),
    }
}

fn apply_required<T>(
    target: &mut T,
    field: UpdateField<T>,
    name: &str,
) -> Result<(), ApplicationError> {
    match field {
        UpdateField::Omitted => Ok(()),
        UpdateField::Null => Err(ApplicationError::Validation(format!(
            "{name} cannot be null"
        ))),
        UpdateField::Value(value) => {
            *target = value;
            Ok(())
        }
    }
}

fn budget_etag(owner: BudgetOwner, token: Uuid) -> EntityTag {
    match owner {
        BudgetOwner::Key { key_id, .. } => {
            EntityTag::for_resource("gateway_key_budget_policy", key_id.as_uuid(), token)
        }
        BudgetOwner::Origin {
            organization_id,
            origin,
        } => EntityTag::for_resource(
            match origin {
                AccountingOrigin::SystemProvided => "system_provider_budget",
                AccountingOrigin::OrganizationByok => "byok_provider_budget",
            },
            organization_id.as_uuid(),
            token,
        ),
    }
}

fn parse_nanos(value: &str, name: &str) -> Result<u128, ApplicationError> {
    value.parse().map_err(|_| {
        ApplicationError::Validation(format!("{name} must be a base-10 non-negative integer"))
    })
}

fn validate_epoch(value: &str) -> Result<(), ApplicationError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 160 || value.chars().any(char::is_control) {
        Err(ApplicationError::Validation(
            "epoch must contain 1 to 160 printable characters".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn parse_budget_mode(value: &str) -> Result<BudgetMode, ApplicationError> {
    match value {
        "enforce" => Ok(BudgetMode::Enforce),
        "record_only" => Ok(BudgetMode::RecordOnly),
        _ => Err(ApplicationError::Internal),
    }
}

const fn budget_mode_str(value: BudgetMode) -> &'static str {
    match value {
        BudgetMode::Enforce => "enforce",
        BudgetMode::RecordOnly => "record_only",
    }
}

fn parse_policy_status(value: &str) -> Result<CatalogStatus, ApplicationError> {
    match value {
        "active" => Ok(CatalogStatus::Active),
        "suspended" | "disabled" => Ok(CatalogStatus::Disabled),
        _ => Err(ApplicationError::Internal),
    }
}

const fn origin_str(origin: AccountingOrigin) -> &'static str {
    match origin {
        AccountingOrigin::SystemProvided => "system_provided",
        AccountingOrigin::OrganizationByok => "organization_byok",
    }
}

fn origin_operation(origin: AccountingOrigin, begin_epoch: bool) -> &'static str {
    match (origin, begin_epoch) {
        (AccountingOrigin::SystemProvided, false) => "organization.provider_budgets.system.update",
        (AccountingOrigin::SystemProvided, true) => {
            "organization.provider_budgets.system.begin_epoch"
        }
        (AccountingOrigin::OrganizationByok, false) => "organization.provider_budgets.byok.update",
        (AccountingOrigin::OrganizationByok, true) => {
            "organization.provider_budgets.byok.begin_epoch"
        }
    }
}

fn actor_value(identity: &RequestIdentity) -> Result<Value, ApplicationError> {
    serde_json::to_value(Actor::from(&identity.principal)).map_err(|_| ApplicationError::Internal)
}

fn closed_string_set(values: &[String], allowed: &[&str]) -> bool {
    !values.is_empty()
        && values.len() == values.iter().collect::<BTreeSet<_>>().len()
        && values.iter().all(|value| allowed.contains(&value.as_str()))
}

fn budget_update_is_empty(value: &UpdateBudgetPolicy) -> bool {
    value.epoch.is_omitted()
        && value.limit_cost_nanos.is_omitted()
        && value.mode.is_omitted()
        && value.estimate_policy.is_omitted()
        && value.allowance_policy.is_omitted()
        && value.failure_policy.is_omitted()
        && value.recovery_policy.is_omitted()
        && value.status.is_omitted()
}

fn ceiling_update_is_empty(value: &UpdateGatewayPolicyCeilings) -> bool {
    value.key_budget_max_limit_cost_nanos.is_omitted()
        && value.byok_origin_budget_max_limit_cost_nanos.is_omitted()
        && value.max_recovery_incident_cap_nanos.is_omitted()
        && value.max_recovery_epoch_cap_nanos.is_omitted()
        && value.max_requests_per_minute.is_omitted()
        && value.max_input_units_per_minute.is_omitted()
        && value.max_concurrency.is_omitted()
        && value.max_stream_seconds.is_omitted()
        && value.allowed_budget_modes.is_omitted()
        && value.allowed_rate_grant_modes.is_omitted()
        && value.allowed_concurrency_modes.is_omitted()
}

#[derive(Clone, Debug)]
struct ActivationWork {
    id: Uuid,
    candidate: PolicyCandidate,
    state: String,
    active_version_id: Option<Uuid>,
    active_epoch: Option<String>,
    active_generation: Option<i64>,
    prior_cutoff_at: Option<chrono::DateTime<Utc>>,
}

impl Application {
    pub fn start_policy_activation_worker(self: &Arc<Self>) {
        if self.coordinator.is_none() {
            return;
        }
        let application = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(250));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                if let Err(error) = application.reconcile_policy_activations().await {
                    tracing::error!(%error, "policy activation reconciliation failed");
                }
                if let Err(error) = application.reconcile_coordinator_recoveries(32).await {
                    tracing::error!(%error, "coordinator recovery reconciliation failed");
                }
            }
        });
    }

    pub(crate) async fn reconcile_policy_activations(&self) -> Result<u64, ApplicationError> {
        let Some(coordinator) = self.coordinator.as_ref() else {
            return Err(ApplicationError::DependencyUnavailable);
        };
        let rows = sqlx::query(
            "SELECT activation.id,activation.organization_id,activation.policy_kind,
                    activation.policy_id,activation.desired_epoch,
                    activation.desired_version_id,activation.desired_generation,
                    COALESCE((
                        SELECT MAX(recovery.recovery_generation)
                        FROM coordinator_recoveries recovery
                        WHERE recovery.policy_kind=activation.policy_kind
                          AND recovery.policy_id=activation.policy_id
                          AND recovery.epoch=activation.desired_epoch
                    ),0) AS desired_recovery_generation,
                    activation.candidate_fence,activation.state,
                    activation.active_version_id,activation.active_epoch,
                    activation.active_generation,activation.prior_cutoff_at,
                    budget.mode AS budget_mode,
                    budget.limit_cost_nanos::text AS budget_limit_cost_nanos,
                    budget.allowance_policy AS budget_allowance_policy,
                    rate.requests_per_minute,rate.input_units_per_minute,
                    rate.grant_mode,rate.grant_policy,rate.concurrency_mode,
                    rate.concurrency_limit,rate.lease_seconds,rate.max_stream_seconds
             FROM policy_activations activation
             LEFT JOIN budget_policy_versions budget
               ON budget.id=activation.desired_version_id
              AND activation.policy_kind IN ('gateway_key_budget','organization_origin_budget')
             LEFT JOIN gateway_key_rate_policy_versions rate
               ON rate.id=activation.desired_version_id
              AND activation.policy_kind='gateway_key_request_limits'
             WHERE activation.state NOT IN ('finalized','superseded','failed')
             ORDER BY activation.created_at,activation.id LIMIT 32",
        )
        .fetch_all(self.store.pool())
        .await?;
        let mut reconciled = 0_u64;
        for row in rows {
            let work = activation_work_from_row(&row)?;
            if let Err(error) = self.reconcile_policy_activation(coordinator, &work).await {
                tracing::warn!(activation_id=%work.id, %error, "policy activation remains pending");
            } else {
                reconciled = reconciled
                    .checked_add(1)
                    .ok_or(ApplicationError::Internal)?;
            }
        }
        Ok(reconciled)
    }

    async fn reconcile_policy_activation(
        &self,
        coordinator: &RedisCoordinator,
        work: &ActivationWork,
    ) -> Result<(), ApplicationError> {
        match work.state.as_str() {
            "desired" => {
                coordinator
                    .stage_policy(&work.candidate)
                    .await
                    .map_err(coordinator_error)?;
                persist_activation_state(self, work, "desired", "coordinator_staged", None).await?;
            }
            "coordinator_staged" => {
                coordinator
                    .arm_policy(&work.candidate)
                    .await
                    .map_err(coordinator_error)?;
                persist_activation_state(
                    self,
                    work,
                    "coordinator_staged",
                    "coordinator_armed",
                    None,
                )
                .await?;
            }
            "coordinator_armed" => {
                coordinator
                    .activate_policy(&work.candidate)
                    .await
                    .map_err(coordinator_error)?;
                activate_policy_durably(self, work).await?;
            }
            "active" => {
                let cutoff = work.prior_cutoff_at.ok_or(ApplicationError::Internal)?;
                let cutoff_unix_ms = u64::try_from(cutoff.timestamp_millis())
                    .map_err(|_| ApplicationError::Internal)?;
                coordinator
                    .begin_policy_retirement(&work.candidate, cutoff_unix_ms)
                    .await
                    .map_err(coordinator_error)?;
                if cutoff <= Utc::now() {
                    coordinator
                        .finalize_policy(&work.candidate)
                        .await
                        .map_err(coordinator_error)?;
                    persist_activation_state(self, work, "active", "finalized", None).await?;
                }
            }
            _ => return Err(ApplicationError::Internal),
        }
        Ok(())
    }
}

fn activation_work_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<ActivationWork, ApplicationError> {
    let kind = match row.try_get::<String, _>("policy_kind")?.as_str() {
        "gateway_key_budget" => PolicyKind::GatewayKeyBudget,
        "organization_origin_budget" => PolicyKind::OrganizationOriginBudget,
        "gateway_key_request_limits" => PolicyKind::GatewayKeyRequestLimits,
        _ => return Err(ApplicationError::Internal),
    };
    let desired_version_id: Uuid = row.try_get("desired_version_id")?;
    let config = match kind {
        PolicyKind::GatewayKeyBudget | PolicyKind::OrganizationOriginBudget => {
            let allowance: BudgetAllowancePolicy =
                serde_json::from_value(row.try_get::<Value, _>("budget_allowance_policy")?)
                    .map_err(|_| ApplicationError::Internal)?;
            PolicyCoordinatorConfig::Budget {
                version_id: desired_version_id,
                mode: row.try_get("budget_mode")?,
                limit_cost_nanos: row.try_get("budget_limit_cost_nanos")?,
                max_slice_nanos: allowance.max_slice_nanos.to_string(),
                grant_seconds: allowance.grant_seconds,
            }
        }
        PolicyKind::GatewayKeyRequestLimits => {
            let grant: RateGrantPolicy =
                serde_json::from_value(row.try_get::<Value, _>("grant_policy")?)
                    .map_err(|_| ApplicationError::Internal)?;
            PolicyCoordinatorConfig::RequestLimits {
                version_id: desired_version_id,
                requests_per_minute: u32::try_from(row.try_get::<i32, _>("requests_per_minute")?)
                    .map_err(|_| ApplicationError::Internal)?,
                input_units_per_minute: row
                    .try_get::<Option<i64>, _>("input_units_per_minute")?
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| ApplicationError::Internal)?,
                grant_mode: row.try_get("grant_mode")?,
                max_request_tokens: grant.max_request_tokens,
                grant_seconds: grant.grant_seconds,
                concurrency_mode: row.try_get("concurrency_mode")?,
                concurrency_limit: row
                    .try_get::<Option<i32>, _>("concurrency_limit")?
                    .map(u32::try_from)
                    .transpose()
                    .map_err(|_| ApplicationError::Internal)?,
                lease_seconds: row
                    .try_get::<Option<i32>, _>("lease_seconds")?
                    .map(u32::try_from)
                    .transpose()
                    .map_err(|_| ApplicationError::Internal)?,
                max_stream_seconds: u32::try_from(row.try_get::<i32, _>("max_stream_seconds")?)
                    .map_err(|_| ApplicationError::Internal)?,
            }
        }
    };
    Ok(ActivationWork {
        id: row.try_get("id")?,
        candidate: PolicyCandidate {
            organization_id: OrganizationId::from_uuid(row.try_get("organization_id")?),
            kind,
            policy_id: row.try_get("policy_id")?,
            desired_epoch: row.try_get("desired_epoch")?,
            desired_version_id,
            desired_generation: u64::try_from(row.try_get::<i64, _>("desired_generation")?)
                .map_err(|_| ApplicationError::Internal)?,
            desired_recovery_generation: u64::try_from(
                row.try_get::<i64, _>("desired_recovery_generation")?,
            )
            .map_err(|_| ApplicationError::Internal)?,
            fence: row.try_get("candidate_fence")?,
            config,
        },
        state: row.try_get("state")?,
        active_version_id: row.try_get("active_version_id")?,
        active_epoch: row.try_get("active_epoch")?,
        active_generation: row.try_get("active_generation")?,
        prior_cutoff_at: row.try_get("prior_cutoff_at")?,
    })
}

async fn persist_activation_state(
    application: &Application,
    work: &ActivationWork,
    expected: &str,
    next: &str,
    prior_cutoff_at: Option<chrono::DateTime<Utc>>,
) -> Result<(), ApplicationError> {
    let mut transaction = application.store.begin().await?;
    let changed = sqlx::query(
        "UPDATE policy_activations SET state=$4,prior_cutoff_at=COALESCE($5,prior_cutoff_at),
                updated_at=now()
         WHERE id=$1 AND desired_generation=$2 AND candidate_fence=$3 AND state=$6",
    )
    .bind(work.id)
    .bind(i64::try_from(work.candidate.desired_generation).map_err(|_| ApplicationError::Internal)?)
    .bind(work.candidate.fence)
    .bind(next)
    .bind(prior_cutoff_at)
    .bind(expected)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(ApplicationError::Conflict(
            "policy activation candidate changed while the coordinator was running".to_owned(),
        ));
    }
    let runtime_event = (next == "finalized").then(|| RuntimeEvent {
        event_kind: "gateway_policy.activation_finalized".to_owned(),
        affected_scope: json!({
            "organization_id": work.candidate.organization_id,
            "policy_kind": work.candidate.kind.as_str(),
            "policy_id": work.candidate.policy_id,
        }),
        security_tightening: false,
    });
    application
        .store
        .commit_command(
            transaction,
            &AuditRecord {
                actor: None,
                authentication_evidence: json!({"method":"internal_worker"}),
                organization_id: Some(work.candidate.organization_id),
                target_resource_kind: "policy_activation".to_owned(),
                target_resource_id: Some(work.id.to_string()),
                operation_id: format!("system.workers.policy_activation.{next}"),
                outcome: "accepted",
                request_id: format!("worker-policy-{}-{next}", work.id),
                changed_fields: vec!["state".to_owned()],
                safe_details: json!({
                    "from": expected,
                    "to": next,
                    "policy_kind": work.candidate.kind.as_str(),
                    "generation": work.candidate.desired_generation,
                }),
            },
            runtime_event.as_ref(),
        )
        .await?;
    if next == "finalized" {
        application
            .publish_committed_runtime(
                &format!("worker-policy-{}-finalized", work.id),
                "system.workers.policy_activation.finalized",
            )
            .await;
    }
    Ok(())
}

async fn activate_policy_durably(
    application: &Application,
    work: &ActivationWork,
) -> Result<(), ApplicationError> {
    let mut transaction = application.store.begin().await?;
    let table = match work.candidate.kind {
        PolicyKind::GatewayKeyBudget => "gateway_key_budget_policies",
        PolicyKind::OrganizationOriginBudget => "organization_origin_budget_policies",
        PolicyKind::GatewayKeyRequestLimits => "gateway_key_rate_policies",
    };
    let changed = sqlx::query(&format!(
        "UPDATE {table} SET active_version_id=desired_version_id,updated_at=now()
         WHERE id=$1 AND desired_version_id=(
            SELECT desired_version_id FROM policy_activations
            WHERE id=$2 AND state='coordinator_armed' AND candidate_fence=$3
         )"
    ))
    .bind(work.candidate.policy_id)
    .bind(work.id)
    .bind(work.candidate.fence)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(ApplicationError::Conflict(
            "policy desired pointer changed before durable activation".to_owned(),
        ));
    }
    let grace = chrono::Duration::from_std(application.config.policy_retirement_grace)
        .map_err(|_| ApplicationError::Internal)?;
    let cutoff = Utc::now() + grace;
    let activation_changed = sqlx::query(
        "UPDATE policy_activations SET
            active_epoch=desired_epoch,active_version_id=desired_version_id,
            active_generation=desired_generation,
            prior_epoch=$4,prior_version_id=$5,prior_generation=$6,
            state='active',prior_cutoff_at=$7,updated_at=now()
         WHERE id=$1 AND desired_generation=$2 AND candidate_fence=$3
           AND state='coordinator_armed'",
    )
    .bind(work.id)
    .bind(i64::try_from(work.candidate.desired_generation).map_err(|_| ApplicationError::Internal)?)
    .bind(work.candidate.fence)
    .bind(&work.active_epoch)
    .bind(work.active_version_id)
    .bind(work.active_generation)
    .bind(cutoff)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if activation_changed != 1 {
        return Err(ApplicationError::Conflict(
            "policy activation fence changed before durable publication".to_owned(),
        ));
    }
    application
        .store
        .commit_command(
            transaction,
            &AuditRecord {
                actor: None,
                authentication_evidence: json!({"method":"internal_worker"}),
                organization_id: Some(work.candidate.organization_id),
                target_resource_kind: "policy_activation".to_owned(),
                target_resource_id: Some(work.id.to_string()),
                operation_id: "system.workers.policy_activation.activate".to_owned(),
                outcome: "accepted",
                request_id: format!("worker-policy-{}", work.id),
                changed_fields: vec!["active_version".to_owned()],
                safe_details: json!({
                    "policy_kind": work.candidate.kind.as_str(),
                    "generation": work.candidate.desired_generation,
                    "epoch": work.candidate.desired_epoch,
                }),
            },
            Some(&RuntimeEvent {
                event_kind: "gateway_policy.activated".to_owned(),
                affected_scope: json!({
                    "organization_id":work.candidate.organization_id,
                    "policy_kind":work.candidate.kind.as_str(),
                    "policy_id":work.candidate.policy_id,
                }),
                security_tightening: true,
            }),
        )
        .await?;
    application
        .publish_committed_runtime(
            &format!("worker-policy-{}", work.id),
            "system.workers.policy_activation.activate",
        )
        .await;
    Ok(())
}

fn coordinator_error(error: crate::adapters::coordinator::CoordinatorError) -> ApplicationError {
    tracing::warn!(%error, "Redis coordinator operation failed");
    ApplicationError::DependencyUnavailable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_ceilings_are_closed_and_finite() {
        let mut value = GatewayPolicyCeilings {
            key_budget_max_limit_cost_nanos: "1000".to_owned(),
            byok_origin_budget_max_limit_cost_nanos: "1000".to_owned(),
            max_recovery_incident_cap_nanos: "10".to_owned(),
            max_recovery_epoch_cap_nanos: "50".to_owned(),
            max_requests_per_minute: 100,
            max_input_units_per_minute: 1000,
            max_concurrency: 10,
            max_stream_seconds: 3600,
            allowed_budget_modes: vec![BudgetMode::Enforce, BudgetMode::RecordOnly],
            allowed_rate_grant_modes: vec!["local_grants".to_owned(), "strict".to_owned()],
            allowed_concurrency_modes: vec!["approximate".to_owned(), "strict".to_owned()],
            updated_at: Utc::now(),
        };
        assert!(validate_gateway_ceilings(&value).is_ok());
        value.max_recovery_incident_cap_nanos = "100".to_owned();
        value.max_recovery_epoch_cap_nanos = "10".to_owned();
        assert!(validate_gateway_ceilings(&value).is_err());
    }
}
