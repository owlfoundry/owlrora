use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use sqlx::{Executor, Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::{
    adapters::postgres::{AuditRecord, RuntimeEvent},
    domain::{
        Actor, BudgetAllowancePolicy, BudgetEstimatePolicy, BudgetFailurePolicy, BudgetMode,
        BudgetPolicyId, BudgetPolicyVersionId, BudgetRecoveryPolicy, Capability, GatewayKeyId,
        LlmScopeSet, ManagementScope, MaterialVersionId, OrganizationId, OrganizationRole,
        Principal, RouteId, UnknownEstimateMode, gateway_key_digest, generate_gateway_key,
    },
};

use super::{
    Application, ApplicationError, AuthorizationTarget, CreateGatewayApiKey, EntityTag,
    GatewayApiKey, GatewayBudgetInput, KeyStatus, OneTimeGatewayApiKey, Page, RequestIdentity,
    RotateGatewayApiKey, UpdateField, UpdateGatewayApiKey,
};

impl Application {
    pub async fn list_gateway_api_keys(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<GatewayApiKey>, ApplicationError> {
        authorize_gateway_keys(
            self,
            identity,
            organization_id,
            Capability::ReadGatewayKeys,
            false,
        )?;
        let family = format!("gateway_api_keys:{organization_id}");
        let (cursor, limit) = super::resources::page_parameters(&family, cursor, limit)?;
        let rows = sqlx::query(
            "SELECT key.id,key.organization_id,key.issuance_policy_class,key.created_by_principal,
                    key.name,key.scopes,key.status,key.expires_at,key.budget_policy_id,key.created_at,key.updated_at,
                    key.etag_token,
                    current_secret.id AS current_secret_version_id,
                    overlap_secret.overlap_until,
                    COALESCE((SELECT jsonb_agg(route_id ORDER BY route_id)
                      FROM gateway_api_key_routes routes WHERE routes.gateway_api_key_id=key.id),'[]') AS route_ids
             FROM gateway_api_keys key
             JOIN gateway_api_key_secret_versions current_secret
               ON current_secret.gateway_api_key_id=key.id AND current_secret.state='current'
             LEFT JOIN gateway_api_key_secret_versions overlap_secret
               ON overlap_secret.gateway_api_key_id=key.id AND overlap_secret.state='overlap'
             WHERE key.organization_id=$1 AND ($2::uuid IS NULL OR key.id>$2)
             ORDER BY key.id LIMIT $3",
        )
        .bind(organization_id.as_uuid())
        .bind(cursor)
        .bind(i64::from(limit) + 1)
        .fetch_all(self.store.pool())
        .await?;
        super::resources::page_from_rows(rows, limit, &family, gateway_key_from_row)
    }

    pub async fn get_gateway_api_key(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        key_id: GatewayKeyId,
    ) -> Result<(GatewayApiKey, EntityTag), ApplicationError> {
        authorize_gateway_keys(
            self,
            identity,
            organization_id,
            Capability::ReadGatewayKeys,
            false,
        )?;
        load_gateway_key(self.store.pool(), organization_id, key_id).await
    }

    pub async fn create_gateway_api_key(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        input: CreateGatewayApiKey,
    ) -> Result<(OneTimeGatewayApiKey, EntityTag), ApplicationError> {
        let member_self_service =
            matches!(identity.principal.principal, Principal::LocalUser { .. })
                && !identity.principal.effective_system_administrator
                && local_role(identity, organization_id) == Some(OrganizationRole::Member);
        authorize_gateway_keys(
            self,
            identity,
            organization_id,
            if member_self_service {
                Capability::ReadOrganization
            } else {
                Capability::CreateGatewayKeys
            },
            true,
        )?;
        self.authorize(
            identity,
            &[ManagementScope::Secrets],
            AuthorizationTarget::CurrentPrincipal,
        )?;
        validate_name(&input.name)?;
        validate_routes(&input.route_ids)?;
        validate_budget_input(&input.budget)?;
        if input.expires_at.is_some_and(|value| value <= Utc::now()) {
            return Err(ApplicationError::Validation(
                "expires_at must be in the future".to_owned(),
            ));
        }
        let class = if member_self_service {
            "member_self_service"
        } else {
            "standard"
        };
        let issued_at = Utc::now();
        let key_id = GatewayKeyId::new();
        let secret_id = MaterialVersionId::new();
        let budget_id = BudgetPolicyId::new();
        let budget_version_id = BudgetPolicyVersionId::new();
        let material = generate_gateway_key();
        let raw = material.expose_once();
        let lookup = material.lookup_text();
        let digest = gateway_key_digest(&material);
        let mut transaction = self.store.begin().await?;
        lock_organization(&mut transaction, organization_id).await?;
        let policy = load_policy(&mut transaction, organization_id).await?;
        validate_gateway_destination(
            &policy,
            class,
            &input.scopes,
            &input.route_ids,
            &input.budget,
            input.expires_at,
            issued_at,
        )?;
        validate_budget_against_deployment_ceilings(&mut transaction, &input.budget).await?;
        enforce_active_limit(&mut transaction, organization_id, class, &policy).await?;
        validate_route_authority(&mut transaction, organization_id, &input.route_ids).await?;
        let expires_at = effective_expiry(&policy, class, input.expires_at, issued_at)?;
        let actor = actor_value(identity)?;
        sqlx::query(
            "INSERT INTO gateway_api_keys(
                id,organization_id,issuance_policy_class,created_by_principal,name,key_prefix,
                lookup_id,scopes,budget_policy_id,status,expires_at,etag_token,created_at,updated_at
             ) VALUES ($1,$2,$3,$4,$5,'owlrora_llm_v1',$6,$7,$8,'active',$9,$10,$11,$11)",
        )
        .bind(key_id.as_uuid())
        .bind(organization_id.as_uuid())
        .bind(class)
        .bind(actor.clone())
        .bind(input.name.trim())
        .bind(&lookup)
        .bind(scopes_value(&input.scopes))
        .bind(budget_id.as_uuid())
        .bind(expires_at)
        .bind(Uuid::now_v7())
        .bind(issued_at)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_conflict)?;
        sqlx::query(
            "INSERT INTO gateway_api_key_secret_versions(
                id,gateway_api_key_id,lookup_id,secret_digest,state
             ) VALUES ($1,$2,$3,$4,'current')",
        )
        .bind(secret_id.as_uuid())
        .bind(key_id.as_uuid())
        .bind(lookup)
        .bind(digest.to_vec())
        .execute(&mut *transaction)
        .await?;
        for route_id in &input.route_ids {
            sqlx::query(
                "INSERT INTO gateway_api_key_routes(organization_id,gateway_api_key_id,route_id)
                 VALUES ($1,$2,$3)",
            )
            .bind(organization_id.as_uuid())
            .bind(key_id.as_uuid())
            .bind(route_id.as_uuid())
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "INSERT INTO gateway_key_budget_policies(
                id,organization_id,gateway_api_key_id,desired_version_id,active_version_id,
                status,etag_token
             ) VALUES ($1,$2,$3,$4,$6,'active',$5)",
        )
        .bind(budget_id.as_uuid())
        .bind(organization_id.as_uuid())
        .bind(key_id.as_uuid())
        .bind(budget_version_id.as_uuid())
        .bind(Uuid::now_v7())
        .bind((input.budget.mode == BudgetMode::RecordOnly).then_some(budget_version_id.as_uuid()))
        .execute(&mut *transaction)
        .await?;
        insert_budget_version(
            &mut transaction,
            budget_id,
            budget_version_id,
            &input.budget,
            actor,
        )
        .await?;
        if input.budget.mode == BudgetMode::Enforce {
            super::gateway_policies::create_policy_activation(
                &mut transaction,
                crate::domain::PolicyKind::GatewayKeyBudget,
                organization_id,
                budget_id.as_uuid(),
                budget_version_id.as_uuid(),
                None,
                false,
                self.config.policy_activation_timeout,
            )
            .await?;
        }
        let result = load_gateway_key(&mut *transaction, organization_id, key_id).await?;
        commit_key(
            self,
            transaction,
            identity,
            organization_id,
            key_id,
            "organization.gateway_api_keys.create",
            &[
                "name",
                "scopes",
                "route_ids",
                "budget_policy_id",
                "expires_at",
            ],
            false,
        )
        .await?;
        self.publish_committed_runtime(
            &identity.request_id,
            "organization.gateway_api_keys.create",
        )
        .await;
        Ok((
            OneTimeGatewayApiKey {
                gateway_api_key: result.0,
                key: raw,
            },
            result.1,
        ))
    }

    pub async fn update_gateway_api_key(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        key_id: GatewayKeyId,
        if_match: Option<&str>,
        input: UpdateGatewayApiKey,
    ) -> Result<(GatewayApiKey, EntityTag), ApplicationError> {
        authorize_gateway_keys(
            self,
            identity,
            organization_id,
            Capability::ManageGatewayKeys,
            true,
        )?;
        require_nonempty([
            input.name.is_omitted(),
            input.scopes.is_omitted(),
            input.route_ids.is_omitted(),
            input.status.is_omitted(),
            input.expires_at.is_omitted(),
        ])?;
        let mut transaction = self.store.begin().await?;
        lock_organization(&mut transaction, organization_id).await?;
        let policy = load_policy(&mut transaction, organization_id).await?;
        let row = sqlx::query(
            "SELECT name,issuance_policy_class,scopes,status,expires_at,created_at,etag_token
             FROM gateway_api_keys WHERE organization_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(organization_id.as_uuid())
        .bind(key_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        require_if_match(
            if_match,
            &EntityTag::for_resource(
                "gateway_api_key",
                key_id.as_uuid(),
                row.try_get("etag_token")?,
            ),
        )?;
        let class: String = row.try_get("issuance_policy_class")?;
        let mut name: String = row.try_get("name")?;
        let current_scopes = scopes_from_value(row.try_get("scopes")?)?;
        let mut scopes = current_scopes.clone();
        let current_routes = load_route_ids(&mut transaction, key_id).await?;
        let mut routes = current_routes.clone();
        let current_status: String = row.try_get("status")?;
        let mut status = current_status.clone();
        let current_expiry: Option<DateTime<Utc>> = row.try_get("expires_at")?;
        let mut expires_at = current_expiry;
        let issued_at: DateTime<Utc> = row.try_get("created_at")?;
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
        match input.scopes {
            UpdateField::Omitted => {}
            UpdateField::Null => return Err(null_error("scopes")),
            UpdateField::Value(value) => {
                scopes = value;
                changed.push("scopes");
            }
        }
        match input.route_ids {
            UpdateField::Omitted => {}
            UpdateField::Null => return Err(null_error("route_ids")),
            UpdateField::Value(value) => {
                validate_routes(&value)?;
                routes = value;
                changed.push("route_ids");
            }
        }
        match input.status {
            UpdateField::Omitted => {}
            UpdateField::Null => return Err(null_error("status")),
            UpdateField::Value(value) => {
                if current_status == "revoked" && value != KeyStatus::Revoked {
                    return Err(ApplicationError::Conflict(
                        "a revoked gateway key cannot be reactivated".to_owned(),
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
            || !routes.is_subset(&current_routes)
            || (current_status != "active" && status == "active")
            || expiry_extended(current_expiry, expires_at);
        let budget = load_budget_input(&mut transaction, key_id).await?;
        if authority_increase {
            validate_gateway_destination(
                &policy, &class, &scopes, &routes, &budget, expires_at, issued_at,
            )?;
            validate_route_authority(&mut transaction, organization_id, &routes).await?;
        }
        sqlx::query(
            "UPDATE gateway_api_keys SET name=$3,scopes=$4,status=$5,expires_at=$6,
                    etag_token=$7,updated_at=now() WHERE organization_id=$1 AND id=$2",
        )
        .bind(organization_id.as_uuid())
        .bind(key_id.as_uuid())
        .bind(name)
        .bind(scopes_value(&scopes))
        .bind(&status)
        .bind(expires_at)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_conflict)?;
        if routes != current_routes {
            sqlx::query("DELETE FROM gateway_api_key_routes WHERE gateway_api_key_id=$1")
                .bind(key_id.as_uuid())
                .execute(&mut *transaction)
                .await?;
            for route_id in &routes {
                sqlx::query(
                    "INSERT INTO gateway_api_key_routes(organization_id,gateway_api_key_id,route_id)
                     VALUES ($1,$2,$3)",
                )
                .bind(organization_id.as_uuid())
                .bind(key_id.as_uuid())
                .bind(route_id.as_uuid())
                .execute(&mut *transaction)
                .await?;
            }
        }
        let tightening = status != "active"
            || !scopes.is_superset(&current_scopes)
            || routes.is_subset(&current_routes) && routes != current_routes
            || expiry_shortened(current_expiry, expires_at);
        let result = load_gateway_key(&mut *transaction, organization_id, key_id).await?;
        commit_key(
            self,
            transaction,
            identity,
            organization_id,
            key_id,
            "organization.gateway_api_keys.update",
            &changed,
            tightening,
        )
        .await?;
        self.publish_committed_runtime(
            &identity.request_id,
            "organization.gateway_api_keys.update",
        )
        .await;
        Ok(result)
    }

    pub async fn rotate_gateway_api_key(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        key_id: GatewayKeyId,
        if_match: Option<&str>,
        input: RotateGatewayApiKey,
    ) -> Result<(OneTimeGatewayApiKey, EntityTag), ApplicationError> {
        authorize_gateway_keys(
            self,
            identity,
            organization_id,
            Capability::ManageGatewayKeys,
            true,
        )?;
        self.authorize(
            identity,
            &[ManagementScope::Secrets],
            AuthorizationTarget::CurrentPrincipal,
        )?;
        let mut transaction = self.store.begin().await?;
        lock_organization(&mut transaction, organization_id).await?;
        let policy = load_policy(&mut transaction, organization_id).await?;
        let row = sqlx::query(
            "SELECT issuance_policy_class,status,etag_token FROM gateway_api_keys
             WHERE organization_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(organization_id.as_uuid())
        .bind(key_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        require_if_match(
            if_match,
            &EntityTag::for_resource(
                "gateway_api_key",
                key_id.as_uuid(),
                row.try_get("etag_token")?,
            ),
        )?;
        if row.try_get::<String, _>("status")? != "active" {
            return Err(ApplicationError::Conflict(
                "only an active gateway key can be rotated".to_owned(),
            ));
        }
        let class: String = row.try_get("issuance_policy_class")?;
        let max_overlap = policy_section(&policy, &class)?["max_overlap_seconds"]
            .as_u64()
            .ok_or(ApplicationError::Internal)?;
        if u64::from(input.overlap_seconds) > max_overlap {
            return Err(ApplicationError::Validation(
                "overlap_seconds exceeds the current gateway policy".to_owned(),
            ));
        }
        let material = generate_gateway_key();
        let raw = material.expose_once();
        let lookup = material.lookup_text();
        let digest = gateway_key_digest(&material);
        let secret_id = MaterialVersionId::new();
        // A later rotation invalidates any older overlap before the current version enters the
        // unique overlap slot. This ordering also permits rotation after an expired overlap.
        sqlx::query(
            "UPDATE gateway_api_key_secret_versions SET state='retired',overlap_until=NULL,
                    retired_at=now() WHERE gateway_api_key_id=$1 AND state='overlap'",
        )
        .bind(key_id.as_uuid())
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE gateway_api_key_secret_versions
             SET state=CASE WHEN $2=0 THEN 'retired' ELSE 'overlap' END,
                 overlap_until=CASE WHEN $2=0 THEN NULL ELSE now()+make_interval(secs=>$2) END,
                 retired_at=CASE WHEN $2=0 THEN now() ELSE NULL END
             WHERE gateway_api_key_id=$1 AND state='current'",
        )
        .bind(key_id.as_uuid())
        .bind(i32::try_from(input.overlap_seconds).map_err(|_| ApplicationError::Internal)?)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO gateway_api_key_secret_versions(
                id,gateway_api_key_id,lookup_id,secret_digest,state
             ) VALUES ($1,$2,$3,$4,'current')",
        )
        .bind(secret_id.as_uuid())
        .bind(key_id.as_uuid())
        .bind(&lookup)
        .bind(digest.to_vec())
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE gateway_api_keys SET lookup_id=$3,etag_token=$4,updated_at=now()
             WHERE organization_id=$1 AND id=$2",
        )
        .bind(organization_id.as_uuid())
        .bind(key_id.as_uuid())
        .bind(lookup)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let result = load_gateway_key(&mut *transaction, organization_id, key_id).await?;
        commit_key(
            self,
            transaction,
            identity,
            organization_id,
            key_id,
            "organization.gateway_api_keys.rotate",
            &["lookup_id", "secret_versions", "overlap_until"],
            false,
        )
        .await?;
        self.publish_committed_runtime(
            &identity.request_id,
            "organization.gateway_api_keys.rotate",
        )
        .await;
        Ok((
            OneTimeGatewayApiKey {
                gateway_api_key: result.0,
                key: raw,
            },
            result.1,
        ))
    }
}

async fn load_gateway_key<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    organization_id: OrganizationId,
    key_id: GatewayKeyId,
) -> Result<(GatewayApiKey, EntityTag), ApplicationError> {
    let row = sqlx::query(
        "SELECT key.id,key.organization_id,key.issuance_policy_class,key.created_by_principal,
                key.name,key.scopes,key.status,key.expires_at,key.budget_policy_id,key.created_at,key.updated_at,
                key.etag_token,current_secret.id AS current_secret_version_id,
                overlap_secret.overlap_until,
                COALESCE((SELECT jsonb_agg(route_id ORDER BY route_id)
                  FROM gateway_api_key_routes routes WHERE routes.gateway_api_key_id=key.id),'[]') AS route_ids
         FROM gateway_api_keys key
         JOIN gateway_api_key_secret_versions current_secret
           ON current_secret.gateway_api_key_id=key.id AND current_secret.state='current'
         LEFT JOIN gateway_api_key_secret_versions overlap_secret
           ON overlap_secret.gateway_api_key_id=key.id AND overlap_secret.state='overlap'
         WHERE key.organization_id=$1 AND key.id=$2",
    )
    .bind(organization_id.as_uuid())
    .bind(key_id.as_uuid())
    .fetch_optional(executor)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    let etag = EntityTag::for_resource(
        "gateway_api_key",
        key_id.as_uuid(),
        row.try_get("etag_token")?,
    );
    Ok((gateway_key_from_row(row)?, etag))
}

fn gateway_key_from_row(row: sqlx::postgres::PgRow) -> Result<GatewayApiKey, ApplicationError> {
    let id = GatewayKeyId::from_uuid(row.try_get("id")?);
    let route_ids = serde_json::from_value::<Vec<RouteId>>(row.try_get("route_ids")?)
        .map_err(|_| ApplicationError::Internal)?
        .into_iter()
        .collect();
    Ok(GatewayApiKey {
        id,
        organization_id: OrganizationId::from_uuid(row.try_get("organization_id")?),
        issuance_policy_class: row.try_get("issuance_policy_class")?,
        created_by_principal: row.try_get("created_by_principal")?,
        name: row.try_get("name")?,
        scopes: scopes_from_value(row.try_get("scopes")?)?,
        route_ids,
        status: parse_status(&row.try_get::<String, _>("status")?)?,
        expires_at: row.try_get("expires_at")?,
        budget_policy_id: row.try_get::<Uuid, _>("budget_policy_id")?.to_string(),
        current_secret_version_id: MaterialVersionId::from_uuid(
            row.try_get("current_secret_version_id")?,
        ),
        overlap_until: row.try_get("overlap_until")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

async fn insert_budget_version(
    transaction: &mut Transaction<'_, Postgres>,
    policy_id: BudgetPolicyId,
    version_id: BudgetPolicyVersionId,
    input: &GatewayBudgetInput,
    actor: Value,
) -> Result<(), ApplicationError> {
    let limit = parse_budget_limit(&input.limit_cost_nanos)?;
    let ceilings = sqlx::query(
        "SELECT max_recovery_incident_cap_nanos::text AS incident_cap,
                max_recovery_epoch_cap_nanos::text AS epoch_cap
         FROM gateway_policy_ceilings WHERE singleton=true",
    )
    .fetch_one(&mut **transaction)
    .await?;
    let maximum_incident = ceilings
        .try_get::<String, _>("incident_cap")?
        .parse::<u128>()
        .map_err(|_| ApplicationError::Internal)?;
    let maximum_epoch = ceilings
        .try_get::<String, _>("epoch_cap")?
        .parse::<u128>()
        .map_err(|_| ApplicationError::Internal)?;
    let incident_cap = (limit / 100).min(maximum_incident);
    let epoch_cap = (limit / 20).min(maximum_epoch);
    sqlx::query(
        "INSERT INTO budget_policy_versions(
            id,policy_kind,gateway_key_budget_policy_id,generation,limit_cost_nanos,
            recovery_incident_cap_nanos,recovery_epoch_cap_nanos,epoch,mode,
            estimate_policy,allowance_policy,failure_policy,recovery_policy,created_by_principal
         ) VALUES (
            $1,'gateway_key_budget',$2,1,$3::numeric,$4::numeric,$5::numeric,
            $6,$7,$8,$9,$10,$11,$12
         )",
    )
    .bind(version_id.as_uuid())
    .bind(policy_id.as_uuid())
    .bind(limit.to_string())
    .bind(incident_cap.to_string())
    .bind(epoch_cap.to_string())
    .bind(input.epoch.trim())
    .bind(match input.mode {
        BudgetMode::Enforce => "enforce",
        BudgetMode::RecordOnly => "record_only",
    })
    .bind(&input.estimate_policy)
    .bind(&input.allowance_policy)
    .bind(&input.failure_policy)
    .bind(&input.recovery_policy)
    .bind(actor)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn load_budget_input(
    transaction: &mut Transaction<'_, Postgres>,
    key_id: GatewayKeyId,
) -> Result<GatewayBudgetInput, ApplicationError> {
    let row = sqlx::query(
        "SELECT version.limit_cost_nanos::text AS limit_cost_nanos,version.mode,version.epoch,
                version.estimate_policy,version.allowance_policy,version.failure_policy,
                version.recovery_policy
         FROM gateway_key_budget_policies policy
         JOIN budget_policy_versions version
           ON version.id=COALESCE(policy.active_version_id,policy.desired_version_id)
         WHERE policy.gateway_api_key_id=$1",
    )
    .bind(key_id.as_uuid())
    .fetch_one(&mut **transaction)
    .await?;
    Ok(GatewayBudgetInput {
        limit_cost_nanos: row.try_get("limit_cost_nanos")?,
        mode: match row.try_get::<String, _>("mode")?.as_str() {
            "enforce" => BudgetMode::Enforce,
            "record_only" => BudgetMode::RecordOnly,
            _ => return Err(ApplicationError::Internal),
        },
        epoch: row.try_get("epoch")?,
        estimate_policy: row.try_get("estimate_policy")?,
        allowance_policy: row.try_get("allowance_policy")?,
        failure_policy: row.try_get("failure_policy")?,
        recovery_policy: row.try_get("recovery_policy")?,
    })
}

async fn load_route_ids(
    transaction: &mut Transaction<'_, Postgres>,
    key_id: GatewayKeyId,
) -> Result<BTreeSet<RouteId>, ApplicationError> {
    let values = sqlx::query_scalar::<_, Uuid>(
        "SELECT route_id FROM gateway_api_key_routes WHERE gateway_api_key_id=$1",
    )
    .bind(key_id.as_uuid())
    .fetch_all(&mut **transaction)
    .await?;
    Ok(values.into_iter().map(RouteId::from_uuid).collect())
}

async fn validate_route_authority(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    route_ids: &BTreeSet<RouteId>,
) -> Result<(), ApplicationError> {
    for route_id in route_ids {
        let visible = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                SELECT 1 FROM model_routes route
                WHERE route.id=$2 AND (
                    (route.resource_scope_kind='organization' AND route.organization_id=$1)
                    OR (route.resource_scope_kind='deployment' AND EXISTS (
                        SELECT 1 FROM organization_route_grants grant_row
                        WHERE grant_row.organization_id=$1 AND grant_row.route_id=route.id
                          AND grant_row.status='active'
                    ))
                )
             )",
        )
        .bind(organization_id.as_uuid())
        .bind(route_id.as_uuid())
        .fetch_one(&mut **transaction)
        .await?;
        if !visible {
            return Err(ApplicationError::Validation(format!(
                "route {route_id} is not available to this organization"
            )));
        }
    }
    Ok(())
}

async fn validate_budget_against_deployment_ceilings(
    transaction: &mut Transaction<'_, Postgres>,
    budget: &GatewayBudgetInput,
) -> Result<(), ApplicationError> {
    let row = sqlx::query(
        "SELECT key_budget_max_limit_cost_nanos::text AS maximum,
                allowed_budget_modes
         FROM gateway_policy_ceilings WHERE singleton=true",
    )
    .fetch_one(&mut **transaction)
    .await?;
    let maximum = row
        .try_get::<String, _>("maximum")?
        .parse::<u128>()
        .map_err(|_| ApplicationError::Internal)?;
    let modes = serde_json::from_value::<Vec<BudgetMode>>(row.try_get("allowed_budget_modes")?)
        .map_err(|_| ApplicationError::Internal)?;
    if parse_budget_limit(&budget.limit_cost_nanos)? > maximum || !modes.contains(&budget.mode) {
        return Err(ApplicationError::Validation(
            "budget exceeds deployment gateway policy ceilings".to_owned(),
        ));
    }
    Ok(())
}

fn validate_gateway_destination(
    policy: &Value,
    class: &str,
    scopes: &LlmScopeSet,
    routes: &BTreeSet<RouteId>,
    budget: &GatewayBudgetInput,
    expires_at: Option<DateTime<Utc>>,
    issued_at: DateTime<Utc>,
) -> Result<(), ApplicationError> {
    let section = policy_section(policy, class)?;
    if section["enabled"] != true {
        return Err(ApplicationError::Forbidden);
    }
    let allowed_scopes = serde_json::from_value::<LlmScopeSet>(section["allowed_scopes"].clone())
        .map_err(|_| ApplicationError::Internal)?;
    if !allowed_scopes.is_superset(scopes) {
        return Err(ApplicationError::Validation(
            "requested scopes exceed the gateway policy".to_owned(),
        ));
    }
    let allowed_routes =
        serde_json::from_value::<Vec<RouteId>>(section["allowed_route_ids"].clone())
            .map_err(|_| ApplicationError::Internal)?
            .into_iter()
            .collect::<BTreeSet<_>>();
    if !routes.is_subset(&allowed_routes) {
        return Err(ApplicationError::Validation(
            "requested routes exceed the gateway policy".to_owned(),
        ));
    }
    let limit = parse_budget_limit(&budget.limit_cost_nanos)?;
    let maximum = section["budget"]["max_limit_cost_nanos"]
        .as_str()
        .and_then(|value| value.parse::<u128>().ok())
        .ok_or(ApplicationError::Internal)?;
    if limit > maximum || limit == 0 {
        return Err(ApplicationError::Validation(
            "budget limit exceeds the gateway policy or is not finite-positive".to_owned(),
        ));
    }
    let allowed_modes =
        serde_json::from_value::<Vec<BudgetMode>>(section["budget"]["allowed_modes"].clone())
            .map_err(|_| ApplicationError::Internal)?;
    if !allowed_modes.contains(&budget.mode) {
        return Err(ApplicationError::Validation(
            "budget mode exceeds the gateway policy".to_owned(),
        ));
    }
    let max_days = section["max_expiry_days"]
        .as_u64()
        .ok_or(ApplicationError::Internal)?;
    if expires_at.is_some_and(|expiry| {
        expiry > issued_at + Duration::days(i64::try_from(max_days).unwrap_or(i64::MAX))
    }) {
        return Err(ApplicationError::Validation(
            "expires_at exceeds the gateway policy".to_owned(),
        ));
    }
    Ok(())
}

fn effective_expiry(
    policy: &Value,
    class: &str,
    requested: Option<DateTime<Utc>>,
    issued_at: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>, ApplicationError> {
    let days = policy_section(policy, class)?["max_expiry_days"]
        .as_u64()
        .ok_or(ApplicationError::Internal)?;
    let maximum =
        issued_at + Duration::days(i64::try_from(days).map_err(|_| ApplicationError::Internal)?);
    Ok(Some(requested.map_or(maximum, |value| value.min(maximum))))
}

async fn enforce_active_limit(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    class: &str,
    policy: &Value,
) -> Result<(), ApplicationError> {
    let global_maximum = policy["gateway"]["max_active_keys"]
        .as_u64()
        .ok_or(ApplicationError::Internal)?;
    let global_count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM gateway_api_keys
         WHERE organization_id=$1 AND status='active'
           AND (expires_at IS NULL OR expires_at>now())",
    )
    .bind(organization_id.as_uuid())
    .fetch_one(&mut **transaction)
    .await?;
    if u64::try_from(global_count).map_err(|_| ApplicationError::Internal)? >= global_maximum {
        return Err(ApplicationError::Conflict(
            "the global Gateway-key active limit has been reached".to_owned(),
        ));
    }
    if class == "member_self_service" {
        let class_maximum = policy_section(policy, class)?["max_active_keys"]
            .as_u64()
            .ok_or(ApplicationError::Internal)?;
        let class_count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM gateway_api_keys
             WHERE organization_id=$1 AND issuance_policy_class='member_self_service'
               AND status='active' AND (expires_at IS NULL OR expires_at>now())",
        )
        .bind(organization_id.as_uuid())
        .fetch_one(&mut **transaction)
        .await?;
        if u64::try_from(class_count).map_err(|_| ApplicationError::Internal)? >= class_maximum {
            return Err(ApplicationError::Conflict(
                "the member self-service Gateway-key active limit has been reached".to_owned(),
            ));
        }
    }
    Ok(())
}

async fn lock_organization(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
) -> Result<(), ApplicationError> {
    let status =
        sqlx::query_scalar::<_, String>("SELECT status FROM organizations WHERE id=$1 FOR UPDATE")
            .bind(organization_id.as_uuid())
            .fetch_optional(&mut **transaction)
            .await?
            .ok_or(ApplicationError::NotFound)?;
    if status != "active" {
        return Err(ApplicationError::Forbidden);
    }
    Ok(())
}

async fn load_policy(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
) -> Result<Value, ApplicationError> {
    sqlx::query_scalar(
        "SELECT policy FROM organization_api_key_policies WHERE organization_id=$1 FOR UPDATE",
    )
    .bind(organization_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(ApplicationError::NotFound)
}

fn policy_section<'a>(policy: &'a Value, class: &str) -> Result<&'a Value, ApplicationError> {
    let name = if class == "member_self_service" {
        "gateway_member_self_service"
    } else {
        "gateway"
    };
    policy.get(name).ok_or(ApplicationError::Internal)
}

fn authorize_gateway_keys(
    application: &Application,
    identity: &RequestIdentity,
    organization_id: OrganizationId,
    capability: Capability,
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
            capability,
        },
    )
}

fn local_role(
    identity: &RequestIdentity,
    organization_id: OrganizationId,
) -> Option<OrganizationRole> {
    let Principal::LocalUser { user_id } = identity.principal.principal else {
        return None;
    };
    identity
        .generation
        .snapshot
        .identity
        .memberships
        .get(&(organization_id, user_id))
        .map(|membership| membership.role)
}

async fn commit_key(
    application: &Application,
    transaction: Transaction<'_, Postgres>,
    identity: &RequestIdentity,
    organization_id: OrganizationId,
    key_id: GatewayKeyId,
    operation_id: &'static str,
    changed_fields: &[&str],
    security_tightening: bool,
) -> Result<(), ApplicationError> {
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
                organization_id: Some(organization_id),
                target_resource_kind: "gateway_api_key".to_owned(),
                target_resource_id: Some(key_id.to_string()),
                operation_id: operation_id.to_owned(),
                outcome: "accepted",
                request_id: identity.request_id.clone(),
                changed_fields: changed_fields
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                safe_details: json!({}),
            },
            Some(&RuntimeEvent {
                event_kind: "gateway_api_key.changed".to_owned(),
                affected_scope: json!({
                    "organization_id": organization_id,
                    "gateway_api_key_id": key_id,
                }),
                security_tightening,
            }),
        )
        .await?;
    Ok(())
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

fn validate_routes(routes: &BTreeSet<RouteId>) -> Result<(), ApplicationError> {
    if routes.is_empty() || routes.len() > 1024 {
        return Err(ApplicationError::Validation(
            "route_ids must contain 1 to 1024 unique stable route IDs".to_owned(),
        ));
    }
    Ok(())
}

fn validate_budget_input(input: &GatewayBudgetInput) -> Result<(), ApplicationError> {
    let limit = parse_budget_limit(&input.limit_cost_nanos)?;
    let estimate: BudgetEstimatePolicy = typed_budget_policy(&input.estimate_policy)?;
    let allowance: BudgetAllowancePolicy = typed_budget_policy(&input.allowance_policy)?;
    let _: BudgetFailurePolicy = typed_budget_policy(&input.failure_policy)?;
    let _: BudgetRecoveryPolicy = typed_budget_policy(&input.recovery_policy)?;
    if limit == 0
        || input.epoch.trim().is_empty()
        || input.epoch.len() > 160
        || input.epoch.chars().any(char::is_control)
        || estimate.input_units_per_byte == 0
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
        || !(1..=3600).contains(&allowance.grant_seconds)
        || allowance.emergency_reserve_nanos > limit
    {
        return Err(ApplicationError::Validation(
            "budget requires a finite positive limit, bounded epoch, and closed typed policy values"
                .to_owned(),
        ));
    }
    Ok(())
}

fn typed_budget_policy<T: serde::de::DeserializeOwned>(
    value: &Value,
) -> Result<T, ApplicationError> {
    serde_json::from_value(value.clone())
        .map_err(|error| ApplicationError::Validation(format!("budget policy is invalid: {error}")))
}

fn parse_budget_limit(value: &str) -> Result<u128, ApplicationError> {
    value.parse::<u128>().map_err(|_| {
        ApplicationError::Validation(
            "limit_cost_nanos must be a finite non-negative base-10 integer".to_owned(),
        )
    })
}

fn scopes_value(scopes: &LlmScopeSet) -> Value {
    json!(
        scopes
            .iter()
            .map(crate::domain::LlmScope::as_str)
            .collect::<Vec<_>>()
    )
}

fn scopes_from_value(value: Value) -> Result<LlmScopeSet, ApplicationError> {
    serde_json::from_value(value).map_err(|_| ApplicationError::Internal)
}

fn parse_status(value: &str) -> Result<KeyStatus, ApplicationError> {
    match value {
        "active" => Ok(KeyStatus::Active),
        "disabled" => Ok(KeyStatus::Disabled),
        "revoked" => Ok(KeyStatus::Revoked),
        _ => Err(ApplicationError::Internal),
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

fn require_nonempty<const N: usize>(values: [bool; N]) -> Result<(), ApplicationError> {
    if values.into_iter().all(|value| value) {
        Err(ApplicationError::Validation(
            "at least one update field is required".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn expiry_extended(current: Option<DateTime<Utc>>, candidate: Option<DateTime<Utc>>) -> bool {
    match (current, candidate) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(current), Some(candidate)) => candidate > current,
    }
}

fn expiry_shortened(current: Option<DateTime<Utc>>, candidate: Option<DateTime<Utc>>) -> bool {
    match (current, candidate) {
        (None, Some(_)) => true,
        (Some(current), Some(candidate)) => candidate < current,
        _ => false,
    }
}

fn null_error(field: &str) -> ApplicationError {
    ApplicationError::Validation(format!("{field} cannot be null"))
}

fn map_database_conflict(error: sqlx::Error) -> ApplicationError {
    if error.as_database_error().is_some() {
        ApplicationError::Conflict("the gateway key conflicts with current state".to_owned())
    } else {
        error.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{LlmScope, LlmScopeSet};

    #[test]
    fn budget_input_rejects_unbounded_or_invalid_values() {
        let valid = GatewayBudgetInput {
            limit_cost_nanos: "100000000".to_owned(),
            mode: BudgetMode::Enforce,
            epoch: "epoch-1".to_owned(),
            estimate_policy: json!({}),
            allowance_policy: json!({}),
            failure_policy: json!({}),
            recovery_policy: json!({}),
        };
        assert!(validate_budget_input(&valid).is_ok());
        let mut invalid = valid;
        invalid.limit_cost_nanos = "infinite".to_owned();
        assert!(validate_budget_input(&invalid).is_err());
    }

    #[test]
    fn omitted_budget_policy_sections_use_closed_defaults() {
        let input = serde_json::from_value::<GatewayBudgetInput>(json!({
            "limit_cost_nanos": "100000000",
            "mode": "enforce",
            "epoch": "epoch-defaults"
        }))
        .unwrap();
        assert_eq!(input.estimate_policy, json!({}));
        assert_eq!(input.allowance_policy, json!({}));
        assert_eq!(input.failure_policy, json!({}));
        assert_eq!(input.recovery_policy, json!({}));
        assert!(validate_budget_input(&input).is_ok());
    }

    #[test]
    fn route_allowlist_and_invoke_scope_are_nonempty() {
        assert!(validate_routes(&BTreeSet::new()).is_err());
        assert!(LlmScopeSet::new([LlmScope::Invoke]).is_ok());
        assert!(LlmScopeSet::new([LlmScope::Stream]).is_err());
    }
}
