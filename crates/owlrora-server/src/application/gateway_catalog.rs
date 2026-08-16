use std::collections::{BTreeSet, HashMap, HashSet};

use rand::RngCore as _;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sqlx::{Executor, PgConnection, Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::{
    adapters::postgres::{AuditRecord, RuntimeEvent},
    domain::{
        Actor, Capability, CatalogScopeKind, CredentialKind, DeploymentId, EndpointAdapterKind,
        EndpointId, IngressProtocolFamily, LlmFeatureCapability, ManagementScope, OrganizationId,
        PricingPolicyId, PricingPolicyVersionId, ReliabilityPolicyId, ResourceScope, RouteId,
        RouteRequestPolicy, RouteSelectionPolicy, TargetId, TargetNarrowingConstraints,
        TargetTimeoutOverrides, TransportKind, UserId, compatibility,
    },
};

use super::{
    Application, ApplicationError, AuthorizationTarget, CatalogStatus, CreateModelDeployment,
    CreateModelRoute, CreatePricingPolicy, EntityTag, IdempotencyDecision, IdempotentCommand,
    ModelDeployment, ModelRoute, Page, PricingPolicy, PricingPolicyVersion,
    PublishPricingPolicyVersion, PublishedPricingPolicyVersion, RequestIdentity, RouteStatus,
    RouteTarget, RouteTargetInput, TransferModelRouteOwnership, UpdateField, UpdateModelDeployment,
    UpdateModelRoute, UpdatePricingPolicy, ValidatedCatalogStatus,
};

impl Application {
    pub async fn list_pricing_policies(
        &self,
        identity: &RequestIdentity,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<PricingPolicy>, ApplicationError> {
        authorize_system_catalog(self, identity, false)?;
        let family = "pricing_policies";
        let (cursor, limit) = super::resources::page_parameters(family, cursor, limit)?;
        let rows = sqlx::query(
            "SELECT id FROM pricing_policies WHERE ($1::uuid IS NULL OR id>$1)
             ORDER BY id LIMIT $2",
        )
        .bind(cursor)
        .bind(i64::from(limit) + 1)
        .fetch_all(self.store.pool())
        .await?;
        let has_more = rows.len() > limit as usize;
        let selected = rows.into_iter().take(limit as usize).collect::<Vec<_>>();
        let mut items = Vec::with_capacity(selected.len());
        let mut connection = self.store.pool().acquire().await?;
        for row in selected {
            let id = PricingPolicyId::from_uuid(row.try_get("id")?);
            items.push(load_pricing_policy(&mut connection, id).await?.0);
        }
        let next_cursor = has_more
            .then(|| items.last().map(|item| item.id.to_string()))
            .flatten();
        Ok(Page { items, next_cursor })
    }

    pub async fn get_pricing_policy(
        &self,
        identity: &RequestIdentity,
        id: PricingPolicyId,
    ) -> Result<(PricingPolicy, EntityTag), ApplicationError> {
        authorize_system_catalog(self, identity, false)?;
        let mut connection = self.store.pool().acquire().await?;
        load_pricing_policy(&mut connection, id).await
    }

    pub async fn create_pricing_policy(
        &self,
        identity: &RequestIdentity,
        input: CreatePricingPolicy,
        idempotency_key: Option<&str>,
    ) -> Result<IdempotentCommand<(PricingPolicy, EntityTag)>, ApplicationError> {
        authorize_system_catalog(self, identity, true)?;
        validate_name(&input.name)?;
        let scope = ResourceScope::Deployment;
        let operation_id = "system.pricing_policies.create";
        let mut transaction = self.store.begin().await?;
        let handle = match self
            .begin_idempotent_command(
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
        let id = PricingPolicyId::new();
        sqlx::query(
            "INSERT INTO pricing_policies(
                id,name,status,created_by_principal,etag_token
             ) VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(id.as_uuid())
        .bind(input.name.trim())
        .bind(input.status.as_str())
        .bind(actor_value(identity)?)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_conflict)?;
        let result = load_pricing_policy(&mut transaction, id).await?;
        self.complete_idempotent_command(
            &mut transaction,
            handle,
            200,
            &result.0,
            Some(result.1.as_str()),
        )
        .await?;
        commit_catalog(
            self,
            transaction,
            identity,
            None,
            "pricing_policy",
            id.to_string(),
            operation_id,
            &["name", "status"],
            false,
        )
        .await?;
        self.publish_committed_runtime(&identity.request_id, "system.pricing_policies.create")
            .await;
        Ok(IdempotentCommand::Executed(result))
    }

    pub async fn update_pricing_policy(
        &self,
        identity: &RequestIdentity,
        id: PricingPolicyId,
        if_match: Option<&str>,
        input: UpdatePricingPolicy,
    ) -> Result<(PricingPolicy, EntityTag), ApplicationError> {
        authorize_system_catalog(self, identity, true)?;
        if input.name.is_omitted() && input.status.is_omitted() {
            return Err(empty_update());
        }
        let mut transaction = self.store.begin().await?;
        let row = sqlx::query(
            "SELECT name,status,etag_token FROM pricing_policies WHERE id=$1 FOR UPDATE",
        )
        .bind(id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        require_if_match(
            if_match,
            &EntityTag::for_resource("pricing_policy", id.as_uuid(), row.try_get("etag_token")?),
        )?;
        let mut name: String = row.try_get("name")?;
        let old_status: String = row.try_get("status")?;
        let mut status = old_status.clone();
        let mut changed = Vec::new();
        apply_name(&mut name, input.name, &mut changed)?;
        apply_catalog_status(&mut status, input.status, &mut changed)?;
        sqlx::query(
            "UPDATE pricing_policies SET name=$2,status=$3,etag_token=$4,updated_at=now()
             WHERE id=$1",
        )
        .bind(id.as_uuid())
        .bind(name)
        .bind(&status)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_conflict)?;
        let result = load_pricing_policy(&mut transaction, id).await?;
        commit_catalog(
            self,
            transaction,
            identity,
            None,
            "pricing_policy",
            id.to_string(),
            "system.pricing_policies.update",
            &changed,
            old_status == "active" && status == "disabled",
        )
        .await?;
        self.publish_committed_runtime(&identity.request_id, "system.pricing_policies.update")
            .await;
        Ok(result)
    }

    pub async fn publish_pricing_policy_version(
        &self,
        identity: &RequestIdentity,
        id: PricingPolicyId,
        if_match: Option<&str>,
        input: PublishPricingPolicyVersion,
        idempotency_key: Option<&str>,
    ) -> Result<IdempotentCommand<(PublishedPricingPolicyVersion, EntityTag)>, ApplicationError>
    {
        authorize_system_catalog(self, identity, true)?;
        validate_pricing_input(&input)?;
        let idempotency_request = json!({
            "pricing_policy_id": id,
            "if_match": if_match,
            "input": &input,
        });
        let mut transaction = self.store.begin().await?;
        let handle = match self
            .begin_idempotent_command(
                &mut transaction,
                identity,
                &ResourceScope::Deployment,
                "system.pricing_policies.publish_version",
                idempotency_key,
                &idempotency_request,
            )
            .await?
        {
            IdempotencyDecision::Execute(handle) => handle,
            IdempotencyDecision::Replay(replay) => {
                return Ok(IdempotentCommand::Replay(replay));
            }
        };
        let row = sqlx::query("SELECT etag_token FROM pricing_policies WHERE id=$1 FOR UPDATE")
            .bind(id.as_uuid())
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(ApplicationError::NotFound)?;
        require_if_match(
            if_match,
            &EntityTag::for_resource("pricing_policy", id.as_uuid(), row.try_get("etag_token")?),
        )?;
        let generation = sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(MAX(generation),0)+1 FROM pricing_policy_versions
             WHERE pricing_policy_id=$1",
        )
        .bind(id.as_uuid())
        .fetch_one(&mut *transaction)
        .await?;
        let version_id = PricingPolicyVersionId::new();
        sqlx::query(
            "INSERT INTO pricing_policy_versions(
                id,pricing_policy_id,generation,rates,rounding_policy,organization_usable,
                publication_evidence,created_by_principal
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(version_id.as_uuid())
        .bind(id.as_uuid())
        .bind(generation)
        .bind(serde_json::to_value(&input.rates).map_err(|_| ApplicationError::Internal)?)
        .bind(serde_json::to_value(&input.rounding_policy).map_err(|_| ApplicationError::Internal)?)
        .bind(input.organization_usable)
        .bind(&input.publication_evidence)
        .bind(actor_value(identity)?)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE pricing_policies SET desired_version_id=$2,current_version_id=$2,
                    etag_token=$3,updated_at=now() WHERE id=$1",
        )
        .bind(id.as_uuid())
        .bind(version_id.as_uuid())
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let (pricing_policy, etag) = load_pricing_policy(&mut transaction, id).await?;
        let version = pricing_policy
            .versions
            .iter()
            .find(|version| version.id == version_id)
            .cloned()
            .ok_or(ApplicationError::Internal)?;
        let response = PublishedPricingPolicyVersion {
            pricing_policy,
            version,
        };
        self.complete_idempotent_command(
            &mut transaction,
            handle,
            200,
            &response,
            Some(etag.as_str()),
        )
        .await?;
        commit_catalog(
            self,
            transaction,
            identity,
            None,
            "pricing_policy",
            id.to_string(),
            "system.pricing_policies.publish_version",
            &[
                "desired_version_id",
                "current_version_id",
                "rates",
                "rounding_policy",
                "organization_usable",
                "publication_evidence",
            ],
            false,
        )
        .await?;
        self.publish_committed_runtime(
            &identity.request_id,
            "system.pricing_policies.publish_version",
        )
        .await;
        Ok(IdempotentCommand::Executed((response, etag)))
    }

    pub async fn list_model_deployments(
        &self,
        identity: &RequestIdentity,
        scope: ResourceScope,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<ModelDeployment>, ApplicationError> {
        authorize_deployment(self, identity, &scope, false)?;
        let family = scope_family("model_deployments", &scope);
        let (cursor, limit) = super::resources::page_parameters(&family, cursor, limit)?;
        let (_, organization_id) = scope_columns(&scope);
        let rows = sqlx::query(
            "SELECT id,name,endpoint_id,credential_id,transport_kind,upstream_model_id,
                    model_family,capability_set,context_limits,state_isolation_profile,
                    pricing_policy_version_id,unpriced,status,config_version,
                    validation_evidence,etag_token,created_at,updated_at,validated_at
             FROM model_deployments
             WHERE organization_id IS NOT DISTINCT FROM $1 AND ($2::uuid IS NULL OR id>$2)
             ORDER BY id LIMIT $3",
        )
        .bind(organization_id)
        .bind(cursor)
        .bind(i64::from(limit) + 1)
        .fetch_all(self.store.pool())
        .await?;
        page_from_catalog_rows(rows, limit, &family, |row| deployment_from_row(row, &scope))
    }

    pub async fn get_model_deployment(
        &self,
        identity: &RequestIdentity,
        scope: ResourceScope,
        id: DeploymentId,
    ) -> Result<(ModelDeployment, EntityTag), ApplicationError> {
        authorize_deployment(self, identity, &scope, false)?;
        load_deployment(self.store.pool(), &scope, id).await
    }

    pub async fn create_model_deployment(
        &self,
        identity: &RequestIdentity,
        scope: ResourceScope,
        input: CreateModelDeployment,
        idempotency_key: Option<&str>,
    ) -> Result<IdempotentCommand<(ModelDeployment, EntityTag)>, ApplicationError> {
        authorize_deployment(self, identity, &scope, true)?;
        validate_deployment_input(&input)?;
        let operation_id = deployment_operation_id(&scope, "create");
        let mut transaction = self.store.begin().await?;
        let handle = match self
            .begin_idempotent_command(
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
        let id = DeploymentId::new();
        let (scope_kind, organization_id) = scope_columns(&scope);
        validate_deployment_bindings(&mut transaction, &scope, &input).await?;
        sqlx::query(
            "INSERT INTO model_deployments(
                id,resource_scope_kind,organization_id,name,endpoint_id,credential_id,
                transport_kind,upstream_model_id,model_family,capability_set,context_limits,
                state_isolation_profile,pricing_policy_version_id,unpriced,status,config_version,
                created_by_principal,etag_token
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,1,$16,$17)",
        )
        .bind(id.as_uuid())
        .bind(scope_kind)
        .bind(organization_id)
        .bind(input.name.trim())
        .bind(input.endpoint_id.as_uuid())
        .bind(input.credential_id.as_uuid())
        .bind(input.transport_kind.as_str())
        .bind(input.upstream_model_id.trim())
        .bind(normalize_optional(
            input.model_family.as_deref(),
            160,
            "model_family",
        )?)
        .bind(serde_json::to_value(&input.capability_set).map_err(|_| ApplicationError::Internal)?)
        .bind(&input.context_limits)
        .bind(&input.state_isolation_profile)
        .bind(
            input
                .pricing_policy_version_id
                .map(PricingPolicyVersionId::as_uuid),
        )
        .bind(input.unpriced)
        .bind(input.status.as_str())
        .bind(actor_value(identity)?)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_conflict)?;
        let result = load_deployment(&mut *transaction, &scope, id).await?;
        self.complete_idempotent_command(
            &mut transaction,
            handle,
            200,
            &result.0,
            Some(result.1.as_str()),
        )
        .await?;
        commit_catalog(
            self,
            transaction,
            identity,
            organization_id.map(OrganizationId::from_uuid),
            "model_deployment",
            id.to_string(),
            operation_id,
            &[
                "name",
                "endpoint_id",
                "credential_id",
                "transport_kind",
                "upstream_model_id",
                "model_family",
                "capability_set",
                "context_limits",
                "state_isolation_profile",
                "pricing_policy_version_id",
                "unpriced",
                "status",
            ],
            false,
        )
        .await?;
        self.publish_committed_runtime(&identity.request_id, operation_id)
            .await;
        Ok(IdempotentCommand::Executed(result))
    }

    pub async fn update_model_deployment(
        &self,
        identity: &RequestIdentity,
        scope: ResourceScope,
        id: DeploymentId,
        if_match: Option<&str>,
        input: UpdateModelDeployment,
    ) -> Result<(ModelDeployment, EntityTag), ApplicationError> {
        authorize_deployment(self, identity, &scope, true)?;
        if input.name.is_omitted()
            && input.model_family.is_omitted()
            && input.capability_set.is_omitted()
            && input.context_limits.is_omitted()
            && input.state_isolation_profile.is_omitted()
            && input.pricing_policy_version_id.is_omitted()
            && input.unpriced.is_omitted()
            && input.status.is_omitted()
        {
            return Err(empty_update());
        }
        let (_, organization_id) = scope_columns(&scope);
        let mut transaction = self.store.begin().await?;
        let row = sqlx::query(
            "SELECT name,model_family,capability_set,context_limits,state_isolation_profile,
                    pricing_policy_version_id,unpriced,status,etag_token
             FROM model_deployments
             WHERE organization_id IS NOT DISTINCT FROM $1 AND id=$2 FOR UPDATE",
        )
        .bind(organization_id)
        .bind(id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        require_if_match(
            if_match,
            &EntityTag::for_resource("model_deployment", id.as_uuid(), row.try_get("etag_token")?),
        )?;
        let mut name: String = row.try_get("name")?;
        let mut model_family: Option<String> = row.try_get("model_family")?;
        let mut capabilities: BTreeSet<LlmFeatureCapability> =
            deserialize_column(&row, "capability_set")?;
        let mut context_limits: Value = row.try_get("context_limits")?;
        let mut state_isolation: Value = row.try_get("state_isolation_profile")?;
        let mut pricing_id = row
            .try_get::<Option<Uuid>, _>("pricing_policy_version_id")?
            .map(PricingPolicyVersionId::from_uuid);
        let mut unpriced: bool = row.try_get("unpriced")?;
        let old_status: String = row.try_get("status")?;
        let mut status = old_status.clone();
        let mut changed = Vec::new();
        apply_name(&mut name, input.name, &mut changed)?;
        apply_optional_string(
            &mut model_family,
            input.model_family,
            160,
            "model_family",
            &mut changed,
        )?;
        apply_required(
            &mut capabilities,
            input.capability_set,
            "capability_set",
            &mut changed,
        )?;
        apply_object(
            &mut context_limits,
            input.context_limits,
            "context_limits",
            &mut changed,
        )?;
        apply_object(
            &mut state_isolation,
            input.state_isolation_profile,
            "state_isolation_profile",
            &mut changed,
        )?;
        match input.pricing_policy_version_id {
            UpdateField::Omitted => {}
            UpdateField::Null => {
                pricing_id = None;
                changed.push("pricing_policy_version_id");
            }
            UpdateField::Value(value) => {
                validate_pricing_version(&mut transaction, &scope, value).await?;
                pricing_id = Some(value);
                changed.push("pricing_policy_version_id");
            }
        }
        apply_required(&mut unpriced, input.unpriced, "unpriced", &mut changed)?;
        apply_validated_status(&mut status, input.status, &mut changed)?;
        validate_deployment_mutable(&capabilities, &context_limits, &state_isolation)?;
        if unpriced == pricing_id.is_some() {
            return Err(ApplicationError::Validation(
                "exactly one of pricing_policy_version_id or unpriced=true is required".to_owned(),
            ));
        }
        sqlx::query(
            "UPDATE model_deployments SET name=$3,model_family=$4,capability_set=$5,
                    context_limits=$6,state_isolation_profile=$7,pricing_policy_version_id=$8,
                    unpriced=$9,status=$10,config_version=config_version+1,
                    validation_evidence=NULL,validated_at=NULL,etag_token=$11,updated_at=now()
             WHERE organization_id IS NOT DISTINCT FROM $1 AND id=$2",
        )
        .bind(organization_id)
        .bind(id.as_uuid())
        .bind(name)
        .bind(model_family)
        .bind(serde_json::to_value(capabilities).map_err(|_| ApplicationError::Internal)?)
        .bind(context_limits)
        .bind(state_isolation)
        .bind(pricing_id.map(PricingPolicyVersionId::as_uuid))
        .bind(unpriced)
        .bind(&status)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_conflict)?;
        let result = load_deployment(&mut *transaction, &scope, id).await?;
        commit_catalog(
            self,
            transaction,
            identity,
            organization_id.map(OrganizationId::from_uuid),
            "model_deployment",
            id.to_string(),
            deployment_operation_id(&scope, "update"),
            &changed,
            old_status == "active" && status != "active",
        )
        .await?;
        self.publish_committed_runtime(
            &identity.request_id,
            deployment_operation_id(&scope, "update"),
        )
        .await;
        Ok(result)
    }

    pub async fn validate_model_deployment(
        &self,
        identity: &RequestIdentity,
        scope: ResourceScope,
        id: DeploymentId,
        idempotency_key: Option<&str>,
    ) -> Result<IdempotentCommand<super::CatalogValidationResult<ModelDeployment>>, ApplicationError>
    {
        authorize_deployment(self, identity, &scope, true)?;
        let (_, organization_id) = scope_columns(&scope);
        let operation_id = deployment_operation_id(&scope, "validate");
        let request = json!({"deployment_id": id});
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
        self.runtime
            .refresh_now()
            .await
            .map_err(|_| ApplicationError::DependencyUnavailable)?;
        let generation = self.runtime.capture();
        let deployment = generation
            .snapshot
            .catalog
            .deployments
            .get(&id)
            .ok_or(ApplicationError::NotFound)?;
        if !deployment.operational
            || !generation
                .credential_clients
                .clients
                .contains_key(&deployment.client_key())
        {
            return Err(ApplicationError::Conflict(
                "deployment runtime client is not operational".to_owned(),
            ));
        }
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
            "SELECT status,config_version FROM model_deployments
             WHERE organization_id IS NOT DISTINCT FROM $1 AND id=$2 FOR UPDATE",
        )
        .bind(organization_id)
        .bind(id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        let evidence = json!({
            "outcome":"accepted",
            "validation_kind":"binding_and_runtime_client",
            "config_version":row.try_get::<i64, _>("config_version")?,
        });
        sqlx::query(
            "UPDATE model_deployments SET validation_evidence=$3,validated_at=now(),
                    etag_token=$4,updated_at=now(),status=CASE
                        WHEN status='validation_failed' THEN 'active' ELSE status END
             WHERE organization_id IS NOT DISTINCT FROM $1 AND id=$2",
        )
        .bind(organization_id)
        .bind(id.as_uuid())
        .bind(&evidence)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let (resource, _) = load_deployment(&mut *transaction, &scope, id).await?;
        let result = super::CatalogValidationResult {
            resource,
            outcome: "accepted".to_owned(),
            evidence,
        };
        self.complete_idempotent_command(&mut transaction, handle, 200, &result, None)
            .await?;
        commit_catalog(
            self,
            transaction,
            identity,
            organization_id.map(OrganizationId::from_uuid),
            "model_deployment",
            id.to_string(),
            operation_id,
            &["validation_evidence", "validated_at", "status"],
            false,
        )
        .await?;
        self.publish_committed_runtime(&identity.request_id, operation_id)
            .await;
        Ok(IdempotentCommand::Executed(result))
    }

    pub async fn list_model_routes(
        &self,
        identity: &RequestIdentity,
        scope: ResourceScope,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<ModelRoute>, ApplicationError> {
        authorize_route(self, identity, &scope, false)?;
        let family = scope_family("model_routes", &scope);
        let (cursor, limit) = super::resources::page_parameters(&family, cursor, limit)?;
        let (_, organization_id) = scope_columns(&scope);
        let rows = sqlx::query(
            "SELECT id FROM model_routes
             WHERE organization_id IS NOT DISTINCT FROM $1 AND ($2::uuid IS NULL OR id>$2)
             ORDER BY id LIMIT $3",
        )
        .bind(organization_id)
        .bind(cursor)
        .bind(i64::from(limit) + 1)
        .fetch_all(self.store.pool())
        .await?;
        let has_more = rows.len() > limit as usize;
        let selected = rows.into_iter().take(limit as usize).collect::<Vec<_>>();
        let mut items = Vec::with_capacity(selected.len());
        let mut connection = self.store.pool().acquire().await?;
        for row in selected {
            let id = RouteId::from_uuid(row.try_get("id")?);
            items.push(load_route(&mut connection, &scope, id).await?.0);
        }
        let next_cursor = has_more
            .then(|| items.last().map(|item| item.id.to_string()))
            .flatten();
        Ok(Page { items, next_cursor })
    }

    pub async fn get_model_route(
        &self,
        identity: &RequestIdentity,
        scope: ResourceScope,
        id: RouteId,
    ) -> Result<(ModelRoute, EntityTag), ApplicationError> {
        authorize_route(self, identity, &scope, false)?;
        let mut connection = self.store.pool().acquire().await?;
        load_route(&mut connection, &scope, id).await
    }

    pub async fn create_model_route(
        &self,
        identity: &RequestIdentity,
        scope: ResourceScope,
        input: CreateModelRoute,
        idempotency_key: Option<&str>,
    ) -> Result<IdempotentCommand<(ModelRoute, EntityTag)>, ApplicationError> {
        authorize_route(self, identity, &scope, true)?;
        validate_route_input(&input)?;
        let operation_id = route_operation_id(&scope, "create");
        let mut transaction = self.store.begin().await?;
        let handle = match self
            .begin_idempotent_command(
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
        let id = RouteId::new();
        let (scope_kind, organization_id) = scope_columns(&scope);
        let owner = resolve_route_owner(&mut transaction, &scope, input.owner_user_id).await?;
        validate_route_graph(
            &mut transaction,
            &scope,
            input.ingress_protocol_family,
            &input.required_base_capabilities,
            input.reliability_policy_id,
            input.status,
            &input.targets,
        )
        .await?;
        sqlx::query(
            "INSERT INTO model_routes(
                id,resource_scope_kind,organization_id,owner_user_id,owner_membership_id,
                model_key,ingress_protocol_family,required_base_capabilities,selection_policy,
                reliability_policy_id,request_policy,status,config_version,
                created_by_principal,etag_token
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,$13,$14)",
        )
        .bind(id.as_uuid())
        .bind(scope_kind)
        .bind(organization_id)
        .bind(owner.map(|owner| owner.0.as_uuid()))
        .bind(owner.map(|owner| owner.1))
        .bind(input.model_key.trim())
        .bind(input.ingress_protocol_family.as_str())
        .bind(
            serde_json::to_value(&input.required_base_capabilities)
                .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(&input.selection_policy)
        .bind(input.reliability_policy_id.as_uuid())
        .bind(&input.request_policy)
        .bind(input.status.as_str())
        .bind(actor_value(identity)?)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_conflict)?;
        replace_targets(&mut transaction, id, &input.targets).await?;
        let result = load_route(&mut transaction, &scope, id).await?;
        self.complete_idempotent_command(
            &mut transaction,
            handle,
            200,
            &result.0,
            Some(result.1.as_str()),
        )
        .await?;
        commit_catalog(
            self,
            transaction,
            identity,
            organization_id.map(OrganizationId::from_uuid),
            "model_route",
            id.to_string(),
            operation_id,
            &[
                "owner_user_id",
                "owner_membership_id",
                "model_key",
                "ingress_protocol_family",
                "required_base_capabilities",
                "selection_policy",
                "reliability_policy_id",
                "request_policy",
                "status",
                "targets",
            ],
            false,
        )
        .await?;
        self.publish_committed_runtime(&identity.request_id, operation_id)
            .await;
        Ok(IdempotentCommand::Executed(result))
    }

    pub async fn update_model_route(
        &self,
        identity: &RequestIdentity,
        scope: ResourceScope,
        id: RouteId,
        if_match: Option<&str>,
        input: UpdateModelRoute,
    ) -> Result<(ModelRoute, EntityTag), ApplicationError> {
        authorize_route(self, identity, &scope, true)?;
        if input.required_base_capabilities.is_omitted()
            && input.selection_policy.is_omitted()
            && input.reliability_policy_id.is_omitted()
            && input.request_policy.is_omitted()
            && input.status.is_omitted()
            && input.targets.is_omitted()
        {
            return Err(empty_update());
        }
        let (_, organization_id) = scope_columns(&scope);
        let mut transaction = self.store.begin().await?;
        let row = sqlx::query(
            "SELECT ingress_protocol_family,required_base_capabilities,selection_policy,
                    reliability_policy_id,request_policy,status,etag_token
             FROM model_routes
             WHERE organization_id IS NOT DISTINCT FROM $1 AND id=$2 FOR UPDATE",
        )
        .bind(organization_id)
        .bind(id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        require_if_match(
            if_match,
            &EntityTag::for_resource("model_route", id.as_uuid(), row.try_get("etag_token")?),
        )?;
        let ingress = parse_ingress(&row.try_get::<String, _>("ingress_protocol_family")?)?;
        let mut required: BTreeSet<LlmFeatureCapability> =
            deserialize_column(&row, "required_base_capabilities")?;
        let mut selection: Value = row.try_get("selection_policy")?;
        let mut reliability_id =
            ReliabilityPolicyId::from_uuid(row.try_get("reliability_policy_id")?);
        let mut request: Value = row.try_get("request_policy")?;
        let old_status: String = row.try_get("status")?;
        let mut status = parse_route_status(&old_status)?;
        let mut targets = load_target_inputs(&mut transaction, id).await?;
        let mut changed = Vec::new();
        apply_required(
            &mut required,
            input.required_base_capabilities,
            "required_base_capabilities",
            &mut changed,
        )?;
        apply_object(
            &mut selection,
            input.selection_policy,
            "selection_policy",
            &mut changed,
        )?;
        apply_required(
            &mut reliability_id,
            input.reliability_policy_id,
            "reliability_policy_id",
            &mut changed,
        )?;
        apply_object(
            &mut request,
            input.request_policy,
            "request_policy",
            &mut changed,
        )?;
        apply_required(&mut status, input.status, "status", &mut changed)?;
        match input.targets {
            UpdateField::Omitted => {}
            UpdateField::Null => return Err(null_error("targets")),
            UpdateField::Value(value) => {
                targets = value;
                changed.push("targets");
            }
        }
        validate_policy_objects(&selection, &request)?;
        validate_route_graph(
            &mut transaction,
            &scope,
            ingress,
            &required,
            reliability_id,
            status,
            &targets,
        )
        .await?;
        sqlx::query(
            "UPDATE model_routes SET required_base_capabilities=$3,selection_policy=$4,
                    reliability_policy_id=$5,request_policy=$6,status=$7,
                    config_version=config_version+1,etag_token=$8,updated_at=now()
             WHERE organization_id IS NOT DISTINCT FROM $1 AND id=$2",
        )
        .bind(organization_id)
        .bind(id.as_uuid())
        .bind(serde_json::to_value(required).map_err(|_| ApplicationError::Internal)?)
        .bind(selection)
        .bind(reliability_id.as_uuid())
        .bind(request)
        .bind(status.as_str())
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_conflict)?;
        replace_targets(&mut transaction, id, &targets).await?;
        let result = load_route(&mut transaction, &scope, id).await?;
        commit_catalog(
            self,
            transaction,
            identity,
            organization_id.map(OrganizationId::from_uuid),
            "model_route",
            id.to_string(),
            route_operation_id(&scope, "update"),
            &changed,
            old_status == "active" && status != RouteStatus::Active,
        )
        .await?;
        self.publish_committed_runtime(&identity.request_id, route_operation_id(&scope, "update"))
            .await;
        Ok(result)
    }

    pub async fn transfer_model_route_ownership(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        id: RouteId,
        if_match: Option<&str>,
        input: TransferModelRouteOwnership,
    ) -> Result<(ModelRoute, EntityTag), ApplicationError> {
        let scope = ResourceScope::Organization { organization_id };
        authorize_route(self, identity, &scope, true)?;
        let mut transaction = self.store.begin().await?;
        let row = sqlx::query(
            "SELECT owner_user_id,etag_token FROM model_routes
             WHERE organization_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(organization_id.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        require_if_match(
            if_match,
            &EntityTag::for_resource("model_route", id.as_uuid(), row.try_get("etag_token")?),
        )?;
        let (_, membership_id) =
            active_membership(&mut transaction, organization_id, input.owner_user_id).await?;
        sqlx::query(
            "UPDATE model_routes SET owner_user_id=$3,owner_membership_id=$4,
                    config_version=config_version+1,etag_token=$5,updated_at=now()
             WHERE organization_id=$1 AND id=$2",
        )
        .bind(organization_id.as_uuid())
        .bind(id.as_uuid())
        .bind(input.owner_user_id.as_uuid())
        .bind(membership_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let result = load_route(&mut transaction, &scope, id).await?;
        commit_catalog(
            self,
            transaction,
            identity,
            Some(organization_id),
            "model_route",
            id.to_string(),
            "organization.model_routes.transfer_ownership",
            &["owner_user_id", "owner_membership_id"],
            false,
        )
        .await?;
        self.publish_committed_runtime(
            &identity.request_id,
            "organization.model_routes.transfer_ownership",
        )
        .await;
        Ok(result)
    }
}

async fn load_pricing_policy(
    executor: &mut PgConnection,
    id: PricingPolicyId,
) -> Result<(PricingPolicy, EntityTag), ApplicationError> {
    let row = sqlx::query(
        "SELECT id,name,status,desired_version_id,current_version_id,etag_token,created_at,updated_at
         FROM pricing_policies WHERE id=$1",
    )
    .bind(id.as_uuid())
    .fetch_optional(&mut *executor)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    let version_rows = sqlx::query(
        "SELECT id,pricing_policy_id,generation,rates,rounding_policy,organization_usable,
                publication_evidence,created_at
         FROM pricing_policy_versions WHERE pricing_policy_id=$1 ORDER BY generation DESC",
    )
    .bind(id.as_uuid())
    .fetch_all(&mut *executor)
    .await?;
    let versions = version_rows
        .into_iter()
        .map(pricing_version_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    let etag = EntityTag::for_resource("pricing_policy", id.as_uuid(), row.try_get("etag_token")?);
    Ok((
        PricingPolicy {
            id,
            name: row.try_get("name")?,
            status: parse_catalog_status(&row.try_get::<String, _>("status")?)?,
            desired_version_id: row
                .try_get::<Option<Uuid>, _>("desired_version_id")?
                .map(PricingPolicyVersionId::from_uuid),
            current_version_id: row
                .try_get::<Option<Uuid>, _>("current_version_id")?
                .map(PricingPolicyVersionId::from_uuid),
            versions,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        },
        etag,
    ))
}

fn pricing_version_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<PricingPolicyVersion, ApplicationError> {
    Ok(PricingPolicyVersion {
        id: PricingPolicyVersionId::from_uuid(row.try_get("id")?),
        pricing_policy_id: PricingPolicyId::from_uuid(row.try_get("pricing_policy_id")?),
        generation: row.try_get("generation")?,
        rates: deserialize_column(&row, "rates")?,
        rounding_policy: deserialize_column(&row, "rounding_policy")?,
        organization_usable: row.try_get("organization_usable")?,
        publication_evidence: row.try_get("publication_evidence")?,
        created_at: row.try_get("created_at")?,
    })
}

pub(super) async fn load_deployment<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    scope: &ResourceScope,
    id: DeploymentId,
) -> Result<(ModelDeployment, EntityTag), ApplicationError> {
    let (_, organization_id) = scope_columns(scope);
    let row = sqlx::query(
        "SELECT id,name,endpoint_id,credential_id,transport_kind,upstream_model_id,
                model_family,capability_set,context_limits,state_isolation_profile,
                pricing_policy_version_id,unpriced,status,config_version,
                validation_evidence,etag_token,created_at,updated_at,validated_at
         FROM model_deployments WHERE organization_id IS NOT DISTINCT FROM $1 AND id=$2",
    )
    .bind(organization_id)
    .bind(id.as_uuid())
    .fetch_optional(executor)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    let etag =
        EntityTag::for_resource("model_deployment", id.as_uuid(), row.try_get("etag_token")?);
    Ok((deployment_from_row(row, scope)?, etag))
}

fn deployment_from_row(
    row: sqlx::postgres::PgRow,
    scope: &ResourceScope,
) -> Result<ModelDeployment, ApplicationError> {
    Ok(ModelDeployment {
        id: DeploymentId::from_uuid(row.try_get("id")?),
        resource_scope: scope.clone(),
        name: row.try_get("name")?,
        endpoint_id: EndpointId::from_uuid(row.try_get("endpoint_id")?),
        credential_id: crate::domain::CredentialId::from_uuid(row.try_get("credential_id")?),
        transport_kind: parse_transport(&row.try_get::<String, _>("transport_kind")?)?,
        upstream_model_id: row.try_get("upstream_model_id")?,
        model_family: row.try_get("model_family")?,
        capability_set: deserialize_column(&row, "capability_set")?,
        context_limits: row.try_get("context_limits")?,
        state_isolation_profile: row.try_get("state_isolation_profile")?,
        pricing_policy_version_id: row
            .try_get::<Option<Uuid>, _>("pricing_policy_version_id")?
            .map(PricingPolicyVersionId::from_uuid),
        unpriced: row.try_get("unpriced")?,
        status: parse_validated_status(&row.try_get::<String, _>("status")?)?,
        config_version: row.try_get("config_version")?,
        validation_evidence: row.try_get("validation_evidence")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        validated_at: row.try_get("validated_at")?,
    })
}

pub(super) async fn load_route(
    executor: &mut PgConnection,
    scope: &ResourceScope,
    id: RouteId,
) -> Result<(ModelRoute, EntityTag), ApplicationError> {
    let (_, organization_id) = scope_columns(scope);
    let row = sqlx::query(
        "SELECT id,owner_user_id,model_key,ingress_protocol_family,
                required_base_capabilities,selection_policy,reliability_policy_id,
                request_policy,status,config_version,etag_token,created_at,updated_at
         FROM model_routes WHERE organization_id IS NOT DISTINCT FROM $1 AND id=$2",
    )
    .bind(organization_id)
    .bind(id.as_uuid())
    .fetch_optional(&mut *executor)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    let target_rows = sqlx::query(
        "SELECT id,deployment_id,priority,weight,enabled,narrowing_constraints,timeout_overrides
         FROM route_targets WHERE route_id=$1 ORDER BY priority,id",
    )
    .bind(id.as_uuid())
    .fetch_all(&mut *executor)
    .await?;
    let targets = target_rows
        .into_iter()
        .map(route_target_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    let etag = EntityTag::for_resource("model_route", id.as_uuid(), row.try_get("etag_token")?);
    Ok((
        ModelRoute {
            id,
            resource_scope: scope.clone(),
            owner_user_id: row
                .try_get::<Option<Uuid>, _>("owner_user_id")?
                .map(UserId::from_uuid),
            model_key: row.try_get("model_key")?,
            ingress_protocol_family: parse_ingress(
                &row.try_get::<String, _>("ingress_protocol_family")?,
            )?,
            required_base_capabilities: deserialize_column(&row, "required_base_capabilities")?,
            selection_policy: row.try_get("selection_policy")?,
            reliability_policy_id: ReliabilityPolicyId::from_uuid(
                row.try_get("reliability_policy_id")?,
            ),
            request_policy: row.try_get("request_policy")?,
            status: parse_route_status(&row.try_get::<String, _>("status")?)?,
            config_version: row.try_get("config_version")?,
            targets,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        },
        etag,
    ))
}

fn route_target_from_row(row: sqlx::postgres::PgRow) -> Result<RouteTarget, ApplicationError> {
    Ok(RouteTarget {
        id: TargetId::from_uuid(row.try_get("id")?),
        deployment_id: DeploymentId::from_uuid(row.try_get("deployment_id")?),
        priority: u8::try_from(row.try_get::<i16, _>("priority")?)
            .map_err(|_| ApplicationError::Internal)?,
        weight: u16::try_from(row.try_get::<i16, _>("weight")?)
            .map_err(|_| ApplicationError::Internal)?,
        enabled: row.try_get("enabled")?,
        narrowing_constraints: row.try_get("narrowing_constraints")?,
        timeout_overrides: row.try_get("timeout_overrides")?,
    })
}

async fn validate_deployment_bindings(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ResourceScope,
    input: &CreateModelDeployment,
) -> Result<(), ApplicationError> {
    let endpoint =
        sqlx::query("SELECT adapter_kind,status FROM upstream_endpoints WHERE id=$1 FOR SHARE")
            .bind(input.endpoint_id.as_uuid())
            .fetch_optional(&mut **transaction)
            .await?
            .ok_or(ApplicationError::NotFound)?;
    let (_, organization_id) = scope_columns(scope);
    let credential = sqlx::query(
        "SELECT credential_kind,administrative_status
         FROM upstream_credentials
         WHERE organization_id IS NOT DISTINCT FROM $1 AND id=$2 FOR SHARE",
    )
    .bind(organization_id)
    .bind(input.credential_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    let adapter = parse_endpoint_adapter(&endpoint.try_get::<String, _>("adapter_kind")?)?;
    let credential_kind =
        parse_credential_kind(&credential.try_get::<String, _>("credential_kind")?)?;
    if !transport_tuple_exists(adapter, credential_kind, input.transport_kind) {
        return Err(ApplicationError::Validation(
            "endpoint, credential, and transport are not a supported compatibility tuple"
                .to_owned(),
        ));
    }
    if let ResourceScope::Organization { organization_id } = scope {
        let granted = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM organization_endpoint_grants
             WHERE organization_id=$1 AND endpoint_id=$2 AND status='active')",
        )
        .bind(organization_id.as_uuid())
        .bind(input.endpoint_id.as_uuid())
        .fetch_one(&mut **transaction)
        .await?;
        if !granted {
            return Err(ApplicationError::Forbidden);
        }
    }
    if let Some(version_id) = input.pricing_policy_version_id {
        validate_pricing_version(transaction, scope, version_id).await?;
    }
    Ok(())
}

async fn validate_pricing_version(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ResourceScope,
    id: PricingPolicyVersionId,
) -> Result<(), ApplicationError> {
    let row = sqlx::query(
        "SELECT version.organization_usable,policy.status
         FROM pricing_policy_versions version
         JOIN pricing_policies policy ON policy.id=version.pricing_policy_id
         WHERE version.id=$1 FOR SHARE OF version,policy",
    )
    .bind(id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    if matches!(scope, ResourceScope::Organization { .. })
        && !row.try_get::<bool, _>("organization_usable")?
    {
        return Err(ApplicationError::Conflict(
            "the pricing version is not eligible for this deployment scope".to_owned(),
        ));
    }
    Ok(())
}

async fn validate_route_graph(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ResourceScope,
    ingress: IngressProtocolFamily,
    required_capabilities: &BTreeSet<LlmFeatureCapability>,
    reliability_policy_id: ReliabilityPolicyId,
    status: RouteStatus,
    targets: &[RouteTargetInput],
) -> Result<(), ApplicationError> {
    validate_targets(targets, status)?;
    let deadline_policy = sqlx::query_scalar::<_, Value>(
        "SELECT deadline_policy FROM reliability_policies WHERE id=$1 FOR SHARE",
    )
    .bind(reliability_policy_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    validate_target_timeout_ceilings(targets, &deadline_policy)?;
    if let ResourceScope::Organization { organization_id } = scope {
        let grant = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM organization_reliability_policy_grants
             WHERE organization_id=$1 AND reliability_policy_id=$2 AND status='active')",
        )
        .bind(organization_id.as_uuid())
        .bind(reliability_policy_id.as_uuid())
        .fetch_one(&mut **transaction)
        .await?;
        if !grant {
            return Err(ApplicationError::Forbidden);
        }
    }
    for target in targets {
        let row = sqlx::query(
            "SELECT resource_scope_kind,organization_id,transport_kind,capability_set,status
             FROM model_deployments WHERE id=$1 FOR SHARE",
        )
        .bind(target.deployment_id.as_uuid())
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        let target_scope: CatalogScopeKind =
            parse_scope_kind(&row.try_get::<String, _>("resource_scope_kind")?)?;
        let target_organization = row
            .try_get::<Option<Uuid>, _>("organization_id")?
            .map(OrganizationId::from_uuid);
        let allowed = match scope {
            ResourceScope::Deployment => target_scope == CatalogScopeKind::Deployment,
            ResourceScope::Organization { organization_id } => {
                if target_scope == CatalogScopeKind::Organization {
                    target_organization == Some(*organization_id)
                } else {
                    sqlx::query_scalar::<_, bool>(
                        "SELECT EXISTS(SELECT 1 FROM organization_deployment_grants
                         WHERE organization_id=$1 AND deployment_id=$2 AND status='active')",
                    )
                    .bind(organization_id.as_uuid())
                    .bind(target.deployment_id.as_uuid())
                    .fetch_one(&mut **transaction)
                    .await?
                }
            }
        };
        if !allowed {
            return Err(ApplicationError::Forbidden);
        }
        let transport = parse_transport(&row.try_get::<String, _>("transport_kind")?)?;
        if !transport_supports_ingress(transport, ingress) {
            return Err(ApplicationError::Validation(
                "a route target transport does not implement the ingress protocol".to_owned(),
            ));
        }
        let target_capabilities: BTreeSet<LlmFeatureCapability> =
            deserialize_column(&row, "capability_set")?;
        if !required_capabilities.is_subset(&target_capabilities) {
            return Err(ApplicationError::Validation(
                "every target must satisfy the route required capabilities".to_owned(),
            ));
        }
    }
    Ok(())
}

async fn resolve_route_owner(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ResourceScope,
    owner_user_id: Option<UserId>,
) -> Result<Option<(UserId, Uuid)>, ApplicationError> {
    match (scope, owner_user_id) {
        (ResourceScope::Deployment, None) => Ok(None),
        (ResourceScope::Deployment, Some(_)) => Err(ApplicationError::Validation(
            "system routes cannot have an owner_user_id".to_owned(),
        )),
        (ResourceScope::Organization { organization_id }, Some(user_id)) => {
            active_membership(transaction, *organization_id, user_id)
                .await
                .map(Some)
        }
        (ResourceScope::Organization { .. }, None) => Err(ApplicationError::Validation(
            "organization routes require an explicit active owner_user_id".to_owned(),
        )),
    }
}

async fn active_membership(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    user_id: UserId,
) -> Result<(UserId, Uuid), ApplicationError> {
    let membership_id = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM memberships
         WHERE organization_id=$1 AND user_id=$2 AND status='active' FOR SHARE",
    )
    .bind(organization_id.as_uuid())
    .bind(user_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(ApplicationError::Validation(
        "route owner must be an active organization member".to_owned(),
    ))?;
    Ok((user_id, membership_id))
}

async fn load_target_inputs(
    transaction: &mut Transaction<'_, Postgres>,
    route_id: RouteId,
) -> Result<Vec<RouteTargetInput>, ApplicationError> {
    let rows = sqlx::query(
        "SELECT id,deployment_id,priority,weight,enabled,narrowing_constraints,timeout_overrides
         FROM route_targets WHERE route_id=$1 ORDER BY priority,id FOR UPDATE",
    )
    .bind(route_id.as_uuid())
    .fetch_all(&mut **transaction)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(RouteTargetInput {
                id: Some(TargetId::from_uuid(row.try_get("id")?)),
                deployment_id: DeploymentId::from_uuid(row.try_get("deployment_id")?),
                priority: u8::try_from(row.try_get::<i16, _>("priority")?)
                    .map_err(|_| ApplicationError::Internal)?,
                weight: u16::try_from(row.try_get::<i16, _>("weight")?)
                    .map_err(|_| ApplicationError::Internal)?,
                enabled: row.try_get("enabled")?,
                narrowing_constraints: row.try_get("narrowing_constraints")?,
                timeout_overrides: row.try_get("timeout_overrides")?,
            })
        })
        .collect()
}

async fn replace_targets(
    transaction: &mut Transaction<'_, Postgres>,
    route_id: RouteId,
    targets: &[RouteTargetInput],
) -> Result<(), ApplicationError> {
    let existing_rows =
        sqlx::query("SELECT id,deployment_id FROM route_targets WHERE route_id=$1 FOR UPDATE")
            .bind(route_id.as_uuid())
            .fetch_all(&mut **transaction)
            .await?;
    let existing = existing_rows
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get::<Uuid, _>("id")?,
                row.try_get::<Uuid, _>("deployment_id")?,
            ))
        })
        .collect::<Result<HashMap<_, _>, sqlx::Error>>()?;
    let retained = targets
        .iter()
        .filter_map(|target| target.id.map(TargetId::as_uuid))
        .collect::<HashSet<_>>();
    for id in existing.keys().filter(|id| !retained.contains(id)) {
        sqlx::query("DELETE FROM route_targets WHERE route_id=$1 AND id=$2")
            .bind(route_id.as_uuid())
            .bind(id)
            .execute(&mut **transaction)
            .await?;
    }
    for target in targets {
        if let Some(id) = target.id {
            let deployment_id = existing.get(&id.as_uuid()).ok_or_else(|| {
                ApplicationError::Validation(
                    "existing target IDs must belong to the route and cannot be reused".to_owned(),
                )
            })?;
            if *deployment_id != target.deployment_id.as_uuid() {
                return Err(ApplicationError::Validation(
                    "a stable target ID cannot change deployment binding".to_owned(),
                ));
            }
            sqlx::query(
                "UPDATE route_targets SET priority=$3,weight=$4,enabled=$5,
                        narrowing_constraints=$6,timeout_overrides=$7,
                        etag_token=$8,updated_at=now()
                 WHERE route_id=$1 AND id=$2",
            )
            .bind(route_id.as_uuid())
            .bind(id.as_uuid())
            .bind(i16::from(target.priority))
            .bind(i16::try_from(target.weight).map_err(|_| ApplicationError::Internal)?)
            .bind(target.enabled)
            .bind(&target.narrowing_constraints)
            .bind(&target.timeout_overrides)
            .bind(Uuid::now_v7())
            .execute(&mut **transaction)
            .await?;
        } else {
            let id = TargetId::new();
            let mut affinity = [0_u8; 16];
            rand::rng().fill_bytes(&mut affinity);
            sqlx::query(
                "INSERT INTO route_targets(
                    id,route_id,deployment_id,affinity_identity,priority,weight,enabled,
                    narrowing_constraints,timeout_overrides,etag_token
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            )
            .bind(id.as_uuid())
            .bind(route_id.as_uuid())
            .bind(target.deployment_id.as_uuid())
            .bind(affinity.to_vec())
            .bind(i16::from(target.priority))
            .bind(i16::try_from(target.weight).map_err(|_| ApplicationError::Internal)?)
            .bind(target.enabled)
            .bind(&target.narrowing_constraints)
            .bind(&target.timeout_overrides)
            .bind(Uuid::now_v7())
            .execute(&mut **transaction)
            .await
            .map_err(map_database_conflict)?;
        }
    }
    Ok(())
}

fn validate_pricing_input(input: &PublishPricingPolicyVersion) -> Result<(), ApplicationError> {
    if input.rates.currency != "USD"
        || input.rates.cost_nanos_per_unit.is_empty()
        || input.rates.cost_nanos_per_unit.len() > 64
        || input
            .rates
            .cost_nanos_per_unit
            .iter()
            .any(|(dimension, cost)| {
                dimension.is_empty()
                    || dimension.len() > 128
                    || dimension.chars().any(char::is_control)
                    || *cost == 0
            })
        || input.rounding_policy.quantum_units == 0
        || !input.publication_evidence.is_object()
    {
        return Err(ApplicationError::Validation(
            "pricing version requires USD positive nanos rates, positive rounding quantum, and object evidence"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_deployment_input(input: &CreateModelDeployment) -> Result<(), ApplicationError> {
    validate_name(&input.name)?;
    if input.upstream_model_id.trim().is_empty()
        || input.upstream_model_id.len() > 512
        || input.upstream_model_id.chars().any(char::is_control)
        || input.unpriced == input.pricing_policy_version_id.is_some()
    {
        return Err(ApplicationError::Validation(
            "deployment requires a printable upstream_model_id and exactly one pricing version or unpriced=true"
                .to_owned(),
        ));
    }
    normalize_optional(input.model_family.as_deref(), 160, "model_family")?;
    validate_deployment_mutable(
        &input.capability_set,
        &input.context_limits,
        &input.state_isolation_profile,
    )
}

fn validate_deployment_mutable(
    capabilities: &BTreeSet<LlmFeatureCapability>,
    context_limits: &Value,
    state_isolation: &Value,
) -> Result<(), ApplicationError> {
    if capabilities.len() > 32 || !context_limits.is_object() || !state_isolation.is_object() {
        return Err(ApplicationError::Validation(
            "deployment capabilities must be bounded and context/state policies must be objects"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_route_input(input: &CreateModelRoute) -> Result<(), ApplicationError> {
    if input.model_key.trim().is_empty()
        || input.model_key.len() > 512
        || input.model_key.chars().any(char::is_control)
    {
        return Err(ApplicationError::Validation(
            "model_key must contain 1 to 512 printable characters".to_owned(),
        ));
    }
    validate_policy_objects(&input.selection_policy, &input.request_policy)?;
    validate_targets(&input.targets, input.status)
}

fn validate_policy_objects(selection: &Value, request: &Value) -> Result<(), ApplicationError> {
    let selection: RouteSelectionPolicy = runtime_json_value(selection, "selection_policy")?;
    let request: RouteRequestPolicy = runtime_json_value(request, "request_policy")?;
    if !selection.is_valid() || !request.is_valid() {
        return Err(ApplicationError::Validation(
            "route policies contain an unsupported algorithm or a zero-valued ceiling".to_owned(),
        ));
    }
    Ok(())
}

fn runtime_json_value<T: DeserializeOwned>(
    value: &Value,
    name: &str,
) -> Result<T, ApplicationError> {
    serde_json::from_value(value.clone()).map_err(|error| {
        ApplicationError::Validation(format!(
            "{name} does not match its runtime contract: {error}"
        ))
    })
}

fn validate_targets(
    targets: &[RouteTargetInput],
    status: RouteStatus,
) -> Result<(), ApplicationError> {
    if targets.len() > 256 {
        return Err(ApplicationError::Validation(
            "a route cannot contain more than 256 targets".to_owned(),
        ));
    }
    let mut ids = HashSet::new();
    let mut deployments = HashSet::new();
    let mut tiers: HashMap<u8, u16> = HashMap::new();
    for target in targets {
        let narrowing: TargetNarrowingConstraints =
            runtime_json_value(&target.narrowing_constraints, "narrowing_constraints")?;
        let timeouts: TargetTimeoutOverrides =
            runtime_json_value(&target.timeout_overrides, "timeout_overrides")?;
        if target.weight == 0
            || target.weight > 256
            || !narrowing.is_valid()
            || !timeouts.is_valid()
            || target.id.is_some_and(|id| !ids.insert(id))
            || !deployments.insert(target.deployment_id)
        {
            return Err(ApplicationError::Validation(
                "targets require unique IDs/deployments, weight 1..=256, and positive narrowing constraints"
                    .to_owned(),
            ));
        }
        let total = tiers.entry(target.priority).or_default();
        *total = total.checked_add(target.weight).ok_or_else(|| {
            ApplicationError::Validation("target tier weight overflow".to_owned())
        })?;
        if *total > 256 {
            return Err(ApplicationError::Validation(
                "target weights in one priority tier cannot exceed 256".to_owned(),
            ));
        }
    }
    if status == RouteStatus::Active && targets.is_empty() {
        return Err(ApplicationError::Validation(
            "an active route requires at least one structural target".to_owned(),
        ));
    }
    Ok(())
}

fn validate_target_timeout_ceilings(
    targets: &[RouteTargetInput],
    deadline_policy: &Value,
) -> Result<(), ApplicationError> {
    let ceiling = |field: &str| {
        deadline_policy
            .get(field)
            .and_then(Value::as_u64)
            .ok_or(ApplicationError::Internal)
    };
    let connect = ceiling("connect_timeout_ms")?;
    let response_header = ceiling("response_header_timeout_ms")?;
    let body = ceiling("body_timeout_ms")?;
    let stream_idle = ceiling("stream_idle_timeout_ms")?;
    for target in targets {
        let overrides: TargetTimeoutOverrides =
            runtime_json_value(&target.timeout_overrides, "timeout_overrides")?;
        if overrides
            .connect_timeout_ms
            .is_some_and(|value| value > connect)
            || overrides
                .response_header_timeout_ms
                .is_some_and(|value| value > response_header)
            || overrides.body_timeout_ms.is_some_and(|value| value > body)
            || overrides
                .stream_idle_timeout_ms
                .is_some_and(|value| value > stream_idle)
        {
            return Err(ApplicationError::Validation(
                "target timeout overrides may only narrow the reliability deadline policy"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

fn transport_tuple_exists(
    endpoint: EndpointAdapterKind,
    credential: CredentialKind,
    transport: TransportKind,
) -> bool {
    crate::domain::COMPATIBILITY_REGISTRY_V1
        .iter()
        .any(|entry| {
            entry.endpoint == endpoint
                && entry.credential == credential
                && entry.transport == transport
        })
}

fn transport_supports_ingress(transport: TransportKind, ingress: IngressProtocolFamily) -> bool {
    crate::domain::COMPATIBILITY_REGISTRY_V1
        .iter()
        .any(|entry| {
            entry.transport == transport
                && entry.ingress == ingress
                && compatibility(
                    entry.ingress,
                    entry.endpoint,
                    entry.credential,
                    entry.transport,
                )
                .is_some()
        })
}

fn authorize_system_catalog(
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

fn authorize_deployment(
    application: &Application,
    identity: &RequestIdentity,
    scope: &ResourceScope,
    write: bool,
) -> Result<(), ApplicationError> {
    authorize_scoped(application, identity, scope, write, Capability::ManageByok)
}

fn authorize_route(
    application: &Application,
    identity: &RequestIdentity,
    scope: &ResourceScope,
    write: bool,
) -> Result<(), ApplicationError> {
    authorize_scoped(
        application,
        identity,
        scope,
        write,
        Capability::ConfigureRoutes,
    )
}

fn authorize_scoped(
    application: &Application,
    identity: &RequestIdentity,
    scope: &ResourceScope,
    write: bool,
    organization_capability: Capability,
) -> Result<(), ApplicationError> {
    let required = [if write {
        ManagementScope::Write
    } else {
        ManagementScope::Read
    }];
    match scope {
        ResourceScope::Deployment => application.authorize(
            identity,
            &required,
            AuthorizationTarget::System {
                capability: Capability::ManageGatewayCatalog,
            },
        ),
        ResourceScope::Organization { organization_id } => application.authorize(
            identity,
            &required,
            AuthorizationTarget::Organization {
                organization_id: *organization_id,
                capability: organization_capability,
            },
        ),
    }
}

async fn commit_catalog(
    application: &Application,
    transaction: Transaction<'_, Postgres>,
    identity: &RequestIdentity,
    organization_id: Option<OrganizationId>,
    resource_kind: &str,
    resource_id: String,
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
                organization_id,
                target_resource_kind: resource_kind.to_owned(),
                target_resource_id: Some(resource_id.clone()),
                operation_id: operation_id.to_owned(),
                outcome: "accepted",
                request_id: identity.request_id.clone(),
                changed_fields: changed_fields.iter().map(|field| (*field).to_owned()).collect(),
                safe_details: json!({}),
            },
            Some(&RuntimeEvent {
                event_kind: format!("{resource_kind}.changed"),
                affected_scope: json!({"resource_id":resource_id,"organization_id":organization_id}),
                security_tightening,
            }),
        )
        .await?;
    Ok(())
}

fn page_from_catalog_rows<T>(
    rows: Vec<sqlx::postgres::PgRow>,
    limit: u32,
    family: &str,
    parse: impl Fn(sqlx::postgres::PgRow) -> Result<T, ApplicationError>,
) -> Result<Page<T>, ApplicationError>
where
    T: CatalogPageIdentity,
{
    let has_more = rows.len() > limit as usize;
    let items = rows
        .into_iter()
        .take(limit as usize)
        .map(parse)
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor = has_more
        .then(|| items.last().map(|item| item.catalog_id().to_string()))
        .flatten();
    let _ = family;
    Ok(Page { items, next_cursor })
}

trait CatalogPageIdentity {
    fn catalog_id(&self) -> Uuid;
}

impl CatalogPageIdentity for ModelDeployment {
    fn catalog_id(&self) -> Uuid {
        self.id.as_uuid()
    }
}

fn scope_family(base: &str, scope: &ResourceScope) -> String {
    match scope {
        ResourceScope::Deployment => format!("{base}:deployment"),
        ResourceScope::Organization { organization_id } => {
            format!("{base}:organization:{organization_id}")
        }
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

fn deployment_operation_id(scope: &ResourceScope, action: &str) -> &'static str {
    match (scope, action) {
        (ResourceScope::Deployment, "create") => "system.model_deployments.create",
        (ResourceScope::Deployment, "update") => "system.model_deployments.update",
        (ResourceScope::Deployment, "validate") => "system.model_deployments.validate",
        (ResourceScope::Organization { .. }, "create") => "organization.model_deployments.create",
        (ResourceScope::Organization { .. }, "update") => "organization.model_deployments.update",
        (ResourceScope::Organization { .. }, "validate") => {
            "organization.model_deployments.validate"
        }
        _ => unreachable!("closed model deployment operation"),
    }
}

fn route_operation_id(scope: &ResourceScope, action: &str) -> &'static str {
    match (scope, action) {
        (ResourceScope::Deployment, "create") => "system.model_routes.create",
        (ResourceScope::Deployment, "update") => "system.model_routes.update",
        (ResourceScope::Organization { .. }, "create") => "organization.model_routes.create",
        (ResourceScope::Organization { .. }, "update") => "organization.model_routes.update",
        _ => unreachable!("closed model route operation"),
    }
}

fn actor_value(identity: &RequestIdentity) -> Result<Value, ApplicationError> {
    serde_json::to_value(Actor::from(&identity.principal)).map_err(|_| ApplicationError::Internal)
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

fn normalize_optional(
    value: Option<&str>,
    maximum: usize,
    field: &str,
) -> Result<Option<String>, ApplicationError> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            if value.len() > maximum || value.chars().any(char::is_control) {
                Err(ApplicationError::Validation(format!(
                    "{field} exceeds its printable character limit"
                )))
            } else {
                Ok(value.to_owned())
            }
        })
        .transpose()
}

fn deserialize_column<T: serde::de::DeserializeOwned>(
    row: &sqlx::postgres::PgRow,
    field: &str,
) -> Result<T, ApplicationError> {
    serde_json::from_value(row.try_get(field)?).map_err(|_| ApplicationError::Internal)
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

fn apply_name(
    target: &mut String,
    field: UpdateField<String>,
    changed: &mut Vec<&'static str>,
) -> Result<(), ApplicationError> {
    match field {
        UpdateField::Omitted => {}
        UpdateField::Null => return Err(null_error("name")),
        UpdateField::Value(value) => {
            validate_name(&value)?;
            *target = value.trim().to_owned();
            changed.push("name");
        }
    }
    Ok(())
}

fn apply_catalog_status(
    target: &mut String,
    field: UpdateField<CatalogStatus>,
    changed: &mut Vec<&'static str>,
) -> Result<(), ApplicationError> {
    match field {
        UpdateField::Omitted => {}
        UpdateField::Null => return Err(null_error("status")),
        UpdateField::Value(value) => {
            *target = value.as_str().to_owned();
            changed.push("status");
        }
    }
    Ok(())
}

fn apply_validated_status(
    target: &mut String,
    field: UpdateField<ValidatedCatalogStatus>,
    changed: &mut Vec<&'static str>,
) -> Result<(), ApplicationError> {
    match field {
        UpdateField::Omitted => {}
        UpdateField::Null => return Err(null_error("status")),
        UpdateField::Value(value) => {
            *target = value.as_str().to_owned();
            changed.push("status");
        }
    }
    Ok(())
}

fn apply_optional_string(
    target: &mut Option<String>,
    field: UpdateField<String>,
    maximum: usize,
    name: &'static str,
    changed: &mut Vec<&'static str>,
) -> Result<(), ApplicationError> {
    match field {
        UpdateField::Omitted => {}
        UpdateField::Null => {
            *target = None;
            changed.push(name);
        }
        UpdateField::Value(value) => {
            *target = normalize_optional(Some(&value), maximum, name)?;
            changed.push(name);
        }
    }
    Ok(())
}

fn apply_required<T>(
    target: &mut T,
    field: UpdateField<T>,
    name: &'static str,
    changed: &mut Vec<&'static str>,
) -> Result<(), ApplicationError> {
    match field {
        UpdateField::Omitted => {}
        UpdateField::Null => return Err(null_error(name)),
        UpdateField::Value(value) => {
            *target = value;
            changed.push(name);
        }
    }
    Ok(())
}

fn apply_object(
    target: &mut Value,
    field: UpdateField<Value>,
    name: &'static str,
    changed: &mut Vec<&'static str>,
) -> Result<(), ApplicationError> {
    match field {
        UpdateField::Omitted => {}
        UpdateField::Null => return Err(null_error(name)),
        UpdateField::Value(value) => {
            if !value.is_object() {
                return Err(ApplicationError::Validation(format!(
                    "{name} must be an object"
                )));
            }
            *target = value;
            changed.push(name);
        }
    }
    Ok(())
}

fn empty_update() -> ApplicationError {
    ApplicationError::Validation("at least one update field is required".to_owned())
}

fn null_error(field: &str) -> ApplicationError {
    ApplicationError::Validation(format!("{field} cannot be null"))
}

fn parse_catalog_status(value: &str) -> Result<CatalogStatus, ApplicationError> {
    match value {
        "active" => Ok(CatalogStatus::Active),
        "disabled" => Ok(CatalogStatus::Disabled),
        _ => Err(ApplicationError::Internal),
    }
}

fn parse_validated_status(value: &str) -> Result<ValidatedCatalogStatus, ApplicationError> {
    match value {
        "active" => Ok(ValidatedCatalogStatus::Active),
        "disabled" => Ok(ValidatedCatalogStatus::Disabled),
        "validation_failed" => Ok(ValidatedCatalogStatus::ValidationFailed),
        _ => Err(ApplicationError::Internal),
    }
}

fn parse_route_status(value: &str) -> Result<RouteStatus, ApplicationError> {
    match value {
        "draft" => Ok(RouteStatus::Draft),
        "active" => Ok(RouteStatus::Active),
        "disabled" => Ok(RouteStatus::Disabled),
        _ => Err(ApplicationError::Internal),
    }
}

fn parse_scope_kind(value: &str) -> Result<CatalogScopeKind, ApplicationError> {
    match value {
        "deployment" => Ok(CatalogScopeKind::Deployment),
        "organization" => Ok(CatalogScopeKind::Organization),
        _ => Err(ApplicationError::Internal),
    }
}

fn parse_ingress(value: &str) -> Result<IngressProtocolFamily, ApplicationError> {
    match value {
        "anthropic_messages" => Ok(IngressProtocolFamily::AnthropicMessages),
        "openai_chat_completions" => Ok(IngressProtocolFamily::OpenaiChatCompletions),
        "openai_responses" => Ok(IngressProtocolFamily::OpenaiResponses),
        "google_gemini" => Ok(IngressProtocolFamily::GoogleGemini),
        _ => Err(ApplicationError::Internal),
    }
}

fn parse_endpoint_adapter(value: &str) -> Result<EndpointAdapterKind, ApplicationError> {
    match value {
        "anthropic_api" => Ok(EndpointAdapterKind::AnthropicApi),
        "aws_bedrock_runtime" => Ok(EndpointAdapterKind::AwsBedrockRuntime),
        "google_vertex" => Ok(EndpointAdapterKind::GoogleVertex),
        "google_gemini_api" => Ok(EndpointAdapterKind::GoogleGeminiApi),
        "openai_api" => Ok(EndpointAdapterKind::OpenaiApi),
        "openai_codex" => Ok(EndpointAdapterKind::OpenaiCodex),
        "azure_openai" => Ok(EndpointAdapterKind::AzureOpenai),
        _ => Err(ApplicationError::Internal),
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

fn parse_transport(value: &str) -> Result<TransportKind, ApplicationError> {
    crate::domain::COMPATIBILITY_REGISTRY_V1
        .iter()
        .find(|entry| entry.transport.as_str() == value)
        .map(|entry| entry.transport)
        .ok_or(ApplicationError::Internal)
}

fn map_database_conflict(error: sqlx::Error) -> ApplicationError {
    if error.as_database_error().is_some() {
        ApplicationError::Conflict("the catalog resource conflicts with current state".to_owned())
    } else {
        error.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(priority: u8, weight: u16, enabled: bool) -> RouteTargetInput {
        RouteTargetInput {
            id: None,
            deployment_id: DeploymentId::new(),
            priority,
            weight,
            enabled,
            narrowing_constraints: json!({}),
            timeout_overrides: json!({}),
        }
    }

    #[test]
    fn route_targets_enforce_complete_set_invariants() {
        assert!(
            validate_targets(
                &[target(0, 128, true), target(0, 128, true)],
                RouteStatus::Active
            )
            .is_ok()
        );
        assert!(
            validate_targets(
                &[target(0, 256, true), target(0, 1, true)],
                RouteStatus::Active
            )
            .is_err()
        );
        assert!(validate_targets(&[target(0, 1, false)], RouteStatus::Active).is_ok());
        assert!(validate_targets(&[], RouteStatus::Active).is_err());
    }

    #[test]
    fn route_runtime_json_is_validated_before_persistence() {
        assert!(validate_policy_objects(&json!({}), &json!({})).is_ok());
        assert!(
            validate_policy_objects(&json!({"unexpected_runtime_field":true}), &json!({})).is_err()
        );
        assert!(validate_policy_objects(&json!({}), &json!({"max_stream_seconds":0})).is_err());

        let mut invalid_target = target(0, 1, true);
        invalid_target.timeout_overrides = json!({"connect_timeout_ms":"not-an-integer"});
        assert!(validate_targets(&[invalid_target], RouteStatus::Active).is_err());

        let mut unknown_target = target(0, 1, true);
        unknown_target.narrowing_constraints = json!({"unexpected_runtime_field":true});
        assert!(validate_targets(&[unknown_target], RouteStatus::Active).is_err());
    }

    #[test]
    fn target_timeout_overrides_only_narrow_reliability_deadlines() {
        let deadline = json!({
            "connect_timeout_ms":100,
            "response_header_timeout_ms":200,
            "body_timeout_ms":300,
            "stream_idle_timeout_ms":400
        });
        let mut target = target(0, 1, true);
        target.timeout_overrides = json!({"connect_timeout_ms":100});
        assert!(validate_target_timeout_ceilings(&[target.clone()], &deadline).is_ok());
        target.timeout_overrides = json!({"connect_timeout_ms":101});
        assert!(validate_target_timeout_ceilings(&[target], &deadline).is_err());
    }

    #[test]
    fn pricing_versions_require_positive_usd_rates() {
        let valid = PublishPricingPolicyVersion {
            rates: crate::domain::PricingRates {
                currency: "USD".to_owned(),
                cost_nanos_per_unit: [("input_token".to_owned(), 10)].into(),
            },
            rounding_policy: crate::domain::PricingRoundingPolicy {
                mode: crate::domain::PricingRoundingMode::Up,
                quantum_units: 1,
            },
            organization_usable: true,
            publication_evidence: json!({"source":"test"}),
        };
        assert!(validate_pricing_input(&valid).is_ok());
    }
}
