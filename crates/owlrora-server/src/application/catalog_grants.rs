use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::{
    adapters::postgres::{AuditRecord, RuntimeEvent},
    domain::{Actor, Capability, ManagementScope, OrganizationId, SystemRouteGrantCeilings},
};

use super::{
    Application, ApplicationError, AuthorizationTarget, AvailableModelDeployment,
    AvailableModelRoute, AvailableReliabilityPolicy, AvailableUpstreamEndpoint, CatalogGrantSet,
    EntityTag, Page, RequestIdentity, UpdateCatalogGrantSet,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogGrantKind {
    SystemRoute,
    Endpoint,
    Deployment,
    ReliabilityPolicy,
}

impl CatalogGrantKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SystemRoute => "system_route",
            Self::Endpoint => "endpoint",
            Self::Deployment => "deployment",
            Self::ReliabilityPolicy => "reliability_policy",
        }
    }

    const fn table(self) -> &'static str {
        match self {
            Self::SystemRoute => "organization_route_grants",
            Self::Endpoint => "organization_endpoint_grants",
            Self::Deployment => "organization_deployment_grants",
            Self::ReliabilityPolicy => "organization_reliability_policy_grants",
        }
    }

    const fn id_column(self) -> &'static str {
        match self {
            Self::SystemRoute => "route_id",
            Self::Endpoint => "endpoint_id",
            Self::Deployment => "deployment_id",
            Self::ReliabilityPolicy => "reliability_policy_id",
        }
    }

    const fn resource_table(self) -> &'static str {
        match self {
            Self::SystemRoute => "model_routes",
            Self::Endpoint => "upstream_endpoints",
            Self::Deployment => "model_deployments",
            Self::ReliabilityPolicy => "reliability_policies",
        }
    }

    const fn operation_family(self) -> &'static str {
        match self {
            Self::SystemRoute => "organization.system_route_grants",
            Self::Endpoint => "organization.endpoint_grants",
            Self::Deployment => "organization.deployment_grants",
            Self::ReliabilityPolicy => "organization.reliability_policy_grants",
        }
    }

    const fn update_operation_id(self) -> &'static str {
        match self {
            Self::SystemRoute => "organization.system_route_grants.update",
            Self::Endpoint => "organization.endpoint_grants.update",
            Self::Deployment => "organization.deployment_grants.update",
            Self::ReliabilityPolicy => "organization.reliability_policy_grants.update",
        }
    }
}

impl Application {
    pub async fn list_available_endpoints(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<AvailableUpstreamEndpoint>, ApplicationError> {
        authorize_discovery(self, identity, organization_id)?;
        let family = format!("available_endpoints:{organization_id}");
        let (cursor, limit) = super::resources::page_parameters(&family, cursor, limit)?;
        let rows = sqlx::query(
            "SELECT endpoint.id,grant_row.endpoint_id IS NOT NULL AS granted
             FROM upstream_endpoints endpoint
             LEFT JOIN organization_endpoint_grants grant_row
               ON grant_row.endpoint_id=endpoint.id AND grant_row.organization_id=$1
              AND grant_row.status='active'
             WHERE ($2::uuid IS NULL OR endpoint.id>$2)
             ORDER BY endpoint.id LIMIT $3",
        )
        .bind(organization_id.as_uuid())
        .bind(cursor)
        .bind(i64::from(limit) + 1)
        .fetch_all(self.store.pool())
        .await?;
        let has_more = rows.len() > limit as usize;
        let selected = rows.into_iter().take(limit as usize).collect::<Vec<_>>();
        let mut items = Vec::with_capacity(selected.len());
        for row in selected {
            let id = crate::domain::EndpointId::from_uuid(row.try_get("id")?);
            let endpoint = super::catalog::load_endpoint(self.store.pool(), id)
                .await?
                .0;
            items.push(AvailableUpstreamEndpoint {
                endpoint,
                granted: row.try_get("granted")?,
            });
        }
        let next_cursor = has_more
            .then(|| items.last().map(|item| item.endpoint.id.to_string()))
            .flatten();
        Ok(Page { items, next_cursor })
    }

    pub async fn list_available_deployments(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<AvailableModelDeployment>, ApplicationError> {
        authorize_discovery(self, identity, organization_id)?;
        let family = format!("available_deployments:{organization_id}");
        let (cursor, limit) = super::resources::page_parameters(&family, cursor, limit)?;
        let rows = sqlx::query(
            "SELECT deployment.id,grant_row.deployment_id IS NOT NULL AS granted
             FROM model_deployments deployment
             LEFT JOIN organization_deployment_grants grant_row
               ON grant_row.deployment_id=deployment.id AND grant_row.organization_id=$1
              AND grant_row.status='active'
             WHERE deployment.resource_scope_kind='deployment'
               AND ($2::uuid IS NULL OR deployment.id>$2)
             ORDER BY deployment.id LIMIT $3",
        )
        .bind(organization_id.as_uuid())
        .bind(cursor)
        .bind(i64::from(limit) + 1)
        .fetch_all(self.store.pool())
        .await?;
        let has_more = rows.len() > limit as usize;
        let selected = rows.into_iter().take(limit as usize).collect::<Vec<_>>();
        let mut items = Vec::with_capacity(selected.len());
        for row in selected {
            let id = crate::domain::DeploymentId::from_uuid(row.try_get("id")?);
            let deployment = super::gateway_catalog::load_deployment(
                self.store.pool(),
                &crate::domain::ResourceScope::Deployment,
                id,
            )
            .await?
            .0;
            items.push(AvailableModelDeployment {
                deployment,
                granted: row.try_get("granted")?,
            });
        }
        let next_cursor = has_more
            .then(|| items.last().map(|item| item.deployment.id.to_string()))
            .flatten();
        Ok(Page { items, next_cursor })
    }

    pub async fn list_available_reliability_policies(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<AvailableReliabilityPolicy>, ApplicationError> {
        authorize_discovery(self, identity, organization_id)?;
        let family = format!("available_reliability_policies:{organization_id}");
        let (cursor, limit) = super::resources::page_parameters(&family, cursor, limit)?;
        let rows = sqlx::query(
            "SELECT policy.id,grant_row.reliability_policy_id IS NOT NULL AS granted
             FROM reliability_policies policy
             LEFT JOIN organization_reliability_policy_grants grant_row
               ON grant_row.reliability_policy_id=policy.id AND grant_row.organization_id=$1
              AND grant_row.status='active'
             WHERE ($2::uuid IS NULL OR policy.id>$2)
             ORDER BY policy.id LIMIT $3",
        )
        .bind(organization_id.as_uuid())
        .bind(cursor)
        .bind(i64::from(limit) + 1)
        .fetch_all(self.store.pool())
        .await?;
        let has_more = rows.len() > limit as usize;
        let selected = rows.into_iter().take(limit as usize).collect::<Vec<_>>();
        let mut items = Vec::with_capacity(selected.len());
        for row in selected {
            let id = crate::domain::ReliabilityPolicyId::from_uuid(row.try_get("id")?);
            let reliability_policy = super::catalog::load_reliability(self.store.pool(), id)
                .await?
                .0;
            items.push(AvailableReliabilityPolicy {
                reliability_policy,
                granted: row.try_get("granted")?,
            });
        }
        let next_cursor = has_more
            .then(|| {
                items
                    .last()
                    .map(|item| item.reliability_policy.id.to_string())
            })
            .flatten();
        Ok(Page { items, next_cursor })
    }

    pub async fn list_available_routes(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<AvailableModelRoute>, ApplicationError> {
        authorize_discovery(self, identity, organization_id)?;
        let family = format!("available_routes:{organization_id}");
        let (cursor, limit) = super::resources::page_parameters(&family, cursor, limit)?;
        let rows = sqlx::query(
            "SELECT route.id,grant_row.route_id IS NOT NULL AS granted
             FROM model_routes route
             LEFT JOIN organization_route_grants grant_row
               ON grant_row.route_id=route.id AND grant_row.organization_id=$1
              AND grant_row.status='active'
             WHERE route.resource_scope_kind='deployment'
               AND ($2::uuid IS NULL OR route.id>$2)
             ORDER BY route.id LIMIT $3",
        )
        .bind(organization_id.as_uuid())
        .bind(cursor)
        .bind(i64::from(limit) + 1)
        .fetch_all(self.store.pool())
        .await?;
        let has_more = rows.len() > limit as usize;
        let selected = rows.into_iter().take(limit as usize).collect::<Vec<_>>();
        let mut connection = self.store.pool().acquire().await?;
        let mut items = Vec::with_capacity(selected.len());
        for row in selected {
            let id = crate::domain::RouteId::from_uuid(row.try_get("id")?);
            let route = super::gateway_catalog::load_route(
                &mut connection,
                &crate::domain::ResourceScope::Deployment,
                id,
            )
            .await?
            .0;
            items.push(AvailableModelRoute {
                route,
                granted: row.try_get("granted")?,
            });
        }
        let next_cursor = has_more
            .then(|| items.last().map(|item| item.route.id.to_string()))
            .flatten();
        Ok(Page { items, next_cursor })
    }

    pub async fn get_catalog_grant_set(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        kind: CatalogGrantKind,
    ) -> Result<(CatalogGrantSet, EntityTag), ApplicationError> {
        authorize_grants(self, identity, false)?;
        load_grant_set(self, organization_id, kind).await
    }

    pub async fn update_catalog_grant_set(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        kind: CatalogGrantKind,
        if_match: Option<&str>,
        input: UpdateCatalogGrantSet,
    ) -> Result<(CatalogGrantSet, EntityTag), ApplicationError> {
        authorize_grants(self, identity, true)?;
        if input.resource_ids.len() > 4096 {
            return Err(ApplicationError::Validation(
                "catalog grant sets cannot exceed 4096 resources".to_owned(),
            ));
        }
        let ids = input
            .resource_ids
            .iter()
            .map(|value| {
                Uuid::parse_str(value).map_err(|_| {
                    ApplicationError::Validation(
                        "catalog grant resource IDs must be exact UUIDs".to_owned(),
                    )
                })
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let system_route_ceilings =
            normalize_system_route_ceilings(kind, &ids, input.system_route_ceilings)?;
        let mut transaction = self.store.begin().await?;
        let row = sqlx::query(
            "SELECT etag_token FROM organization_catalog_grant_sets
             WHERE organization_id=$1 AND grant_kind=$2 FOR UPDATE",
        )
        .bind(organization_id.as_uuid())
        .bind(kind.as_str())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        require_if_match(
            if_match,
            &EntityTag::for_resource(
                kind.operation_family(),
                organization_id.as_uuid(),
                row.try_get("etag_token")?,
            ),
        )?;
        let organization_active = sqlx::query_scalar::<_, bool>(
            "SELECT status='active' FROM organizations WHERE id=$1 FOR SHARE",
        )
        .bind(organization_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        if !organization_active {
            return Err(ApplicationError::Forbidden);
        }
        validate_resources(&mut transaction, kind, &ids).await?;
        let old_ids = load_ids(&mut transaction, organization_id, kind).await?;
        let old_system_route_ceilings =
            load_system_route_ceilings(&mut transaction, organization_id, kind).await?;
        let tightening = !old_ids.is_subset(&ids)
            || old_ids.intersection(&ids).any(|id| {
                old_system_route_ceilings
                    .get(id)
                    .zip(system_route_ceilings.get(id))
                    .is_some_and(|(old, new)| system_route_ceiling_tightened(old, new))
            });
        replace_rows(
            &mut transaction,
            identity,
            organization_id,
            kind,
            &ids,
            &system_route_ceilings,
        )
        .await?;
        sqlx::query(
            "UPDATE organization_catalog_grant_sets
             SET etag_token=$3,updated_at=now()
             WHERE organization_id=$1 AND grant_kind=$2",
        )
        .bind(organization_id.as_uuid())
        .bind(kind.as_str())
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let result = load_grant_set_in_transaction(&mut transaction, organization_id, kind).await?;
        self.store
            .commit_command(
                transaction,
                &AuditRecord {
                    actor: Some(Actor::from(&identity.principal)),
                    authentication_evidence: json!({
                        "method":identity.principal.authentication_method,
                        "session_id":identity.principal.session_id,
                        "external_issuer_id":identity.principal.external_issuer_id,
                    }),
                    organization_id: Some(organization_id),
                    target_resource_kind: "organization_catalog_grant_set".to_owned(),
                    target_resource_id: Some(format!("{}:{}", organization_id, kind.as_str())),
                    operation_id: kind.update_operation_id().to_owned(),
                    outcome: "accepted",
                    request_id: identity.request_id.clone(),
                    changed_fields: if kind == CatalogGrantKind::SystemRoute {
                        vec![
                            "resource_ids".to_owned(),
                            "system_route_ceilings".to_owned(),
                        ]
                    } else {
                        vec!["resource_ids".to_owned()]
                    },
                    safe_details: json!({
                        "grant_kind":kind.as_str(),
                        "resource_count":ids.len(),
                        "ceiling_count":system_route_ceilings.len(),
                    }),
                },
                Some(&RuntimeEvent {
                    event_kind: "organization_catalog_grants.changed".to_owned(),
                    affected_scope: json!({
                        "organization_id":organization_id,
                        "grant_kind":kind.as_str(),
                    }),
                    security_tightening: tightening,
                }),
            )
            .await?;
        self.publish_committed_runtime(&identity.request_id, kind.update_operation_id())
            .await;
        Ok(result)
    }
}

async fn load_grant_set(
    application: &Application,
    organization_id: OrganizationId,
    kind: CatalogGrantKind,
) -> Result<(CatalogGrantSet, EntityTag), ApplicationError> {
    let mut transaction = application.store.begin().await?;
    let result = load_grant_set_in_transaction(&mut transaction, organization_id, kind).await?;
    transaction.rollback().await?;
    Ok(result)
}

async fn load_grant_set_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    kind: CatalogGrantKind,
) -> Result<(CatalogGrantSet, EntityTag), ApplicationError> {
    let row = sqlx::query(
        "SELECT etag_token FROM organization_catalog_grant_sets
         WHERE organization_id=$1 AND grant_kind=$2",
    )
    .bind(organization_id.as_uuid())
    .bind(kind.as_str())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    let ids = load_ids(transaction, organization_id, kind).await?;
    let system_route_ceilings = load_system_route_ceilings(transaction, organization_id, kind)
        .await?
        .into_iter()
        .map(|(id, ceilings)| (id.to_string(), ceilings))
        .collect();
    Ok((
        CatalogGrantSet {
            resource_ids: ids.into_iter().map(|id| id.to_string()).collect(),
            system_route_ceilings,
        },
        EntityTag::for_resource(
            kind.operation_family(),
            organization_id.as_uuid(),
            row.try_get("etag_token")?,
        ),
    ))
}

async fn load_ids(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    kind: CatalogGrantKind,
) -> Result<BTreeSet<Uuid>, ApplicationError> {
    let query = format!(
        "SELECT {} AS resource_id FROM {} WHERE organization_id=$1 AND status='active' ORDER BY {}",
        kind.id_column(),
        kind.table(),
        kind.id_column(),
    );
    let rows = sqlx::query(&query)
        .bind(organization_id.as_uuid())
        .fetch_all(&mut **transaction)
        .await?;
    rows.into_iter()
        .map(|row| row.try_get("resource_id"))
        .collect::<Result<_, _>>()
        .map_err(Into::into)
}

fn normalize_system_route_ceilings(
    kind: CatalogGrantKind,
    ids: &BTreeSet<Uuid>,
    input: BTreeMap<String, SystemRouteGrantCeilings>,
) -> Result<BTreeMap<Uuid, SystemRouteGrantCeilings>, ApplicationError> {
    if kind != CatalogGrantKind::SystemRoute {
        if input.is_empty() {
            return Ok(BTreeMap::new());
        }
        return Err(ApplicationError::Validation(
            "system_route_ceilings are valid only for system route grants".to_owned(),
        ));
    }

    let mut ceilings = ids
        .iter()
        .copied()
        .map(|id| (id, SystemRouteGrantCeilings::default()))
        .collect::<BTreeMap<_, _>>();
    for (value, ceiling) in input {
        let id = Uuid::parse_str(&value).map_err(|_| {
            ApplicationError::Validation(
                "system route ceiling keys must be exact route UUIDs".to_owned(),
            )
        })?;
        if !ids.contains(&id) {
            return Err(ApplicationError::Validation(
                "system route ceilings must reference a route in resource_ids".to_owned(),
            ));
        }
        if !ceiling.is_valid() {
            return Err(ApplicationError::Validation(
                "system route ceilings must contain positive limits".to_owned(),
            ));
        }
        ceilings.insert(id, ceiling);
    }
    Ok(ceilings)
}

async fn load_system_route_ceilings(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    kind: CatalogGrantKind,
) -> Result<BTreeMap<Uuid, SystemRouteGrantCeilings>, ApplicationError> {
    if kind != CatalogGrantKind::SystemRoute {
        return Ok(BTreeMap::new());
    }
    let rows = sqlx::query(
        "SELECT route_id,ceilings FROM organization_route_grants
         WHERE organization_id=$1 AND status='active' ORDER BY route_id",
    )
    .bind(organization_id.as_uuid())
    .fetch_all(&mut **transaction)
    .await?;
    let mut ceilings = BTreeMap::new();
    for row in rows {
        let value: Value = row.try_get("ceilings")?;
        let ceiling: SystemRouteGrantCeilings =
            serde_json::from_value(value).map_err(|_| ApplicationError::Internal)?;
        if !ceiling.is_valid() {
            return Err(ApplicationError::Internal);
        }
        ceilings.insert(row.try_get("route_id")?, ceiling);
    }
    Ok(ceilings)
}

fn system_route_ceiling_tightened(
    old: &SystemRouteGrantCeilings,
    new: &SystemRouteGrantCeilings,
) -> bool {
    let capabilities_tightened = match (&old.allowed_capabilities, &new.allowed_capabilities) {
        (None, Some(_)) => true,
        (Some(old), Some(new)) => !new.is_superset(old),
        _ => false,
    };
    capabilities_tightened
        || optional_limit_tightened(old.max_context_bytes, new.max_context_bytes)
        || optional_limit_tightened(old.max_output_units, new.max_output_units)
        || optional_limit_tightened(
            old.request_policy.max_header_bytes,
            new.request_policy.max_header_bytes,
        )
        || optional_limit_tightened(
            old.request_policy.max_request_body_bytes,
            new.request_policy.max_request_body_bytes,
        )
        || optional_limit_tightened(
            old.request_policy.max_response_body_bytes,
            new.request_policy.max_response_body_bytes,
        )
        || optional_limit_tightened(
            old.request_policy.max_stream_seconds,
            new.request_policy.max_stream_seconds,
        )
        || optional_limit_tightened(
            old.request_policy.state_origin_ttl_seconds,
            new.request_policy.state_origin_ttl_seconds,
        )
}

fn optional_limit_tightened<T: Ord>(old: Option<T>, new: Option<T>) -> bool {
    new.is_some_and(|new| old.is_none_or(|old| new < old))
}

async fn validate_resources(
    transaction: &mut Transaction<'_, Postgres>,
    kind: CatalogGrantKind,
    ids: &BTreeSet<Uuid>,
) -> Result<(), ApplicationError> {
    if ids.is_empty() {
        return Ok(());
    }
    let query = match kind {
        CatalogGrantKind::SystemRoute | CatalogGrantKind::Deployment => format!(
            "SELECT id FROM {} WHERE id=ANY($1) AND resource_scope_kind='deployment' FOR SHARE",
            kind.resource_table(),
        ),
        _ => format!(
            "SELECT id FROM {} WHERE id=ANY($1) FOR SHARE",
            kind.resource_table(),
        ),
    };
    let present = sqlx::query_scalar::<_, Uuid>(&query)
        .bind(ids.iter().copied().collect::<Vec<_>>())
        .fetch_all(&mut **transaction)
        .await?;
    if present.len() != ids.len() {
        return Err(ApplicationError::Validation(
            "catalog grant set contains a missing or non-system resource".to_owned(),
        ));
    }
    Ok(())
}

async fn replace_rows(
    transaction: &mut Transaction<'_, Postgres>,
    identity: &RequestIdentity,
    organization_id: OrganizationId,
    kind: CatalogGrantKind,
    ids: &BTreeSet<Uuid>,
    system_route_ceilings: &BTreeMap<Uuid, SystemRouteGrantCeilings>,
) -> Result<(), ApplicationError> {
    let delete = format!("DELETE FROM {} WHERE organization_id=$1", kind.table());
    sqlx::query(&delete)
        .bind(organization_id.as_uuid())
        .execute(&mut **transaction)
        .await?;
    let actor: Value = serde_json::to_value(Actor::from(&identity.principal))
        .map_err(|_| ApplicationError::Internal)?;
    for id in ids {
        if kind == CatalogGrantKind::SystemRoute {
            sqlx::query(
                "INSERT INTO organization_route_grant_identities(
                    id,organization_id,route_id,created_by_principal
                 ) VALUES ($1,$2,$3,$4)
                 ON CONFLICT (organization_id,route_id) DO NOTHING",
            )
            .bind(Uuid::now_v7())
            .bind(organization_id.as_uuid())
            .bind(id)
            .bind(&actor)
            .execute(&mut **transaction)
            .await?;
        }
        let insert = if kind == CatalogGrantKind::SystemRoute {
            format!(
                "INSERT INTO {}(organization_id,{},ceilings,status,created_by_principal,etag_token)
                 VALUES ($1,$2,$3,'active',$4,$5)",
                kind.table(),
                kind.id_column(),
            )
        } else {
            format!(
                "INSERT INTO {}(organization_id,{},status,created_by_principal,etag_token)
                 VALUES ($1,$2,'active',$3,$4)",
                kind.table(),
                kind.id_column(),
            )
        };
        let mut query = sqlx::query(&insert)
            .bind(organization_id.as_uuid())
            .bind(id);
        if kind == CatalogGrantKind::SystemRoute {
            let ceilings = system_route_ceilings
                .get(id)
                .ok_or(ApplicationError::Internal)?;
            query =
                query.bind(serde_json::to_value(ceilings).map_err(|_| ApplicationError::Internal)?);
        }
        query
            .bind(&actor)
            .bind(Uuid::now_v7())
            .execute(&mut **transaction)
            .await?;
    }
    Ok(())
}

fn authorize_discovery(
    application: &Application,
    identity: &RequestIdentity,
    organization_id: OrganizationId,
) -> Result<(), ApplicationError> {
    application.authorize(
        identity,
        &[ManagementScope::Read],
        AuthorizationTarget::Organization {
            organization_id,
            capability: Capability::ReadOrganization,
        },
    )
}

fn authorize_grants(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{LlmFeatureCapability, RouteGrantRequestPolicyCeilings};

    #[test]
    fn catalog_grant_update_rejects_unknown_top_level_fields() {
        let route_id = Uuid::now_v7();
        assert!(
            serde_json::from_value::<UpdateCatalogGrantSet>(json!({
                "resource_ids":[route_id],
                "system_route_ceiling":{"not-read":{"max_output_units":10}}
            }))
            .is_err()
        );
    }

    #[test]
    fn catalog_grant_update_rejects_duplicate_and_oversized_resource_arrays() {
        let route_id = Uuid::now_v7().to_string();
        assert!(
            serde_json::from_value::<UpdateCatalogGrantSet>(json!({
                "resource_ids":[route_id.clone(),route_id]
            }))
            .is_err()
        );
        let oversized = (0..4097)
            .map(|_| Uuid::now_v7().to_string())
            .collect::<Vec<_>>();
        assert!(
            serde_json::from_value::<UpdateCatalogGrantSet>(json!({
                "resource_ids":oversized
            }))
            .is_err()
        );
    }

    #[test]
    fn catalog_grant_update_rejects_explicit_null_ceilings() {
        let route_id = Uuid::now_v7();
        for ceilings in [
            json!({"max_output_units":null}),
            json!({"allowed_capabilities":null}),
            json!({"request_policy":{"max_stream_seconds":null}}),
        ] {
            assert!(
                serde_json::from_value::<UpdateCatalogGrantSet>(json!({
                    "resource_ids":[route_id],
                    "system_route_ceilings":{route_id.to_string():ceilings}
                }))
                .is_err()
            );
        }
    }

    #[test]
    fn route_grant_security_revision_changes_only_for_directional_tightening() {
        let unrestricted = SystemRouteGrantCeilings::default();
        let restricted = SystemRouteGrantCeilings {
            allowed_capabilities: Some(BTreeSet::from([LlmFeatureCapability::Streaming])),
            max_output_units: Some(100),
            request_policy: RouteGrantRequestPolicyCeilings {
                max_stream_seconds: Some(30),
                ..RouteGrantRequestPolicyCeilings::default()
            },
            ..SystemRouteGrantCeilings::default()
        };
        assert!(system_route_ceiling_tightened(&unrestricted, &restricted));
        assert!(!system_route_ceiling_tightened(&restricted, &unrestricted));

        let expanded = SystemRouteGrantCeilings {
            allowed_capabilities: Some(BTreeSet::from([
                LlmFeatureCapability::Streaming,
                LlmFeatureCapability::Tools,
            ])),
            max_output_units: Some(200),
            request_policy: RouteGrantRequestPolicyCeilings {
                max_stream_seconds: Some(60),
                ..RouteGrantRequestPolicyCeilings::default()
            },
            ..SystemRouteGrantCeilings::default()
        };
        assert!(!system_route_ceiling_tightened(&restricted, &expanded));
        assert!(system_route_ceiling_tightened(&expanded, &restricted));
    }
}
