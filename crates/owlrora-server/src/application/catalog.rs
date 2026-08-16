use owlrora_key_provider::{
    ContextVersion, FieldPurpose, InstallationId, MaterialId, OwnerId, OwnerKind,
    ProtectionContext, ProtectionContextParts, SecretPlaintext, SecretScope,
};
use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, pem::PemObject as _};
use serde_json::{Value, json};
use sqlx::{Executor, Postgres, Row as _};
use uuid::Uuid;

use crate::{
    adapters::{
        postgres::{AuditRecord, RuntimeEvent},
        provider::codex::RESPONSES_BASE_URL,
    },
    domain::{
        Actor, Capability, EndpointAdapterKind, EndpointId, ManagementScope, NetworkPolicyId,
        ReliabilityPolicyId,
    },
};

use super::{
    Application, ApplicationError, AuthorizationTarget, CatalogStatus, CreateEgressNetworkPolicy,
    CreateReliabilityPolicy, CreateUpstreamEndpoint, EgressNetworkPolicy, EntityTag,
    IdempotencyDecision, IdempotentCommand, Page, ProtectedSecretMetadata, ReliabilityPolicy,
    ReplaceEgressCustomCa, RequestIdentity, UpdateEgressNetworkPolicy, UpdateField,
    UpdateReliabilityPolicy, UpdateUpstreamEndpoint, UpstreamEndpoint, ValidatedCatalogStatus,
};

const CATALOG_CAPABILITY: Capability = Capability::ManageGatewayCatalog;

impl Application {
    pub async fn list_egress_network_policies(
        &self,
        identity: &RequestIdentity,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<EgressNetworkPolicy>, ApplicationError> {
        authorize_catalog(self, identity, false)?;
        let family = "egress_network_policies";
        let (cursor, limit) = super::resources::page_parameters(family, cursor, limit)?;
        let rows = sqlx::query(
            "SELECT policy.id,policy.name,policy.dns_policy,policy.address_policy,policy.proxy_url,
                    policy.tls_policy,policy.redirect_policy,policy.connection_policy,
                    policy.body_policy,policy.status,policy.config_version,policy.etag_token,
                    policy.created_at,policy.updated_at,secret.id AS custom_ca_material_id,
                    secret.custody_provider_id AS custom_ca_provider_id,
                    secret.provider_format_version AS custom_ca_provider_format,
                    secret.created_at AS custom_ca_created_at
             FROM egress_network_policies policy
             LEFT JOIN protected_secret_versions secret ON secret.id=policy.custom_ca_secret_id
             WHERE ($1::uuid IS NULL OR policy.id>$1)
             ORDER BY policy.id LIMIT $2",
        )
        .bind(cursor)
        .bind(i64::from(limit) + 1)
        .fetch_all(self.store.pool())
        .await?;
        super::resources::page_from_rows(rows, limit, family, egress_from_row)
    }

    pub async fn get_egress_network_policy(
        &self,
        identity: &RequestIdentity,
        id: NetworkPolicyId,
    ) -> Result<(EgressNetworkPolicy, EntityTag), ApplicationError> {
        authorize_catalog(self, identity, false)?;
        load_egress(self.store.pool(), id).await
    }

    pub async fn create_egress_network_policy(
        &self,
        identity: &RequestIdentity,
        input: CreateEgressNetworkPolicy,
        idempotency_key: Option<&str>,
    ) -> Result<IdempotentCommand<(EgressNetworkPolicy, EntityTag)>, ApplicationError> {
        authorize_catalog(self, identity, true)?;
        if input.custom_ca_pem.is_some() {
            self.authorize(
                identity,
                &[ManagementScope::Secrets],
                AuthorizationTarget::CurrentPrincipal,
            )?;
        }
        validate_name(&input.name)?;
        validate_egress_policy(
            &input.dns_policy,
            &input.address_policy,
            input.proxy_url.as_deref(),
            &input.tls_policy,
            &input.redirect_policy,
            &input.connection_policy,
            &input.body_policy,
        )?;
        let proxy_url = normalize_optional_url(input.proxy_url.as_deref(), "proxy_url")?;
        let custom_ca = input
            .custom_ca_pem
            .as_deref()
            .map(validate_custom_ca_pem)
            .transpose()?;
        let scope = crate::domain::ResourceScope::Deployment;
        let operation_id = "system.egress_network_policies.create";
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
        let id = NetworkPolicyId::new();
        let actor = actor_value(identity)?;
        let sealed_custom_ca = match custom_ca {
            Some(custom_ca) => Some(seal_custom_ca(self, id, 1, custom_ca).await?),
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
        sqlx::query(
            "INSERT INTO egress_network_policies(
                id,name,dns_policy,address_policy,proxy_url,tls_policy,redirect_policy,
                connection_policy,body_policy,status,config_version,created_by_principal,etag_token
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,$11,$12)",
        )
        .bind(id.as_uuid())
        .bind(input.name.trim())
        .bind(serde_json::to_value(input.dns_policy).map_err(|_| ApplicationError::Internal)?)
        .bind(serde_json::to_value(input.address_policy).map_err(|_| ApplicationError::Internal)?)
        .bind(proxy_url)
        .bind(serde_json::to_value(input.tls_policy).map_err(|_| ApplicationError::Internal)?)
        .bind(serde_json::to_value(input.redirect_policy).map_err(|_| ApplicationError::Internal)?)
        .bind(
            serde_json::to_value(input.connection_policy)
                .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(serde_json::to_value(input.body_policy).map_err(|_| ApplicationError::Internal)?)
        .bind(input.status.as_str())
        .bind(actor)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_conflict)?;
        if let Some(sealed_custom_ca) = &sealed_custom_ca {
            persist_custom_ca(&mut transaction, id, 1, sealed_custom_ca).await?;
        }
        let result = load_egress(&mut *transaction, id).await?;
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
            "egress_network_policy",
            id.to_string(),
            operation_id,
            &[
                "name",
                "dns_policy",
                "address_policy",
                "proxy_url",
                "tls_policy",
                "redirect_policy",
                "connection_policy",
                "body_policy",
                "status",
            ],
            false,
        )
        .await?;
        self.publish_committed_runtime(
            &identity.request_id,
            "system.egress_network_policies.create",
        )
        .await;
        Ok(IdempotentCommand::Executed(result))
    }

    pub async fn replace_egress_custom_ca(
        &self,
        identity: &RequestIdentity,
        id: NetworkPolicyId,
        if_match: Option<&str>,
        input: ReplaceEgressCustomCa,
    ) -> Result<(EgressNetworkPolicy, EntityTag), ApplicationError> {
        authorize_catalog(self, identity, true)?;
        self.authorize(
            identity,
            &[ManagementScope::Secrets],
            AuthorizationTarget::CurrentPrincipal,
        )?;
        let pem = validate_custom_ca_pem(&input.custom_ca_pem)?;
        let captured = sqlx::query(
            "SELECT config_version,custom_ca_generation,etag_token
             FROM egress_network_policies WHERE id=$1",
        )
        .bind(id.as_uuid())
        .fetch_optional(self.store.pool())
        .await?
        .ok_or(ApplicationError::NotFound)?;
        let captured_etag_token: Uuid = captured.try_get("etag_token")?;
        require_if_match(
            if_match,
            &EntityTag::for_resource("egress_network_policy", id.as_uuid(), captured_etag_token),
        )?;
        let next_ca_generation = captured
            .try_get::<i64, _>("custom_ca_generation")?
            .checked_add(1)
            .ok_or(ApplicationError::Internal)?;
        let next_config_version = captured
            .try_get::<i64, _>("config_version")?
            .checked_add(1)
            .ok_or(ApplicationError::Internal)?;
        let sealed_custom_ca = seal_custom_ca(self, id, next_ca_generation, pem).await?;

        let mut transaction = self.store.begin().await?;
        let row = sqlx::query(
            "SELECT custom_ca_secret_id,etag_token
             FROM egress_network_policies WHERE id=$1 FOR UPDATE",
        )
        .bind(id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        require_if_match(
            if_match,
            &EntityTag::for_resource(
                "egress_network_policy",
                id.as_uuid(),
                row.try_get("etag_token")?,
            ),
        )?;
        if row.try_get::<Uuid, _>("etag_token")? != captured_etag_token {
            return Err(ApplicationError::Stale {
                current_etag: Some(
                    EntityTag::for_resource(
                        "egress_network_policy",
                        id.as_uuid(),
                        row.try_get("etag_token")?,
                    )
                    .to_string(),
                ),
            });
        }
        let old_secret: Option<Uuid> = row.try_get("custom_ca_secret_id")?;
        persist_custom_ca(&mut transaction, id, next_config_version, &sealed_custom_ca).await?;
        if let Some(old_secret) = old_secret {
            sqlx::query("DELETE FROM protected_secret_versions WHERE id=$1")
                .bind(old_secret)
                .execute(&mut *transaction)
                .await?;
        }
        let result = load_egress(&mut *transaction, id).await?;
        commit_catalog(
            self,
            transaction,
            identity,
            "egress_network_policy",
            id.to_string(),
            "system.egress_network_policies.replace_custom_ca",
            &["custom_ca", "custom_ca_generation", "config_version"],
            true,
        )
        .await?;
        self.publish_committed_runtime(
            &identity.request_id,
            "system.egress_network_policies.replace_custom_ca",
        )
        .await;
        Ok(result)
    }

    pub async fn update_egress_network_policy(
        &self,
        identity: &RequestIdentity,
        id: NetworkPolicyId,
        if_match: Option<&str>,
        input: UpdateEgressNetworkPolicy,
    ) -> Result<(EgressNetworkPolicy, EntityTag), ApplicationError> {
        authorize_catalog(self, identity, true)?;
        require_nonempty([
            input.name.is_omitted(),
            input.dns_policy.is_omitted(),
            input.address_policy.is_omitted(),
            input.proxy_url.is_omitted(),
            input.tls_policy.is_omitted(),
            input.redirect_policy.is_omitted(),
            input.connection_policy.is_omitted(),
            input.body_policy.is_omitted(),
            input.status.is_omitted(),
        ])?;
        let mut transaction = self.store.begin().await?;
        let row = sqlx::query(
            "SELECT name,dns_policy,address_policy,proxy_url,tls_policy,redirect_policy,
                    connection_policy,body_policy,status,etag_token
             FROM egress_network_policies WHERE id=$1 FOR UPDATE",
        )
        .bind(id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        require_if_match(
            if_match,
            &EntityTag::for_resource(
                "egress_network_policy",
                id.as_uuid(),
                row.try_get("etag_token")?,
            ),
        )?;
        let mut name: String = row.try_get("name")?;
        let mut dns: crate::domain::EgressDnsPolicy = deserialize_column(&row, "dns_policy")?;
        let mut address: crate::domain::EgressAddressPolicy =
            deserialize_column(&row, "address_policy")?;
        let mut proxy: Option<String> = row.try_get("proxy_url")?;
        let mut tls: crate::domain::EgressTlsPolicy = deserialize_column(&row, "tls_policy")?;
        let mut redirect: crate::domain::EgressRedirectPolicy =
            deserialize_column(&row, "redirect_policy")?;
        let mut connection: crate::domain::EgressConnectionPolicy =
            deserialize_column(&row, "connection_policy")?;
        let mut body: crate::domain::EgressBodyPolicy = deserialize_column(&row, "body_policy")?;
        let current_status: String = row.try_get("status")?;
        let mut status = current_status.clone();
        let mut changed = Vec::new();
        apply_name(&mut name, input.name, &mut changed)?;
        apply_typed(&mut dns, input.dns_policy, "dns_policy", &mut changed)?;
        apply_typed(
            &mut address,
            input.address_policy,
            "address_policy",
            &mut changed,
        )?;
        match input.proxy_url {
            UpdateField::Omitted => {}
            UpdateField::Null => {
                proxy = None;
                changed.push("proxy_url");
            }
            UpdateField::Value(value) => {
                proxy = normalize_optional_url(Some(&value), "proxy_url")?;
                changed.push("proxy_url");
            }
        }
        apply_typed(&mut tls, input.tls_policy, "tls_policy", &mut changed)?;
        apply_typed(
            &mut redirect,
            input.redirect_policy,
            "redirect_policy",
            &mut changed,
        )?;
        apply_typed(
            &mut connection,
            input.connection_policy,
            "connection_policy",
            &mut changed,
        )?;
        apply_typed(&mut body, input.body_policy, "body_policy", &mut changed)?;
        validate_egress_policy(
            &dns,
            &address,
            proxy.as_deref(),
            &tls,
            &redirect,
            &connection,
            &body,
        )?;
        apply_catalog_status(&mut status, input.status, &mut changed)?;
        let tightening = current_status == "active" && status == "disabled";
        sqlx::query(
            "UPDATE egress_network_policies SET name=$2,dns_policy=$3,address_policy=$4,
                    proxy_url=$5,tls_policy=$6,redirect_policy=$7,connection_policy=$8,
                    body_policy=$9,status=$10,config_version=config_version+1,
                    etag_token=$11,updated_at=now() WHERE id=$1",
        )
        .bind(id.as_uuid())
        .bind(name)
        .bind(serde_json::to_value(dns).map_err(|_| ApplicationError::Internal)?)
        .bind(serde_json::to_value(address).map_err(|_| ApplicationError::Internal)?)
        .bind(proxy)
        .bind(serde_json::to_value(tls).map_err(|_| ApplicationError::Internal)?)
        .bind(serde_json::to_value(redirect).map_err(|_| ApplicationError::Internal)?)
        .bind(serde_json::to_value(connection).map_err(|_| ApplicationError::Internal)?)
        .bind(serde_json::to_value(body).map_err(|_| ApplicationError::Internal)?)
        .bind(status)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_conflict)?;
        let result = load_egress(&mut *transaction, id).await?;
        commit_catalog(
            self,
            transaction,
            identity,
            "egress_network_policy",
            id.to_string(),
            "system.egress_network_policies.update",
            &changed,
            tightening,
        )
        .await?;
        self.publish_committed_runtime(
            &identity.request_id,
            "system.egress_network_policies.update",
        )
        .await;
        Ok(result)
    }

    pub async fn list_reliability_policies(
        &self,
        identity: &RequestIdentity,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<ReliabilityPolicy>, ApplicationError> {
        authorize_catalog(self, identity, false)?;
        let family = "reliability_policies";
        let (cursor, limit) = super::resources::page_parameters(family, cursor, limit)?;
        let rows = sqlx::query(
            "SELECT id,name,attempt_policy,deadline_policy,retry_policy,failover_policy,
                    commitment_policy,health_policy,circuit_policy,probe_policy,status,
                    config_version,etag_token,created_at,updated_at
             FROM reliability_policies WHERE ($1::uuid IS NULL OR id>$1)
             ORDER BY id LIMIT $2",
        )
        .bind(cursor)
        .bind(i64::from(limit) + 1)
        .fetch_all(self.store.pool())
        .await?;
        super::resources::page_from_rows(rows, limit, family, reliability_from_row)
    }

    pub async fn get_reliability_policy(
        &self,
        identity: &RequestIdentity,
        id: ReliabilityPolicyId,
    ) -> Result<(ReliabilityPolicy, EntityTag), ApplicationError> {
        authorize_catalog(self, identity, false)?;
        load_reliability(self.store.pool(), id).await
    }

    pub async fn create_reliability_policy(
        &self,
        identity: &RequestIdentity,
        input: CreateReliabilityPolicy,
        idempotency_key: Option<&str>,
    ) -> Result<IdempotentCommand<(ReliabilityPolicy, EntityTag)>, ApplicationError> {
        authorize_catalog(self, identity, true)?;
        validate_name(&input.name)?;
        validate_reliability_policy(
            &input.attempt_policy,
            &input.deadline_policy,
            &input.retry_policy,
            &input.failover_policy,
            &input.commitment_policy,
            &input.health_policy,
            &input.circuit_policy,
            &input.probe_policy,
        )?;
        let scope = crate::domain::ResourceScope::Deployment;
        let operation_id = "system.reliability_policies.create";
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
        let id = ReliabilityPolicyId::new();
        sqlx::query(
            "INSERT INTO reliability_policies(
                id,name,attempt_policy,deadline_policy,retry_policy,failover_policy,
                commitment_policy,health_policy,circuit_policy,probe_policy,status,
                config_version,created_by_principal,etag_token
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1,$12,$13)",
        )
        .bind(id.as_uuid())
        .bind(input.name.trim())
        .bind(input.attempt_policy)
        .bind(input.deadline_policy)
        .bind(input.retry_policy)
        .bind(input.failover_policy)
        .bind(input.commitment_policy)
        .bind(input.health_policy)
        .bind(input.circuit_policy)
        .bind(input.probe_policy)
        .bind(input.status.as_str())
        .bind(actor_value(identity)?)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_conflict)?;
        let result = load_reliability(&mut *transaction, id).await?;
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
            "reliability_policy",
            id.to_string(),
            operation_id,
            &[
                "name",
                "attempt_policy",
                "deadline_policy",
                "retry_policy",
                "failover_policy",
                "commitment_policy",
                "health_policy",
                "circuit_policy",
                "probe_policy",
                "status",
            ],
            false,
        )
        .await?;
        self.publish_committed_runtime(&identity.request_id, "system.reliability_policies.create")
            .await;
        Ok(IdempotentCommand::Executed(result))
    }

    pub async fn update_reliability_policy(
        &self,
        identity: &RequestIdentity,
        id: ReliabilityPolicyId,
        if_match: Option<&str>,
        input: UpdateReliabilityPolicy,
    ) -> Result<(ReliabilityPolicy, EntityTag), ApplicationError> {
        authorize_catalog(self, identity, true)?;
        require_nonempty([
            input.name.is_omitted(),
            input.attempt_policy.is_omitted(),
            input.deadline_policy.is_omitted(),
            input.retry_policy.is_omitted(),
            input.failover_policy.is_omitted(),
            input.commitment_policy.is_omitted(),
            input.health_policy.is_omitted(),
            input.circuit_policy.is_omitted(),
            input.probe_policy.is_omitted(),
            input.status.is_omitted(),
        ])?;
        let mut transaction = self.store.begin().await?;
        let row = sqlx::query(
            "SELECT name,attempt_policy,deadline_policy,retry_policy,failover_policy,
                    commitment_policy,health_policy,circuit_policy,probe_policy,status,etag_token
             FROM reliability_policies WHERE id=$1 FOR UPDATE",
        )
        .bind(id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        require_if_match(
            if_match,
            &EntityTag::for_resource(
                "reliability_policy",
                id.as_uuid(),
                row.try_get("etag_token")?,
            ),
        )?;
        let mut name: String = row.try_get("name")?;
        let mut attempt: Value = row.try_get("attempt_policy")?;
        let mut deadline: Value = row.try_get("deadline_policy")?;
        let mut retry: Value = row.try_get("retry_policy")?;
        let mut failover: Value = row.try_get("failover_policy")?;
        let mut commitment: Value = row.try_get("commitment_policy")?;
        let mut health: Value = row.try_get("health_policy")?;
        let mut circuit: Value = row.try_get("circuit_policy")?;
        let mut probe: Value = row.try_get("probe_policy")?;
        let current_status: String = row.try_get("status")?;
        let mut status = current_status.clone();
        let mut changed = Vec::new();
        apply_name(&mut name, input.name, &mut changed)?;
        apply_object(
            &mut attempt,
            input.attempt_policy,
            "attempt_policy",
            &mut changed,
        )?;
        apply_object(
            &mut deadline,
            input.deadline_policy,
            "deadline_policy",
            &mut changed,
        )?;
        apply_object(&mut retry, input.retry_policy, "retry_policy", &mut changed)?;
        apply_object(
            &mut failover,
            input.failover_policy,
            "failover_policy",
            &mut changed,
        )?;
        apply_object(
            &mut commitment,
            input.commitment_policy,
            "commitment_policy",
            &mut changed,
        )?;
        apply_object(
            &mut health,
            input.health_policy,
            "health_policy",
            &mut changed,
        )?;
        apply_object(
            &mut circuit,
            input.circuit_policy,
            "circuit_policy",
            &mut changed,
        )?;
        apply_object(&mut probe, input.probe_policy, "probe_policy", &mut changed)?;
        validate_reliability_policy(
            &attempt,
            &deadline,
            &retry,
            &failover,
            &commitment,
            &health,
            &circuit,
            &probe,
        )?;
        apply_catalog_status(&mut status, input.status, &mut changed)?;
        let tightening = current_status == "active" && status == "disabled";
        sqlx::query(
            "UPDATE reliability_policies SET name=$2,attempt_policy=$3,deadline_policy=$4,
                    retry_policy=$5,failover_policy=$6,commitment_policy=$7,health_policy=$8,
                    circuit_policy=$9,probe_policy=$10,status=$11,config_version=config_version+1,
                    etag_token=$12,updated_at=now() WHERE id=$1",
        )
        .bind(id.as_uuid())
        .bind(name)
        .bind(attempt)
        .bind(deadline)
        .bind(retry)
        .bind(failover)
        .bind(commitment)
        .bind(health)
        .bind(circuit)
        .bind(probe)
        .bind(status)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_conflict)?;
        let result = load_reliability(&mut *transaction, id).await?;
        commit_catalog(
            self,
            transaction,
            identity,
            "reliability_policy",
            id.to_string(),
            "system.reliability_policies.update",
            &changed,
            tightening,
        )
        .await?;
        self.publish_committed_runtime(&identity.request_id, "system.reliability_policies.update")
            .await;
        Ok(result)
    }

    pub async fn list_upstream_endpoints(
        &self,
        identity: &RequestIdentity,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<UpstreamEndpoint>, ApplicationError> {
        authorize_catalog(self, identity, false)?;
        let family = "upstream_endpoints";
        let (cursor, limit) = super::resources::page_parameters(family, cursor, limit)?;
        let rows = sqlx::query(
            "SELECT id,name,adapter_kind,base_url,region,api_version,network_policy_id,
                    safe_headers,status,config_version,validation_evidence,etag_token,
                    created_at,updated_at,validated_at
             FROM upstream_endpoints WHERE ($1::uuid IS NULL OR id>$1)
             ORDER BY id LIMIT $2",
        )
        .bind(cursor)
        .bind(i64::from(limit) + 1)
        .fetch_all(self.store.pool())
        .await?;
        super::resources::page_from_rows(rows, limit, family, endpoint_from_row)
    }

    pub async fn get_upstream_endpoint(
        &self,
        identity: &RequestIdentity,
        id: EndpointId,
    ) -> Result<(UpstreamEndpoint, EntityTag), ApplicationError> {
        authorize_catalog(self, identity, false)?;
        load_endpoint(self.store.pool(), id).await
    }

    pub async fn create_upstream_endpoint(
        &self,
        identity: &RequestIdentity,
        input: CreateUpstreamEndpoint,
        idempotency_key: Option<&str>,
    ) -> Result<IdempotentCommand<(UpstreamEndpoint, EntityTag)>, ApplicationError> {
        authorize_catalog(self, identity, true)?;
        validate_name(&input.name)?;
        let base_url = normalize_endpoint_url_for_adapter(input.adapter_kind, &input.base_url)?;
        validate_safe_headers(&input.safe_headers)?;
        let scope = crate::domain::ResourceScope::Deployment;
        let operation_id = "system.upstream_endpoints.create";
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
        let id = EndpointId::new();
        sqlx::query(
            "INSERT INTO upstream_endpoints(
                id,name,adapter_kind,base_url,region,api_version,network_policy_id,safe_headers,
                status,config_version,created_by_principal,etag_token
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,1,$10,$11)",
        )
        .bind(id.as_uuid())
        .bind(input.name.trim())
        .bind(input.adapter_kind.as_str())
        .bind(base_url)
        .bind(trim_optional(input.region.as_deref()))
        .bind(trim_optional(input.api_version.as_deref()))
        .bind(input.network_policy_id.as_uuid())
        .bind(input.safe_headers)
        .bind(input.status.as_str())
        .bind(actor_value(identity)?)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_conflict)?;
        let result = load_endpoint(&mut *transaction, id).await?;
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
            "upstream_endpoint",
            id.to_string(),
            operation_id,
            &[
                "name",
                "adapter_kind",
                "base_url",
                "region",
                "api_version",
                "network_policy_id",
                "safe_headers",
                "status",
            ],
            false,
        )
        .await?;
        self.publish_committed_runtime(&identity.request_id, "system.upstream_endpoints.create")
            .await;
        Ok(IdempotentCommand::Executed(result))
    }

    pub async fn update_upstream_endpoint(
        &self,
        identity: &RequestIdentity,
        id: EndpointId,
        if_match: Option<&str>,
        input: UpdateUpstreamEndpoint,
    ) -> Result<(UpstreamEndpoint, EntityTag), ApplicationError> {
        authorize_catalog(self, identity, true)?;
        require_nonempty([
            input.name.is_omitted(),
            input.base_url.is_omitted(),
            input.region.is_omitted(),
            input.api_version.is_omitted(),
            input.network_policy_id.is_omitted(),
            input.safe_headers.is_omitted(),
            input.status.is_omitted(),
        ])?;
        let mut transaction = self.store.begin().await?;
        let row = sqlx::query(
            "SELECT name,adapter_kind,base_url,region,api_version,network_policy_id,safe_headers,status,etag_token
             FROM upstream_endpoints WHERE id=$1 FOR UPDATE",
        )
        .bind(id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        require_if_match(
            if_match,
            &EntityTag::for_resource(
                "upstream_endpoint",
                id.as_uuid(),
                row.try_get("etag_token")?,
            ),
        )?;
        let mut name: String = row.try_get("name")?;
        let adapter_kind = parse_endpoint_adapter(&row.try_get::<String, _>("adapter_kind")?)?;
        let mut base_url: String = row.try_get("base_url")?;
        let mut region: Option<String> = row.try_get("region")?;
        let mut api_version: Option<String> = row.try_get("api_version")?;
        let mut network_policy_id: Uuid = row.try_get("network_policy_id")?;
        let mut safe_headers: Value = row.try_get("safe_headers")?;
        let current_status: String = row.try_get("status")?;
        let mut status = current_status.clone();
        let mut changed = Vec::new();
        apply_name(&mut name, input.name, &mut changed)?;
        match input.base_url {
            UpdateField::Omitted => {}
            UpdateField::Null => return Err(null_error("base_url")),
            UpdateField::Value(value) => {
                base_url = normalize_endpoint_url_for_adapter(adapter_kind, &value)?;
                changed.push("base_url");
            }
        }
        apply_optional_string(&mut region, input.region, "region", &mut changed)?;
        apply_optional_string(
            &mut api_version,
            input.api_version,
            "api_version",
            &mut changed,
        )?;
        match input.network_policy_id {
            UpdateField::Omitted => {}
            UpdateField::Null => return Err(null_error("network_policy_id")),
            UpdateField::Value(value) => {
                network_policy_id = value.as_uuid();
                changed.push("network_policy_id");
            }
        }
        match input.safe_headers {
            UpdateField::Omitted => {}
            UpdateField::Null => return Err(null_error("safe_headers")),
            UpdateField::Value(value) => {
                validate_safe_headers(&value)?;
                safe_headers = value;
                changed.push("safe_headers");
            }
        }
        match input.status {
            UpdateField::Omitted => {}
            UpdateField::Null => return Err(null_error("status")),
            UpdateField::Value(value) => {
                status = value.as_str().to_owned();
                changed.push("status");
            }
        }
        let tightening = current_status == "active" && status != "active";
        sqlx::query(
            "UPDATE upstream_endpoints SET name=$2,base_url=$3,region=$4,api_version=$5,
                    network_policy_id=$6,safe_headers=$7,status=$8,config_version=config_version+1,
                    validation_evidence=NULL,validated_at=NULL,etag_token=$9,updated_at=now()
             WHERE id=$1",
        )
        .bind(id.as_uuid())
        .bind(name)
        .bind(base_url)
        .bind(region)
        .bind(api_version)
        .bind(network_policy_id)
        .bind(safe_headers)
        .bind(status)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_conflict)?;
        let result = load_endpoint(&mut *transaction, id).await?;
        commit_catalog(
            self,
            transaction,
            identity,
            "upstream_endpoint",
            id.to_string(),
            "system.upstream_endpoints.update",
            &changed,
            tightening,
        )
        .await?;
        self.publish_committed_runtime(&identity.request_id, "system.upstream_endpoints.update")
            .await;
        Ok(result)
    }

    pub async fn validate_upstream_endpoint(
        &self,
        identity: &RequestIdentity,
        id: EndpointId,
        idempotency_key: Option<&str>,
    ) -> Result<IdempotentCommand<super::CatalogValidationResult<UpstreamEndpoint>>, ApplicationError>
    {
        authorize_catalog(self, identity, true)?;
        let operation_id = "system.upstream_endpoints.validate";
        let scope = crate::domain::ResourceScope::Deployment;
        let request = json!({"endpoint_id": id});
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
        if generation
            .credential_clients
            .unavailable
            .keys()
            .any(|key| key.endpoint_id == id)
        {
            return Err(ApplicationError::Conflict(
                "endpoint runtime client validation failed for a dependent deployment".to_owned(),
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
            "SELECT base_url,status,config_version FROM upstream_endpoints WHERE id=$1 FOR UPDATE",
        )
        .bind(id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        let base_url = row.try_get::<String, _>("base_url")?;
        normalize_endpoint_url(&base_url)?;
        let evidence = json!({
            "outcome":"accepted",
            "validation_kind":"configuration_and_runtime_client",
            "config_version":row.try_get::<i64, _>("config_version")?,
        });
        sqlx::query(
            "UPDATE upstream_endpoints SET validation_evidence=$2,validated_at=now(),
                    etag_token=$3,updated_at=now(),status=CASE
                        WHEN status='validation_failed' THEN 'active' ELSE status END
             WHERE id=$1",
        )
        .bind(id.as_uuid())
        .bind(&evidence)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let (resource, _) = load_endpoint(&mut *transaction, id).await?;
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
            "upstream_endpoint",
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
}

async fn load_egress<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    id: NetworkPolicyId,
) -> Result<(EgressNetworkPolicy, EntityTag), ApplicationError> {
    let row = sqlx::query(
        "SELECT policy.id,policy.name,policy.dns_policy,policy.address_policy,policy.proxy_url,
                policy.tls_policy,policy.redirect_policy,policy.connection_policy,
                policy.body_policy,policy.status,policy.config_version,policy.etag_token,
                policy.created_at,policy.updated_at,secret.id AS custom_ca_material_id,
                secret.custody_provider_id AS custom_ca_provider_id,
                secret.provider_format_version AS custom_ca_provider_format,
                secret.created_at AS custom_ca_created_at
         FROM egress_network_policies policy
         LEFT JOIN protected_secret_versions secret ON secret.id=policy.custom_ca_secret_id
         WHERE policy.id=$1",
    )
    .bind(id.as_uuid())
    .fetch_optional(executor)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    let tag = EntityTag::for_resource(
        "egress_network_policy",
        id.as_uuid(),
        row.try_get("etag_token")?,
    );
    Ok((egress_from_row(row)?, tag))
}

fn egress_from_row(row: sqlx::postgres::PgRow) -> Result<EgressNetworkPolicy, ApplicationError> {
    Ok(EgressNetworkPolicy {
        id: NetworkPolicyId::from_uuid(row.try_get("id")?),
        name: row.try_get("name")?,
        dns_policy: deserialize_column(&row, "dns_policy")?,
        address_policy: deserialize_column(&row, "address_policy")?,
        proxy_url: row.try_get("proxy_url")?,
        tls_policy: deserialize_column(&row, "tls_policy")?,
        redirect_policy: deserialize_column(&row, "redirect_policy")?,
        connection_policy: deserialize_column(&row, "connection_policy")?,
        body_policy: deserialize_column(&row, "body_policy")?,
        custom_ca: match row.try_get::<Option<Uuid>, _>("custom_ca_material_id")? {
            Some(material_id) => Some(ProtectedSecretMetadata {
                material_id,
                custody_provider_id: row.try_get("custom_ca_provider_id")?,
                provider_format_version: u32::try_from(
                    row.try_get::<Option<i32>, _>("custom_ca_provider_format")?
                        .ok_or(ApplicationError::Internal)?,
                )
                .map_err(|_| ApplicationError::Internal)?,
                created_at: row
                    .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("custom_ca_created_at")?
                    .ok_or(ApplicationError::Internal)?,
            }),
            None => None,
        },
        status: parse_catalog_status(&row.try_get::<String, _>("status")?)?,
        config_version: row.try_get("config_version")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

pub(super) async fn load_reliability<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    id: ReliabilityPolicyId,
) -> Result<(ReliabilityPolicy, EntityTag), ApplicationError> {
    let row = sqlx::query(
        "SELECT id,name,attempt_policy,deadline_policy,retry_policy,failover_policy,
                commitment_policy,health_policy,circuit_policy,probe_policy,status,
                config_version,etag_token,created_at,updated_at
         FROM reliability_policies WHERE id=$1",
    )
    .bind(id.as_uuid())
    .fetch_optional(executor)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    let tag = EntityTag::for_resource(
        "reliability_policy",
        id.as_uuid(),
        row.try_get("etag_token")?,
    );
    Ok((reliability_from_row(row)?, tag))
}

fn reliability_from_row(row: sqlx::postgres::PgRow) -> Result<ReliabilityPolicy, ApplicationError> {
    Ok(ReliabilityPolicy {
        id: ReliabilityPolicyId::from_uuid(row.try_get("id")?),
        name: row.try_get("name")?,
        attempt_policy: row.try_get("attempt_policy")?,
        deadline_policy: row.try_get("deadline_policy")?,
        retry_policy: row.try_get("retry_policy")?,
        failover_policy: row.try_get("failover_policy")?,
        commitment_policy: row.try_get("commitment_policy")?,
        health_policy: row.try_get("health_policy")?,
        circuit_policy: row.try_get("circuit_policy")?,
        probe_policy: row.try_get("probe_policy")?,
        status: parse_catalog_status(&row.try_get::<String, _>("status")?)?,
        config_version: row.try_get("config_version")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

pub(super) async fn load_endpoint<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    id: EndpointId,
) -> Result<(UpstreamEndpoint, EntityTag), ApplicationError> {
    let row = sqlx::query(
        "SELECT id,name,adapter_kind,base_url,region,api_version,network_policy_id,
                safe_headers,status,config_version,validation_evidence,etag_token,
                created_at,updated_at,validated_at FROM upstream_endpoints WHERE id=$1",
    )
    .bind(id.as_uuid())
    .fetch_optional(executor)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    let tag = EntityTag::for_resource(
        "upstream_endpoint",
        id.as_uuid(),
        row.try_get("etag_token")?,
    );
    Ok((endpoint_from_row(row)?, tag))
}

fn endpoint_from_row(row: sqlx::postgres::PgRow) -> Result<UpstreamEndpoint, ApplicationError> {
    Ok(UpstreamEndpoint {
        id: EndpointId::from_uuid(row.try_get("id")?),
        name: row.try_get("name")?,
        adapter_kind: parse_endpoint_adapter(&row.try_get::<String, _>("adapter_kind")?)?,
        base_url: row.try_get("base_url")?,
        region: row.try_get("region")?,
        api_version: row.try_get("api_version")?,
        network_policy_id: NetworkPolicyId::from_uuid(row.try_get("network_policy_id")?),
        safe_headers: row.try_get("safe_headers")?,
        status: parse_validated_status(&row.try_get::<String, _>("status")?)?,
        config_version: row.try_get("config_version")?,
        validation_evidence: row.try_get("validation_evidence")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        validated_at: row.try_get("validated_at")?,
    })
}

fn authorize_catalog(
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
            capability: CATALOG_CAPABILITY,
        },
    )
}

async fn commit_catalog(
    application: &Application,
    transaction: sqlx::Transaction<'_, Postgres>,
    identity: &RequestIdentity,
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
                organization_id: None,
                target_resource_kind: resource_kind.to_owned(),
                target_resource_id: Some(resource_id.clone()),
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
                event_kind: format!("{resource_kind}.changed"),
                affected_scope: json!({"resource_id": resource_id}),
                security_tightening,
            }),
        )
        .await?;
    Ok(())
}

fn actor_value(identity: &RequestIdentity) -> Result<Value, ApplicationError> {
    serde_json::to_value(Actor::from(&identity.principal)).map_err(|_| ApplicationError::Internal)
}

fn validate_custom_ca_pem(value: &str) -> Result<&str, ApplicationError> {
    const MAX_CUSTOM_CA_CERTIFICATES: usize = 64;

    let value = value.trim();
    let invalid = || {
        ApplicationError::Validation(
            "custom_ca_pem must contain 1 to 64 valid PEM certificates and no private keys"
                .to_owned(),
        )
    };
    if value.is_empty()
        || value.len() > 1_048_576
        || value.contains('\0')
        || value.contains("-----BEGIN PRIVATE KEY-----")
        || value.contains("-----BEGIN RSA PRIVATE KEY-----")
        || value.contains("-----BEGIN EC PRIVATE KEY-----")
        || value.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
    {
        return Err(invalid());
    }
    let certificates = CertificateDer::pem_slice_iter(value.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid())?;
    if certificates.is_empty() || certificates.len() > MAX_CUSTOM_CA_CERTIFICATES {
        return Err(invalid());
    }
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate).map_err(|_| invalid())?;
    }
    if roots.len() > MAX_CUSTOM_CA_CERTIFICATES {
        return Err(invalid());
    }
    Ok(value)
}

struct SealedCustomCa {
    material_id: Uuid,
    generation: i64,
    provider_id: String,
    provider_format_version: i32,
    envelope: Vec<u8>,
}

async fn seal_custom_ca(
    application: &Application,
    policy_id: NetworkPolicyId,
    custom_ca_generation: i64,
    pem: &str,
) -> Result<SealedCustomCa, ApplicationError> {
    let material_id = Uuid::now_v7();
    let context = ProtectionContext::new(ProtectionContextParts {
        version: ContextVersion::V1,
        installation_id: InstallationId::new(application.store.installation_id().to_string())
            .map_err(|_| ApplicationError::Internal)?,
        scope: SecretScope::System,
        material_id: MaterialId::new(material_id.to_string())
            .map_err(|_| ApplicationError::Internal)?,
        owner_kind: OwnerKind::new("egress_network_policy")
            .map_err(|_| ApplicationError::Internal)?,
        owner_id: OwnerId::new(policy_id.to_string()).map_err(|_| ApplicationError::Internal)?,
        owner_generation: u64::try_from(custom_ca_generation)
            .map_err(|_| ApplicationError::Internal)?,
        secret_version: u64::try_from(custom_ca_generation)
            .map_err(|_| ApplicationError::Internal)?,
        field_purpose: FieldPurpose::new("custom_ca_bundle")
            .map_err(|_| ApplicationError::Internal)?,
        provider_id: application.secrets.write_pair().provider_id().clone(),
        provider_format_version: application.secrets.write_pair().format_version(),
    })
    .map_err(|_| ApplicationError::Internal)?;
    let plaintext = SecretPlaintext::new(pem.as_bytes().to_vec()).map_err(|_| {
        ApplicationError::Validation("custom_ca_pem exceeds the secret bound".to_owned())
    })?;
    let envelope = application
        .secrets
        .seal(&context, &plaintext)
        .await
        .map_err(|_| ApplicationError::DependencyUnavailable)?;
    Ok(SealedCustomCa {
        material_id,
        generation: custom_ca_generation,
        provider_id: context.parts().provider_id.as_str().to_owned(),
        provider_format_version: i32::try_from(context.parts().provider_format_version.get())
            .map_err(|_| ApplicationError::Internal)?,
        envelope: envelope.expose(<[u8]>::to_vec),
    })
}

async fn persist_custom_ca(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    policy_id: NetworkPolicyId,
    config_version: i64,
    sealed: &SealedCustomCa,
) -> Result<(), ApplicationError> {
    sqlx::query(
        "INSERT INTO protected_secret_versions(
            id,scope_kind,organization_id,owner_kind,owner_id,owner_generation,secret_version,
            field_purpose,custody_provider_id,provider_format_version,context_version,opaque_envelope
         ) VALUES ($1,'system',NULL,'egress_network_policy',$2,$3,$3,'custom_ca_bundle',$4,$5,1,$6)",
    )
    .bind(sealed.material_id)
    .bind(policy_id.as_uuid())
    .bind(sealed.generation)
    .bind(&sealed.provider_id)
    .bind(sealed.provider_format_version)
    .bind(&sealed.envelope)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE egress_network_policies SET custom_ca_secret_id=$2,custom_ca_generation=$3,
                config_version=$4,etag_token=$5,updated_at=now() WHERE id=$1",
    )
    .bind(policy_id.as_uuid())
    .bind(sealed.material_id)
    .bind(sealed.generation)
    .bind(config_version)
    .bind(Uuid::now_v7())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn validate_name(value: &str) -> Result<(), ApplicationError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 160 || trimmed.chars().any(char::is_control) {
        return Err(ApplicationError::Validation(
            "name must contain 1 to 160 printable characters".to_owned(),
        ));
    }
    Ok(())
}

fn deserialize_column<T: serde::de::DeserializeOwned>(
    row: &sqlx::postgres::PgRow,
    column: &str,
) -> Result<T, ApplicationError> {
    serde_json::from_value(row.try_get(column)?).map_err(|_| ApplicationError::Internal)
}

fn validate_egress_policy(
    dns: &crate::domain::EgressDnsPolicy,
    address: &crate::domain::EgressAddressPolicy,
    proxy_url: Option<&str>,
    tls: &crate::domain::EgressTlsPolicy,
    redirect: &crate::domain::EgressRedirectPolicy,
    connection: &crate::domain::EgressConnectionPolicy,
    body: &crate::domain::EgressBodyPolicy,
) -> Result<(), ApplicationError> {
    if !dns.revalidate_on_connect
        || dns.max_resolved_addresses == 0
        || dns.max_resolved_addresses > 32
        || !tls.verify_hostname
        || !tls.verify_certificate
        || !matches!(tls.minimum_version.as_str(), "1.2" | "1.3")
        || redirect.max_redirects != 0
        || !(100..=60_000).contains(&connection.connect_timeout_ms)
        || !(1_000..=600_000).contains(&connection.request_timeout_ms)
        || !(1_000..=600_000).contains(&connection.pool_idle_timeout_ms)
        || !(1..=256).contains(&connection.max_idle_connections_per_host)
        || !(1..=64 * 1024 * 1024).contains(&body.max_request_body_bytes)
        || !(1..=512 * 1024 * 1024).contains(&body.max_response_body_bytes)
    {
        return Err(ApplicationError::Validation(
            "egress policy contains unsupported or unsafe bounds".to_owned(),
        ));
    }
    if address.allowed_cidrs.len() > 64
        || address.denied_cidrs.len() > 64
        || address
            .allowed_cidrs
            .iter()
            .chain(&address.denied_cidrs)
            .any(|network| network.parse::<ipnet::IpNet>().is_err())
    {
        return Err(ApplicationError::Validation(
            "egress address policy contains invalid CIDR values".to_owned(),
        ));
    }
    if proxy_url.is_some() {
        return Err(ApplicationError::Validation(
            "proxy_url is not supported until proxy target-address enforcement is modeled"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_reliability_policy(
    attempt: &Value,
    deadline: &Value,
    retry: &Value,
    failover: &Value,
    commitment: &Value,
    health: &Value,
    circuit: &Value,
    probe: &Value,
) -> Result<(), ApplicationError> {
    validate_exact_unsigned_fields(
        attempt,
        "attempt_policy",
        &[
            ("max_total_attempts", 1, 16),
            ("max_same_target_retries", 0, 8),
            ("max_distinct_failover_targets", 0, 15),
        ],
    )?;
    let max_attempts = required_u64(attempt, "max_total_attempts", "attempt_policy")?;
    let same_target = required_u64(attempt, "max_same_target_retries", "attempt_policy")?;
    let failover_targets =
        required_u64(attempt, "max_distinct_failover_targets", "attempt_policy")?;
    if same_target >= max_attempts || failover_targets >= max_attempts {
        return Err(ApplicationError::Validation(
            "attempt policy retry and failover bounds must be below max_total_attempts".to_owned(),
        ));
    }
    validate_exact_unsigned_fields(
        deadline,
        "deadline_policy",
        &[
            ("overall_timeout_ms", 100, 3_600_000),
            ("connect_timeout_ms", 10, 120_000),
            ("response_header_timeout_ms", 10, 3_600_000),
            ("body_timeout_ms", 10, 3_600_000),
            ("stream_idle_timeout_ms", 100, 3_600_000),
            ("pre_commit_classification_timeout_ms", 10, 120_000),
        ],
    )?;
    let overall = required_u64(deadline, "overall_timeout_ms", "deadline_policy")?;
    for field in [
        "connect_timeout_ms",
        "response_header_timeout_ms",
        "body_timeout_ms",
        "stream_idle_timeout_ms",
        "pre_commit_classification_timeout_ms",
    ] {
        if required_u64(deadline, field, "deadline_policy")? > overall {
            return Err(ApplicationError::Validation(format!(
                "deadline_policy.{field} cannot exceed overall_timeout_ms"
            )));
        }
    }
    validate_retry_policy(retry)?;
    validate_exact_bool_fields(
        failover,
        "failover_policy",
        &["enabled", "require_replay_safe_request"],
    )?;
    validate_exact_unsigned_fields(
        commitment,
        "commitment_policy",
        &[
            ("stream_precommit_buffer_bytes", 1, 16 * 1024 * 1024),
            ("stream_precommit_buffer_events", 1, 4096),
        ],
    )?;
    validate_exact_unsigned_fields(
        health,
        "health_policy",
        &[
            ("shared_summary_ttl_ms", 100, 300_000),
            ("stale_after_ms", 100, 300_000),
        ],
    )?;
    validate_exact_unsigned_fields(
        circuit,
        "circuit_policy",
        &[
            ("failure_threshold", 1, 1000),
            ("success_threshold", 1, 1000),
            ("open_duration_ms", 100, 3_600_000),
            ("max_open_duration_ms", 100, 3_600_000),
            ("half_open_max_requests", 1, 128),
            ("recovery_duration_ms", 100, 3_600_000),
        ],
    )?;
    if circuit["max_open_duration_ms"].as_u64() < circuit["open_duration_ms"].as_u64() {
        return Err(ApplicationError::Validation(
            "circuit_policy.max_open_duration_ms must be at least open_duration_ms".to_owned(),
        ));
    }
    validate_probe_policy(probe)?;
    Ok(())
}

fn validate_retry_policy(value: &Value) -> Result<(), ApplicationError> {
    let object = exact_object(
        value,
        "retry_policy",
        &[
            "conditions",
            "initial_backoff_ms",
            "max_backoff_ms",
            "jitter_ratio_millis",
            "honor_retry_after",
        ],
    )?;
    let conditions = object
        .get("conditions")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ApplicationError::Validation("retry_policy.conditions must be an array".to_owned())
        })?;
    const CONDITIONS: &[&str] = &[
        "connect_failure",
        "connect_timeout",
        "response_header_timeout",
        "provider_overloaded",
        "provider_rate_limited",
        "provider_5xx",
    ];
    if conditions.len() > CONDITIONS.len()
        || conditions.iter().any(|condition| {
            condition
                .as_str()
                .is_none_or(|condition| !CONDITIONS.contains(&condition))
        })
        || conditions
            .iter()
            .filter_map(Value::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != conditions.len()
    {
        return Err(ApplicationError::Validation(
            "retry_policy.conditions contains unknown or duplicate values".to_owned(),
        ));
    }
    let initial = bounded_u64(object, "initial_backoff_ms", 0, 60_000, "retry_policy")?;
    let maximum = bounded_u64(object, "max_backoff_ms", 0, 300_000, "retry_policy")?;
    bounded_u64(object, "jitter_ratio_millis", 0, 1000, "retry_policy")?;
    if initial > maximum
        || object
            .get("honor_retry_after")
            .and_then(Value::as_bool)
            .is_none()
    {
        return Err(ApplicationError::Validation(
            "retry_policy backoff or honor_retry_after is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_probe_policy(value: &Value) -> Result<(), ApplicationError> {
    let object = exact_object(
        value,
        "probe_policy",
        &["enabled", "interval_ms", "timeout_ms", "path"],
    )?;
    if object.get("enabled").and_then(Value::as_bool).is_none() {
        return Err(ApplicationError::Validation(
            "probe_policy.enabled must be boolean".to_owned(),
        ));
    }
    let interval = bounded_u64(object, "interval_ms", 1000, 3_600_000, "probe_policy")?;
    let timeout = bounded_u64(object, "timeout_ms", 10, 120_000, "probe_policy")?;
    let path = object.get("path").and_then(Value::as_str).ok_or_else(|| {
        ApplicationError::Validation("probe_policy.path must be a string".to_owned())
    })?;
    if timeout >= interval
        || path.is_empty()
        || path.len() > 1024
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains('?')
        || path.contains('#')
        || path.chars().any(char::is_control)
    {
        return Err(ApplicationError::Validation(
            "probe_policy bounds or path are invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_exact_unsigned_fields(
    value: &Value,
    name: &str,
    fields: &[(&str, u64, u64)],
) -> Result<(), ApplicationError> {
    let names = fields
        .iter()
        .map(|(field, _, _)| *field)
        .collect::<Vec<_>>();
    let object = exact_object(value, name, &names)?;
    for (field, minimum, maximum) in fields {
        bounded_u64(object, field, *minimum, *maximum, name)?;
    }
    Ok(())
}

fn validate_exact_bool_fields(
    value: &Value,
    name: &str,
    fields: &[&str],
) -> Result<(), ApplicationError> {
    let object = exact_object(value, name, fields)?;
    if fields
        .iter()
        .any(|field| object.get(*field).and_then(Value::as_bool).is_none())
    {
        return Err(ApplicationError::Validation(format!(
            "{name} fields must be boolean"
        )));
    }
    Ok(())
}

fn exact_object<'a>(
    value: &'a Value,
    name: &str,
    fields: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, ApplicationError> {
    let object = value
        .as_object()
        .ok_or_else(|| ApplicationError::Validation(format!("{name} must be an object")))?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(ApplicationError::Validation(format!(
            "{name} must contain exactly the supported fields"
        )));
    }
    Ok(object)
}

fn bounded_u64(
    object: &serde_json::Map<String, Value>,
    field: &str,
    minimum: u64,
    maximum: u64,
    name: &str,
) -> Result<u64, ApplicationError> {
    let value = object.get(field).and_then(Value::as_u64).ok_or_else(|| {
        ApplicationError::Validation(format!("{name}.{field} must be an unsigned integer"))
    })?;
    if !(minimum..=maximum).contains(&value) {
        return Err(ApplicationError::Validation(format!(
            "{name}.{field} is outside the supported bound"
        )));
    }
    Ok(value)
}

fn required_u64(value: &Value, field: &str, name: &str) -> Result<u64, ApplicationError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| ApplicationError::Validation(format!("{name}.{field} is required")))
}

#[cfg(test)]
fn valid_reliability_input() -> CreateReliabilityPolicy {
    CreateReliabilityPolicy {
        name: "default".to_owned(),
        attempt_policy: json!({
            "max_total_attempts":3,
            "max_same_target_retries":1,
            "max_distinct_failover_targets":2
        }),
        deadline_policy: json!({
            "overall_timeout_ms":120_000,
            "connect_timeout_ms":10_000,
            "response_header_timeout_ms":60_000,
            "body_timeout_ms":120_000,
            "stream_idle_timeout_ms":60_000,
            "pre_commit_classification_timeout_ms":5_000
        }),
        retry_policy: json!({
            "conditions":["connect_failure","connect_timeout","provider_overloaded","provider_rate_limited","provider_5xx"],
            "initial_backoff_ms":100,
            "max_backoff_ms":5_000,
            "jitter_ratio_millis":200,
            "honor_retry_after":true
        }),
        failover_policy: json!({"enabled":true,"require_replay_safe_request":true}),
        commitment_policy: json!({
            "stream_precommit_buffer_bytes":262_144,
            "stream_precommit_buffer_events":128
        }),
        health_policy: json!({"shared_summary_ttl_ms":30_000,"stale_after_ms":60_000}),
        circuit_policy: json!({
            "failure_threshold":5,
            "success_threshold":2,
            "open_duration_ms":30_000,
            "max_open_duration_ms":300_000,
            "half_open_max_requests":1,
            "recovery_duration_ms":60_000
        }),
        probe_policy: json!({
            "enabled":false,
            "interval_ms":30_000,
            "timeout_ms":5_000,
            "path":"/health"
        }),
        status: CatalogStatus::Active,
    }
}

fn normalize_optional_url(
    value: Option<&str>,
    field: &str,
) -> Result<Option<String>, ApplicationError> {
    value
        .map(|value| normalize_http_url(value, field))
        .transpose()
}

fn normalize_endpoint_url_for_adapter(
    adapter: EndpointAdapterKind,
    value: &str,
) -> Result<String, ApplicationError> {
    let normalized = normalize_endpoint_url(value)?;
    if adapter == EndpointAdapterKind::OpenaiCodex && normalized != RESPONSES_BASE_URL {
        return Err(ApplicationError::Validation(
            "OpenAI Codex uses the fixed OwlRora Responses authority".to_owned(),
        ));
    }
    Ok(normalized)
}

fn normalize_endpoint_url(value: &str) -> Result<String, ApplicationError> {
    let normalized = normalize_http_url(value, "base_url")?;
    let url = url::Url::parse(&normalized).map_err(|_| ApplicationError::Internal)?;
    if url.scheme() != "https" {
        return Err(ApplicationError::Validation(
            "base_url must use HTTPS".to_owned(),
        ));
    }
    Ok(normalized)
}

fn normalize_http_url(value: &str, field: &str) -> Result<String, ApplicationError> {
    let mut url = url::Url::parse(value.trim()).map_err(|_| {
        ApplicationError::Validation(format!("{field} must be an absolute HTTP URL"))
    })?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ApplicationError::Validation(format!(
            "{field} must be an absolute HTTP URL without credentials or fragment"
        )));
    }
    url.set_fragment(None);
    Ok(url.to_string())
}

fn validate_safe_headers(value: &Value) -> Result<(), ApplicationError> {
    let object = value
        .as_object()
        .ok_or_else(|| ApplicationError::Validation("safe_headers must be an object".to_owned()))?;
    if object.len() > 32 {
        return Err(ApplicationError::Validation(
            "safe_headers exceeds the 32 header limit".to_owned(),
        ));
    }
    const RESERVED: &[&str] = &[
        "authorization",
        "proxy-authorization",
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "upgrade",
        "x-api-key",
        "x-goog-api-key",
        "api-key",
    ];
    for (name, value) in object {
        let lower = name.to_ascii_lowercase();
        if name.is_empty()
            || name.len() > 128
            || RESERVED.contains(&lower.as_str())
            || lower.starts_with("sec-")
            || http::HeaderName::from_bytes(name.as_bytes()).is_err()
        {
            return Err(ApplicationError::Validation(format!(
                "safe_headers contains reserved or invalid header {name}"
            )));
        }
        let text = value.as_str().ok_or_else(|| {
            ApplicationError::Validation("safe header values must be strings".to_owned())
        })?;
        if text.len() > 2048 || http::HeaderValue::from_str(text).is_err() {
            return Err(ApplicationError::Validation(format!(
                "safe_headers contains invalid value for {name}"
            )));
        }
    }
    Ok(())
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

fn require_nonempty<const N: usize>(omitted: [bool; N]) -> Result<(), ApplicationError> {
    if omitted.into_iter().all(|value| value) {
        Err(ApplicationError::Validation(
            "at least one update field is required".to_owned(),
        ))
    } else {
        Ok(())
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

fn apply_typed<T>(
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

fn apply_optional_string(
    target: &mut Option<String>,
    field: UpdateField<String>,
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
            let value = value.trim();
            if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
                return Err(ApplicationError::Validation(format!(
                    "{name} must contain 1 to 128 printable characters"
                )));
            }
            *target = Some(value.to_owned());
            changed.push(name);
        }
    }
    Ok(())
}

fn trim_optional(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
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

    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBgDCCASegAwIBAgIUPHDUu9WL36yvTmFeNFZVe/qhClcwCgYIKoZIzj0EAwIw\n\
HTEbMBkGA1UEAwwSUnVzdGxzIFJvYnVzdCBSb290MCAXDTc1MDEwMTAwMDAwMFoY\n\
DzQwOTYwMTAxMDAwMDAwWjAdMRswGQYDVQQDDBJSdXN0bHMgUm9idXN0IFJvb3Qw\n\
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASW/VkDFs5iGDQvH8jaXYT4jMx66jo+\n\
5CWKyMt4OlTDdBfKfnmQ9LYeK/PsYfJ8wVizuSlPzXi9je8SnyYejGP3o0MwQTAP\n\
BgNVHQ8BAf8EBQMDB4QAMB0GA1UdDgQWBBRqY/oMENJbNo7y39iL6GW3tDs0rzAP\n\
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIEUbrmSUjANju9nNpFop\n\
PAl9Wh8tBxI5IY+BPh466+aUAiA1/9+prypt6s3Doo0GDsnoFGJi1UBivUg1qdik\n\
cy4eNw==\n\
-----END CERTIFICATE-----";

    #[test]
    fn custom_ca_requires_valid_certificates_and_rejects_private_keys() {
        assert_eq!(validate_custom_ca_pem(TEST_CA_PEM).unwrap(), TEST_CA_PEM);
        assert!(
            validate_custom_ca_pem(
                "-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----"
            )
            .is_err()
        );
        assert!(
            validate_custom_ca_pem(&format!(
                "{TEST_CA_PEM}\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"
            ))
            .is_err()
        );
    }

    #[test]
    fn safe_headers_reject_secret_and_framing_boundaries() {
        assert!(validate_safe_headers(&json!({"x-client":"owlrora"})).is_ok());
        assert!(validate_safe_headers(&json!({"Authorization":"secret"})).is_err());
        assert!(validate_safe_headers(&json!({"Content-Length":"1"})).is_err());
        assert!(validate_safe_headers(&json!({"x-api-key":"secret"})).is_err());
    }

    #[test]
    fn urls_reject_credentials_and_non_http_schemes() {
        assert_eq!(
            normalize_endpoint_url("https://api.example.com/v1").unwrap(),
            "https://api.example.com/v1"
        );
        assert!(normalize_endpoint_url("https://user:pass@example.com").is_err());
        assert!(normalize_endpoint_url("file:///tmp/socket").is_err());
        assert!(normalize_endpoint_url("http://api.example.com/v1").is_err());
    }

    #[test]
    fn reliability_policy_is_closed_and_cross_field_bounded() {
        let mut input = valid_reliability_input();
        assert!(
            validate_reliability_policy(
                &input.attempt_policy,
                &input.deadline_policy,
                &input.retry_policy,
                &input.failover_policy,
                &input.commitment_policy,
                &input.health_policy,
                &input.circuit_policy,
                &input.probe_policy,
            )
            .is_ok()
        );
        input.attempt_policy["unknown"] = json!(1);
        assert!(
            validate_reliability_policy(
                &input.attempt_policy,
                &input.deadline_policy,
                &input.retry_policy,
                &input.failover_policy,
                &input.commitment_policy,
                &input.health_policy,
                &input.circuit_policy,
                &input.probe_policy,
            )
            .is_err()
        );
        let mut input = valid_reliability_input();
        input.deadline_policy["connect_timeout_ms"] = json!(200_000);
        assert!(
            validate_reliability_policy(
                &input.attempt_policy,
                &input.deadline_policy,
                &input.retry_policy,
                &input.failover_policy,
                &input.commitment_policy,
                &input.health_policy,
                &input.circuit_policy,
                &input.probe_policy,
            )
            .is_err()
        );
        let mut input = valid_reliability_input();
        input.circuit_policy["max_open_duration_ms"] = json!(10_000);
        assert!(
            validate_reliability_policy(
                &input.attempt_policy,
                &input.deadline_policy,
                &input.retry_policy,
                &input.failover_policy,
                &input.commitment_policy,
                &input.health_policy,
                &input.circuit_policy,
                &input.probe_policy,
            )
            .is_err()
        );
        let mut input = valid_reliability_input();
        input
            .circuit_policy
            .as_object_mut()
            .unwrap()
            .remove("recovery_duration_ms");
        assert!(
            validate_reliability_policy(
                &input.attempt_policy,
                &input.deadline_policy,
                &input.retry_policy,
                &input.failover_policy,
                &input.commitment_policy,
                &input.health_policy,
                &input.circuit_policy,
                &input.probe_policy,
            )
            .is_err()
        );
    }

    #[test]
    fn egress_policy_defaults_are_closed_and_bounded() {
        assert!(
            validate_egress_policy(
                &crate::domain::EgressDnsPolicy::default(),
                &crate::domain::EgressAddressPolicy::default(),
                None,
                &crate::domain::EgressTlsPolicy::default(),
                &crate::domain::EgressRedirectPolicy::default(),
                &crate::domain::EgressConnectionPolicy::default(),
                &crate::domain::EgressBodyPolicy::default(),
            )
            .is_ok()
        );
        assert!(
            validate_egress_policy(
                &crate::domain::EgressDnsPolicy::default(),
                &crate::domain::EgressAddressPolicy::default(),
                Some("https://proxy.example"),
                &crate::domain::EgressTlsPolicy::default(),
                &crate::domain::EgressRedirectPolicy::default(),
                &crate::domain::EgressConnectionPolicy::default(),
                &crate::domain::EgressBodyPolicy::default(),
            )
            .is_err()
        );
        let redirect = crate::domain::EgressRedirectPolicy { max_redirects: 1 };
        assert!(
            validate_egress_policy(
                &crate::domain::EgressDnsPolicy::default(),
                &crate::domain::EgressAddressPolicy::default(),
                None,
                &crate::domain::EgressTlsPolicy::default(),
                &redirect,
                &crate::domain::EgressConnectionPolicy::default(),
                &crate::domain::EgressBodyPolicy::default(),
            )
            .is_err()
        );
    }
}
