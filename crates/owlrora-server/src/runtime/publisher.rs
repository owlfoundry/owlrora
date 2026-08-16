use std::{
    collections::{BTreeSet, HashMap},
    net::SocketAddr,
    str::FromStr as _,
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, jwk::JwkSet};
use serde::Serialize;
use sqlx::{Postgres, Row as _, Transaction};
use tokio::{sync::watch, task::JoinHandle};
use uuid::Uuid;

use crate::{
    adapters::postgres::{PgStore, StoreError},
    domain::{
        BrowserLoginProfile, Capability, CapabilityClaimPolicy, ClaimMapping, IssuerId, JwksSource,
        JwtRouteCeiling, KeyCachePolicy, KeyId, LlmFeatureCapability, LlmScopeCeiling,
        ManagementOrganizationCeiling, ManagementScope, ManagementScopeSet, OrganizationId,
        OrganizationRole, OrganizationSelector, PolicyId, ResourceScope, UserId,
    },
    secrets::SecretService,
};

use super::{
    ExternalIssuerSnapshot, IdentitySnapshot, IssuerVerifierMaterial, ManagementKeyVerifier,
    MembershipSnapshot, RuntimeGeneration, RuntimeSnapshot,
    builder::{build_credential_clients, capture_gateway_runtime, compatibility_registry_version},
};

#[derive(Clone, Debug, Serialize)]
pub struct PublicationStatus {
    pub database_revision: i64,
    pub database_security_revision: i64,
    pub applied_revision: i64,
    pub built_at: DateTime<Utc>,
    pub confirmed_at: DateTime<Utc>,
    pub last_error: Option<String>,
}

pub struct RuntimePublisher {
    store: PgStore,
    secrets: Arc<SecretService>,
    generation: ArcSwap<RuntimeGeneration>,
    status: ArcSwap<PublicationStatus>,
    shutdown: watch::Sender<bool>,
    refresh: tokio::sync::Mutex<()>,
    task: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    egress_dns_overrides: Arc<HashMap<String, SocketAddr>>,
}

impl std::fmt::Debug for RuntimePublisher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimePublisher")
            .field("status", &self.status.load())
            .finish_non_exhaustive()
    }
}

impl RuntimePublisher {
    pub async fn start(
        store: PgStore,
        secrets: Arc<SecretService>,
        node_id: String,
    ) -> Result<Arc<Self>, StoreError> {
        Self::start_with_egress_dns_overrides(store, secrets, node_id, HashMap::new()).await
    }

    pub(crate) async fn start_with_egress_dns_overrides(
        store: PgStore,
        secrets: Arc<SecretService>,
        node_id: String,
        egress_dns_overrides: HashMap<String, SocketAddr>,
    ) -> Result<Arc<Self>, StoreError> {
        let egress_dns_overrides = Arc::new(egress_dns_overrides);
        let initial = compile_generation(&store, &secrets, None, &egress_dns_overrides).await?;
        let status = PublicationStatus {
            database_revision: initial.snapshot.revision,
            database_security_revision: initial.snapshot.security_revision,
            applied_revision: initial.snapshot.revision,
            built_at: initial.snapshot.built_at,
            confirmed_at: Utc::now(),
            last_error: None,
        };
        let (shutdown, receiver) = watch::channel(false);
        let publisher = Arc::new(Self {
            store: store.clone(),
            secrets,
            generation: ArcSwap::from_pointee(initial),
            status: ArcSwap::from_pointee(status),
            shutdown,
            refresh: tokio::sync::Mutex::new(()),
            task: tokio::sync::Mutex::new(None),
            egress_dns_overrides,
        });
        let task_publisher = Arc::clone(&publisher);
        let task = tokio::spawn(async move {
            run_publication_loop(task_publisher, store, node_id, receiver).await;
        });
        *publisher.task.lock().await = Some(task);
        Ok(publisher)
    }

    #[must_use]
    pub fn capture(&self) -> Arc<RuntimeGeneration> {
        self.generation.load_full()
    }

    #[must_use]
    pub fn status(&self) -> Arc<PublicationStatus> {
        self.status.load_full()
    }

    #[must_use]
    pub fn capture_for_admission(
        &self,
        now: DateTime<Utc>,
        max_security_age: Duration,
    ) -> Option<Arc<RuntimeGeneration>> {
        for _ in 0..4 {
            let generation = self.capture();
            let status = self.status();
            let security_state_current = security_revision_is_current(
                generation.snapshot.security_revision,
                &status,
                now,
                max_security_age,
            );
            let tightening_due = generation
                .snapshot
                .organizations
                .values()
                .filter_map(|organization| organization.pending_tightening_deadline)
                .min();
            if !security_state_current || tightening_due.is_some_and(|deadline| deadline <= now) {
                return None;
            }
            if Arc::ptr_eq(&generation, &self.capture()) {
                return Some(generation);
            }
        }
        None
    }

    pub async fn refresh_now(&self) -> Result<i64, StoreError> {
        let _refresh = self.refresh.lock().await;
        let prior = self.capture();
        let candidate = compile_generation(
            &self.store,
            &self.secrets,
            Some(&prior),
            &self.egress_dns_overrides,
        )
        .await?;
        let revision = candidate.snapshot.revision;
        let (database_revision, database_security_revision) =
            publication_revisions(&self.store).await?;
        if database_security_revision > candidate.snapshot.security_revision {
            return Err(StoreError::Invariant(
                "runtime candidate was overtaken by a security tightening",
            ));
        }
        if revision > self.capture().snapshot.revision {
            self.generation.store(Arc::new(candidate));
        }
        self.status.store(Arc::new(PublicationStatus {
            database_revision,
            database_security_revision,
            applied_revision: self.capture().snapshot.revision,
            built_at: self.capture().snapshot.built_at,
            confirmed_at: Utc::now(),
            last_error: None,
        }));
        Ok(self.capture().snapshot.revision)
    }

    pub async fn shutdown(&self) {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.lock().await.take() {
            let _ = task.await;
        }
    }
}

fn security_revision_is_current(
    applied_security_revision: i64,
    status: &PublicationStatus,
    now: DateTime<Utc>,
    max_security_age: Duration,
) -> bool {
    status.database_security_revision <= applied_security_revision
        && now
            .signed_duration_since(status.confirmed_at)
            .to_std()
            .is_ok_and(|age| age <= max_security_age)
}

async fn run_publication_loop(
    publisher: Arc<RuntimePublisher>,
    store: PgStore,
    node_id: String,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let database_revisions = publication_revisions(&store).await;
                match database_revisions {
                    Ok((revision, security_revision)) if revision > publisher.capture().snapshot.revision => {
                        match publisher.refresh_now().await {
                            Ok(applied) => {
                                let security = publisher.capture().snapshot.security_revision;
                                let _ = update_watermark(&store, &node_id, applied, security, None).await;
                            }
                            Err(error) => {
                                let generation = publisher.capture();
                                publisher.status.store(Arc::new(PublicationStatus {
                                    database_revision: revision,
                                    database_security_revision: security_revision,
                                    applied_revision: generation.snapshot.revision,
                                    built_at: generation.snapshot.built_at,
                                    confirmed_at: Utc::now(),
                                    last_error: Some(error.to_string()),
                                }));
                                let security = generation.snapshot.security_revision;
                                let _ = update_watermark(&store, &node_id, generation.snapshot.revision, security, Some("publication_failed")).await;
                            }
                        }
                    }
                    Ok((revision, security_revision)) => {
                        let generation = publisher.capture();
                        publisher.status.store(Arc::new(PublicationStatus {
                            database_revision: revision,
                            database_security_revision: security_revision,
                            applied_revision: generation.snapshot.revision,
                            built_at: generation.snapshot.built_at,
                            confirmed_at: Utc::now(),
                            last_error: None,
                        }));
                        let security = generation.snapshot.security_revision;
                        let _ = update_watermark(&store, &node_id, generation.snapshot.revision, security, None).await;
                    }
                    Err(error) => {
                        let current = publisher.status();
                        publisher.status.store(Arc::new(PublicationStatus {
                            database_revision: current.database_revision,
                            database_security_revision: current.database_security_revision,
                            applied_revision: current.applied_revision,
                            built_at: current.built_at,
                            confirmed_at: current.confirmed_at,
                            last_error: Some(error.to_string()),
                        }));
                    }
                }
            }
            result = shutdown.changed() => {
                if result.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

async fn compile_generation(
    store: &PgStore,
    secrets: &SecretService,
    prior: Option<&RuntimeGeneration>,
    egress_dns_overrides: &HashMap<String, SocketAddr>,
) -> Result<RuntimeGeneration, StoreError> {
    let mut transaction = store.pool().begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let revision = sqlx::query_scalar::<_, i64>(
        "SELECT current_revision FROM runtime_revision_counter WHERE singleton = true",
    )
    .fetch_one(&mut *transaction)
    .await?;
    let security_revision = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(max(revision), 0) FROM configuration_journal
         WHERE security_classification = 'tightening' AND revision <= $1",
    )
    .bind(revision)
    .fetch_one(&mut *transaction)
    .await?;
    let identity = load_identity(&mut transaction).await?;
    let mut gateway = capture_gateway_runtime(&mut transaction).await?;
    transaction.commit().await?;
    let credential_clients = build_credential_clients(
        &mut gateway,
        store.installation_id(),
        secrets,
        prior,
        egress_dns_overrides,
    )
    .await;
    Ok(RuntimeGeneration {
        snapshot: Arc::new(RuntimeSnapshot {
            revision,
            security_revision,
            built_at: Utc::now(),
            compatibility_registry_version: compatibility_registry_version(),
            gateway_policy_ceilings: gateway.gateway_policy_ceilings,
            identity,
            gateway_keys: gateway.gateway_keys,
            organizations: gateway.organizations,
            policy_activations: gateway.policy_activations,
            catalog: gateway.catalog,
        }),
        credential_clients: Arc::new(credential_clients),
    })
}

async fn load_identity(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<IdentitySnapshot, StoreError> {
    let mut identity = IdentitySnapshot::default();
    for row in sqlx::query("SELECT id, status FROM users")
        .fetch_all(&mut **transaction)
        .await?
    {
        identity.active_users.insert(
            UserId::from_uuid(row.try_get("id")?),
            row.try_get::<String, _>("status")? == "active",
        );
    }
    for row in sqlx::query("SELECT id, status FROM organizations")
        .fetch_all(&mut **transaction)
        .await?
    {
        identity.active_organizations.insert(
            OrganizationId::from_uuid(row.try_get("id")?),
            row.try_get::<String, _>("status")? == "active",
        );
    }
    for row in sqlx::query(
        "SELECT id, organization_id, user_id, role, llm_scope_ceiling,
                llm_capability_ceiling, llm_route_ceiling
         FROM memberships WHERE status = 'active'",
    )
    .fetch_all(&mut **transaction)
    .await?
    {
        let role = parse_role(&row.try_get::<String, _>("role")?)?;
        let llm_scopes =
            serde_json::from_value::<LlmScopeCeiling>(row.try_get("llm_scope_ceiling")?)
                .map_err(|_| StoreError::Invariant("invalid membership LLM scope ceiling"))?;
        let llm_capabilities = parse_llm_capabilities(
            row.try_get("llm_capability_ceiling")?,
            "invalid membership LLM capability ceiling",
        )?;
        let llm_routes =
            serde_json::from_value::<JwtRouteCeiling>(row.try_get("llm_route_ceiling")?)
                .map_err(|_| StoreError::Invariant("invalid membership route ceiling"))?;
        identity.memberships.insert(
            (
                OrganizationId::from_uuid(row.try_get("organization_id")?),
                UserId::from_uuid(row.try_get("user_id")?),
            ),
            MembershipSnapshot {
                membership_id: row.try_get("id")?,
                role,
                llm_scopes,
                llm_capabilities,
                llm_routes,
            },
        );
    }
    load_management_keys(transaction, &mut identity).await?;
    load_external_identity(transaction, &mut identity).await?;
    for row in sqlx::query(
        "SELECT subject_kind, user_id, management_api_key_id
         FROM system_administrator_grants WHERE status = 'active'",
    )
    .fetch_all(&mut **transaction)
    .await?
    {
        match row.try_get::<String, _>("subject_kind")?.as_str() {
            "local_user" => {
                let id: Uuid = row.try_get("user_id")?;
                identity
                    .system_administrator_users
                    .insert(UserId::from_uuid(id), true);
            }
            "deployment_management_api_key" => {
                let id: Uuid = row.try_get("management_api_key_id")?;
                identity
                    .system_administrator_keys
                    .insert(KeyId::from_uuid(id), true);
            }
            _ => return Err(StoreError::Invariant("unknown administrator subject kind")),
        }
    }
    Ok(identity)
}

async fn load_external_identity(
    transaction: &mut Transaction<'_, Postgres>,
    identity: &mut IdentitySnapshot,
) -> Result<(), StoreError> {
    let issuer_rows = sqlx::query(
        "SELECT i.id, i.name, i.issuer, i.status, i.jwks_source, i.allowed_algorithms,
                i.accepted_audiences, i.subject_claim, i.claim_mapping,
                i.jwt_capability_ceiling, i.management_scope_ceiling,
                i.management_capability_ceiling, i.management_organization_ceiling,
                i.llm_scope_ceiling, i.llm_capability_ceiling, i.jwt_route_ceiling,
                i.organization_selector, i.capability_claim_policy,
                i.browser_login, i.provisioning_policy_id, i.clock_skew_seconds,
                i.key_cache_policy, i.policy_version,
                m.id AS material_id, m.version AS material_version, m.jwks,
                m.fetched_at, m.accepted_until
         FROM external_identity_issuers i
         LEFT JOIN issuer_verifier_material_versions m
           ON m.id = i.current_verifier_material_version_id AND m.issuer_id = i.id",
    )
    .fetch_all(&mut **transaction)
    .await?;

    for row in issuer_rows {
        let issuer_id = IssuerId::from_uuid(row.try_get("id")?);
        let algorithms = parse_algorithms(row.try_get("allowed_algorithms")?)?;
        let jwt_capability_ceiling = parse_string_set(
            row.try_get("jwt_capability_ceiling")?,
            "invalid issuer capability ceiling",
        )?;
        if jwt_capability_ceiling
            .iter()
            .any(|capability| !matches!(capability.as_str(), "management:access" | "llm:access"))
        {
            return Err(StoreError::Invariant("unknown issuer access class"));
        }
        let management_scopes = parse_optional_scopes(row.try_get("management_scope_ceiling")?)?;
        let management_capabilities =
            parse_capabilities(row.try_get("management_capability_ceiling")?)?;
        let management_organization_ceiling =
            serde_json::from_value::<ManagementOrganizationCeiling>(
                row.try_get("management_organization_ceiling")?,
            )
            .map_err(|_| StoreError::Invariant("invalid issuer organization ceiling"))?;
        let llm_scopes =
            serde_json::from_value::<LlmScopeCeiling>(row.try_get("llm_scope_ceiling")?)
                .map_err(|_| StoreError::Invariant("invalid issuer LLM scope ceiling"))?;
        let llm_capabilities = parse_llm_capabilities(
            row.try_get("llm_capability_ceiling")?,
            "invalid issuer LLM capability ceiling",
        )?;
        let llm_access = jwt_capability_ceiling.contains("llm:access");
        let management_access = jwt_capability_ceiling.contains("management:access");
        let llm_routes =
            serde_json::from_value::<JwtRouteCeiling>(row.try_get("jwt_route_ceiling")?)
                .map_err(|_| StoreError::Invariant("invalid issuer route ceiling"))?;
        let organization_selector =
            serde_json::from_value::<OrganizationSelector>(row.try_get("organization_selector")?)
                .map_err(|_| StoreError::Invariant("invalid issuer organization selector"))?;
        if management_access
            != (management_scopes.iter().next().is_some()
                && !management_capabilities.is_empty()
                && !matches!(
                    management_organization_ceiling,
                    ManagementOrganizationCeiling::None
                ))
        {
            return Err(StoreError::Invariant(
                "incomplete issuer management access contract",
            ));
        }
        if llm_access != llm_scopes.as_scopes().is_some()
            || (!llm_access
                && (!llm_capabilities.is_empty()
                    || !matches!(llm_routes, JwtRouteCeiling::None)
                    || !matches!(organization_selector, OrganizationSelector::None)))
        {
            return Err(StoreError::Invariant(
                "incomplete issuer LLM access contract",
            ));
        }
        let verifier_material = row
            .try_get::<Option<Uuid>, _>("material_id")?
            .map(|id| -> Result<IssuerVerifierMaterial, StoreError> {
                let jwks = serde_json::from_value::<JwkSet>(row.try_get("jwks")?)
                    .map_err(|_| StoreError::Invariant("invalid stored JWK set"))?;
                Ok(IssuerVerifierMaterial {
                    id,
                    version: row.try_get("material_version")?,
                    jwks,
                    fetched_at: row.try_get("fetched_at")?,
                    accepted_until: row.try_get("accepted_until")?,
                })
            })
            .transpose()?;
        let snapshot = ExternalIssuerSnapshot {
            id: issuer_id,
            name: row.try_get("name")?,
            issuer: row.try_get("issuer")?,
            active: row.try_get::<String, _>("status")? == "active",
            allowed_algorithms: algorithms,
            accepted_audiences: parse_string_set(
                row.try_get("accepted_audiences")?,
                "invalid accepted audience set",
            )?,
            subject_claim: row.try_get("subject_claim")?,
            claim_mapping: serde_json::from_value::<ClaimMapping>(row.try_get("claim_mapping")?)
                .map_err(|_| StoreError::Invariant("invalid issuer claim mapping"))?,
            jwt_capability_ceiling,
            management_scopes,
            management_capabilities,
            management_organization_ceiling,
            llm_access,
            llm_scopes,
            llm_capabilities,
            llm_routes,
            organization_selector,
            capability_claim_policy: serde_json::from_value::<CapabilityClaimPolicy>(
                serde_json::Value::String(row.try_get("capability_claim_policy")?),
            )
            .map_err(|_| StoreError::Invariant("invalid capability claim policy"))?,
            browser_login: row
                .try_get::<Option<serde_json::Value>, _>("browser_login")?
                .map(serde_json::from_value::<BrowserLoginProfile>)
                .transpose()
                .map_err(|_| StoreError::Invariant("invalid browser login profile"))?,
            provisioning_policy_id: row
                .try_get::<Option<Uuid>, _>("provisioning_policy_id")?
                .map(PolicyId::from_uuid),
            clock_skew_seconds: u32::try_from(row.try_get::<i32, _>("clock_skew_seconds")?)
                .map_err(|_| StoreError::Invariant("invalid issuer clock skew"))?,
            key_cache_policy: serde_json::from_value::<KeyCachePolicy>(
                row.try_get("key_cache_policy")?,
            )
            .map_err(|_| StoreError::Invariant("invalid issuer key cache policy"))?,
            jwks_source: serde_json::from_value::<JwksSource>(row.try_get("jwks_source")?)
                .map_err(|_| StoreError::Invariant("invalid issuer JWKS source"))?,
            policy_version: row.try_get("policy_version")?,
            verifier_material,
        };
        identity
            .external_issuers_by_issuer
            .insert(snapshot.issuer.clone(), snapshot.clone());
        identity.external_issuers_by_id.insert(issuer_id, snapshot);
    }

    for row in sqlx::query(
        "SELECT issuer_id, external_subject, user_id
         FROM external_identity_bindings WHERE status = 'active'",
    )
    .fetch_all(&mut **transaction)
    .await?
    {
        identity.external_bindings.insert(
            (
                IssuerId::from_uuid(row.try_get("issuer_id")?),
                row.try_get("external_subject")?,
            ),
            UserId::from_uuid(row.try_get("user_id")?),
        );
    }
    Ok(())
}

async fn load_management_keys(
    transaction: &mut Transaction<'_, Postgres>,
    identity: &mut IdentitySnapshot,
) -> Result<(), StoreError> {
    let deployment_policy = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT policy FROM deployment_management_key_policy WHERE singleton=true",
    )
    .fetch_one(&mut **transaction)
    .await?;
    let organization_policies =
        sqlx::query("SELECT organization_id, policy FROM organization_api_key_policies")
            .fetch_all(&mut **transaction)
            .await?
            .into_iter()
            .map(|row| {
                Ok((
                    row.try_get::<Uuid, _>("organization_id")?,
                    row.try_get("policy")?,
                ))
            })
            .collect::<Result<HashMap<Uuid, serde_json::Value>, sqlx::Error>>()?;
    let rows = sqlx::query(
        "SELECT k.id, k.resource_scope_kind, k.organization_id, k.issuance_policy_class,
                k.scopes, k.capability_ceiling, k.status, k.expires_at,
                v.id AS version_id, v.lookup_id, v.secret_digest, v.state, v.overlap_until
         FROM management_api_keys k
         JOIN management_api_key_secret_versions v ON v.management_api_key_id = k.id
         WHERE v.state IN ('current', 'overlap')",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut grouped: HashMap<KeyId, Vec<_>> = HashMap::new();
    for row in rows {
        let key_id = KeyId::from_uuid(row.try_get("id")?);
        grouped.entry(key_id).or_default().push(row);
    }
    for (key_id, rows) in grouped {
        let current = rows
            .iter()
            .find(|row| row.try_get::<String, _>("state").ok().as_deref() == Some("current"))
            .ok_or(StoreError::Invariant(
                "management key has no current secret",
            ))?;
        let stored_scopes = parse_scopes(current.try_get("scopes")?)?;
        let issuance_policy_class: String = current.try_get("issuance_policy_class")?;
        let resource_scope = match current
            .try_get::<String, _>("resource_scope_kind")?
            .as_str()
        {
            "deployment" => ResourceScope::Deployment,
            "organization" => ResourceScope::Organization {
                organization_id: OrganizationId::from_uuid(current.try_get("organization_id")?),
            },
            _ => return Err(StoreError::Invariant("unknown key resource scope")),
        };
        let policy = match &resource_scope {
            ResourceScope::Deployment => &deployment_policy,
            ResourceScope::Organization { organization_id } => organization_policies
                .get(&organization_id.as_uuid())
                .ok_or(StoreError::Invariant("organization key policy is missing"))?,
        };
        if !matches!(
            issuance_policy_class.as_str(),
            "standard" | "member_self_service"
        ) {
            return Err(StoreError::Invariant("unknown key issuance policy class"));
        }
        let global = policy.get("management").ok_or(StoreError::Invariant(
            "management key policy section is missing",
        ))?;
        let global_scopes = parse_optional_scopes(
            global
                .get("allowed_scopes")
                .cloned()
                .ok_or(StoreError::Invariant("policy scope ceiling is missing"))?,
        )?;
        let global_capabilities =
            parse_capabilities(global.get("allowed_capabilities").cloned().ok_or(
                StoreError::Invariant("policy capability ceiling is missing"),
            )?)?;
        let mut policy_scopes = global_scopes;
        let mut policy_capabilities = global_capabilities;
        if issuance_policy_class == "member_self_service" {
            let member = policy
                .get("member_self_service")
                .ok_or(StoreError::Invariant(
                    "member key policy section is missing",
                ))?;
            let member_scopes =
                parse_optional_scopes(member.get("allowed_scopes").cloned().ok_or(
                    StoreError::Invariant("member policy scope ceiling is missing"),
                )?)?;
            policy_scopes = policy_scopes.intersection(&member_scopes);
            let member_capabilities =
                parse_capabilities(member.get("allowed_capabilities").cloned().ok_or(
                    StoreError::Invariant("member policy capability ceiling is missing"),
                )?)?;
            policy_capabilities = policy_capabilities
                .intersection(&member_capabilities)
                .copied()
                .collect();
        }
        let scopes = stored_scopes.intersection(&policy_scopes);
        let stored_capabilities = parse_capabilities(current.try_get("capability_ceiling")?)?;
        let capabilities = stored_capabilities
            .intersection(&policy_capabilities)
            .copied()
            .collect::<BTreeSet<_>>();
        let expires_at: Option<DateTime<Utc>> = current.try_get("expires_at")?;
        let current_digest = digest_array(current.try_get("secret_digest")?)?;
        let overlap = rows
            .iter()
            .find(|row| row.try_get::<String, _>("state").ok().as_deref() == Some("overlap"));
        let effective_overlap_until = overlap
            .map(|row| row.try_get::<Option<DateTime<Utc>>, _>("overlap_until"))
            .transpose()?
            .flatten();
        let active = current.try_get::<String, _>("status")? == "active"
            && scopes.iter().next().is_some()
            && !capabilities.is_empty();
        let verifier = ManagementKeyVerifier {
            key_id,
            resource_scope,
            issuance_policy_class,
            scopes,
            capability_ceiling: serde_json::to_value(capabilities)
                .map_err(|_| StoreError::Invariant("effective key capabilities are invalid"))?,
            current_digest,
            accepted_version_id: current.try_get::<Uuid, _>("version_id")?.to_string(),
            overlap_digest: overlap
                .map(|row| digest_array(row.try_get("secret_digest")?))
                .transpose()?,
            overlap_version_id: overlap
                .map(|row| {
                    row.try_get::<Uuid, _>("version_id")
                        .map(|id| id.to_string())
                })
                .transpose()?,
            overlap_until: effective_overlap_until,
            expires_at,
            active,
        };
        let lookup = current.try_get::<String, _>("lookup_id")?;
        identity.management_keys.insert(lookup, verifier.clone());
        identity
            .management_keys_by_id
            .insert(key_id, verifier.clone());
        if let Some(overlap) = overlap {
            identity
                .management_keys
                .insert(overlap.try_get("lookup_id")?, verifier);
        }
    }
    Ok(())
}

fn parse_llm_capabilities(
    value: serde_json::Value,
    invariant: &'static str,
) -> Result<BTreeSet<LlmFeatureCapability>, StoreError> {
    let capabilities = serde_json::from_value::<Vec<LlmFeatureCapability>>(value)
        .map_err(|_| StoreError::Invariant(invariant))?;
    let unique = capabilities.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != capabilities.len() {
        return Err(StoreError::Invariant(invariant));
    }
    Ok(unique)
}

fn parse_capabilities(value: serde_json::Value) -> Result<BTreeSet<Capability>, StoreError> {
    let capabilities = serde_json::from_value::<Vec<Capability>>(value)
        .map_err(|_| StoreError::Invariant("invalid stored capability ceiling"))?;
    let unique = capabilities.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != capabilities.len() {
        return Err(StoreError::Invariant("duplicate stored capability ceiling"));
    }
    Ok(unique)
}

fn parse_role(value: &str) -> Result<OrganizationRole, StoreError> {
    match value {
        "owner" => Ok(OrganizationRole::Owner),
        "admin" => Ok(OrganizationRole::Admin),
        "member" => Ok(OrganizationRole::Member),
        _ => Err(StoreError::Invariant("unknown organization role")),
    }
}

fn parse_scopes(value: serde_json::Value) -> Result<ManagementScopeSet, StoreError> {
    let scopes = parse_scope_values(value)?;
    ManagementScopeSet::new(scopes)
        .map_err(|_| StoreError::Invariant("empty stored management scope set"))
}

fn parse_optional_scopes(value: serde_json::Value) -> Result<ManagementScopeSet, StoreError> {
    let scopes = parse_scope_values(value)?;
    if scopes.is_empty() {
        Ok(ManagementScopeSet::empty())
    } else {
        ManagementScopeSet::new(scopes)
            .map_err(|_| StoreError::Invariant("invalid issuer management scopes"))
    }
}

fn parse_scope_values(value: serde_json::Value) -> Result<Vec<ManagementScope>, StoreError> {
    let strings: Vec<String> = serde_json::from_value(value)
        .map_err(|_| StoreError::Invariant("invalid stored management scopes"))?;
    strings
        .iter()
        .map(|value| value.parse::<ManagementScope>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StoreError::Invariant("unknown stored management scope"))
}

fn parse_algorithms(value: serde_json::Value) -> Result<Vec<Algorithm>, StoreError> {
    let names: Vec<String> = serde_json::from_value(value)
        .map_err(|_| StoreError::Invariant("invalid issuer algorithm allowlist"))?;
    if names.is_empty() {
        return Err(StoreError::Invariant("empty issuer algorithm allowlist"));
    }
    let mut algorithms = Vec::with_capacity(names.len());
    for name in names {
        let algorithm = Algorithm::from_str(&name)
            .map_err(|_| StoreError::Invariant("unknown issuer algorithm"))?;
        if matches!(
            algorithm,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        ) {
            return Err(StoreError::Invariant(
                "symmetric issuer algorithm is forbidden",
            ));
        }
        if algorithms.contains(&algorithm) {
            return Err(StoreError::Invariant("duplicate issuer algorithm"));
        }
        algorithms.push(algorithm);
    }
    Ok(algorithms)
}

fn parse_string_set(
    value: serde_json::Value,
    invariant: &'static str,
) -> Result<BTreeSet<String>, StoreError> {
    let values: Vec<String> =
        serde_json::from_value(value).map_err(|_| StoreError::Invariant(invariant))?;
    if values.iter().any(String::is_empty)
        || values.len() != values.iter().collect::<BTreeSet<_>>().len()
    {
        return Err(StoreError::Invariant(invariant));
    }
    Ok(values.into_iter().collect())
}

fn digest_array(value: Vec<u8>) -> Result<[u8; 32], StoreError> {
    value
        .try_into()
        .map_err(|_| StoreError::Invariant("invalid stored key digest length"))
}

async fn publication_revisions(store: &PgStore) -> Result<(i64, i64), StoreError> {
    let row = sqlx::query(
        "SELECT current_revision,
                (SELECT COALESCE(max(revision), 0) FROM configuration_journal
                 WHERE security_classification='tightening') AS security_revision
         FROM runtime_revision_counter
         WHERE singleton=true",
    )
    .fetch_one(store.pool())
    .await?;
    Ok((row.get("current_revision"), row.get("security_revision")))
}

async fn update_watermark(
    store: &PgStore,
    node_id: &str,
    applied_revision: i64,
    applied_security_revision: i64,
    error: Option<&str>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO node_watermarks(
            node_id, applied_revision, applied_security_revision, last_success_at,
            last_failure_at, safe_failure_class, heartbeat_at
         ) VALUES ($1,$2,$3,CASE WHEN $4::text IS NULL THEN now() END,
                   CASE WHEN $4::text IS NOT NULL THEN now() END,$4,now())
         ON CONFLICT (node_id) DO UPDATE SET
            applied_revision = EXCLUDED.applied_revision,
            applied_security_revision = EXCLUDED.applied_security_revision,
            last_success_at = COALESCE(EXCLUDED.last_success_at, node_watermarks.last_success_at),
            last_failure_at = COALESCE(EXCLUDED.last_failure_at, node_watermarks.last_failure_at),
            safe_failure_class = EXCLUDED.safe_failure_class,
            heartbeat_at = now()",
    )
    .bind(node_id)
    .bind(applied_revision)
    .bind(applied_security_revision)
    .bind(error)
    .execute(store.pool())
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use owlrora_key_provider::{
        ContextVersion, FieldPurpose, InstallationId, MaterialId,
        OrganizationId as SecretOrganizationId, OwnerId, OwnerKind, ProtectionContext,
        ProtectionContextParts, ProviderFormatVersion, ProviderId, SecretPlaintext, SecretScope,
    };
    use serde_json::json;
    use sha2::{Digest as _, Sha256};

    use crate::{
        adapters::postgres::{
            AuditRecord, RuntimeEvent,
            test_support::{
                connect_from_environment, shared_database_test_lock, valid_reliability_components,
            },
        },
        config::SecretRoot,
        domain::{
            GatewayKeyMaterial, IngressProtocolFamily, OrganizationId, RouteId, gateway_key_digest,
            generate_gateway_key,
        },
    };

    use super::*;

    struct RuntimeFixture {
        organization_id: Uuid,
        route_id: Uuid,
        deployment_id: Uuid,
        endpoint_id: Uuid,
        network_id: Uuid,
        client_key: super::super::CredentialClientKey,
        gateway_key: GatewayKeyMaterial,
        lookup: String,
    }

    fn secret_service(byte: u8) -> Arc<SecretService> {
        Arc::new(
            SecretService::new(
                Some(Arc::new(SecretRoot::from_bytes([byte; 32]))),
                crate::secrets::CustodyRegistry::default(),
                crate::secrets::CustodyPair::software(),
            )
            .unwrap(),
        )
    }

    fn upstream_secret_context(
        installation_id: Uuid,
        material_id: Uuid,
        credential_id: Uuid,
        generation: u64,
        version: u64,
        organization_id: Uuid,
    ) -> ProtectionContext {
        ProtectionContext::new(ProtectionContextParts {
            version: ContextVersion::V1,
            installation_id: InstallationId::new(installation_id.to_string()).unwrap(),
            scope: SecretScope::Organization(
                SecretOrganizationId::new(organization_id.to_string()).unwrap(),
            ),
            material_id: MaterialId::new(material_id.to_string()).unwrap(),
            owner_kind: OwnerKind::new("upstream_credential").unwrap(),
            owner_id: OwnerId::new(credential_id.to_string()).unwrap(),
            owner_generation: generation,
            secret_version: version,
            field_purpose: FieldPurpose::new("upstream_credential_material").unwrap(),
            provider_id: ProviderId::new("software-xchacha20-poly1305").unwrap(),
            provider_format_version: ProviderFormatVersion::new(1).unwrap(),
        })
        .unwrap()
    }

    async fn insert_runtime_fixture(store: &PgStore, secrets: &SecretService) -> RuntimeFixture {
        let organization_id = Uuid::now_v7();
        let user_id = Uuid::now_v7();
        let membership_id = Uuid::now_v7();
        let network_id = Uuid::now_v7();
        let endpoint_id = Uuid::now_v7();
        let credential_id = Uuid::now_v7();
        let protected_id = Uuid::now_v7();
        let secret_version_id = Uuid::now_v7();
        let reliability_id = Uuid::now_v7();
        let deployment_id = Uuid::now_v7();
        let route_id = Uuid::now_v7();
        let target_id = Uuid::now_v7();
        let key_id = Uuid::now_v7();
        let budget_id = Uuid::now_v7();
        let gateway_key = generate_gateway_key();
        let lookup = gateway_key.lookup_text();
        let digest = gateway_key_digest(&gateway_key);
        let context = upstream_secret_context(
            store.installation_id(),
            protected_id,
            credential_id,
            1,
            1,
            organization_id,
        );
        let envelope = secrets
            .seal(
                &context,
                &SecretPlaintext::new(b"fixture-upstream-secret".to_vec()).unwrap(),
            )
            .await
            .unwrap();
        let envelope = envelope.expose(<[u8]>::to_vec);
        let safe_fingerprint: [u8; 32] = Sha256::digest(b"fixture-upstream-secret").into();
        let mut transaction = store.begin().await.unwrap();
        sqlx::query("SET CONSTRAINTS ALL DEFERRED")
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO organizations(id,kind,status,name,created_by_principal,etag_token)
             VALUES ($1,'ordinary','active',$2,'{}',$3)",
        )
        .bind(organization_id)
        .bind(format!("runtime-{organization_id}"))
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO organization_api_key_policies(organization_id,policy,etag_token)
             VALUES ($1,$2,$3)",
        )
        .bind(organization_id)
        .bind(json!({
            "management": {
                "allowed_scopes": ["management:read"], "allowed_capabilities": ["read_organization"],
                "max_active_keys": 100, "max_expiry_days": 365, "max_overlap_seconds": 3600
            },
            "member_self_service": {
                "management_key_creation": false, "allowed_scopes": [], "allowed_capabilities": [],
                "max_active_keys": 0, "max_expiry_days": 0, "max_overlap_seconds": 0
            },
            "gateway": {
                "enabled": true,
                "allowed_scopes": ["llm:invoke", "llm:stream"],
                "allowed_capabilities": [],
                "allowed_route_ids": [route_id],
                "max_active_keys": 10, "max_expiry_days": 365, "max_overlap_seconds": 3600,
                "budget": {"max_limit_cost_nanos":"1000000","allowed_modes":["enforce"]},
                "rate": {"max_requests_per_minute":100,"max_input_units_per_minute":100_000},
                "concurrency": {"max_limit":10,"allowed_modes":["approximate"]}
            },
            "gateway_member_self_service": {
                "enabled": false, "allowed_scopes": [], "allowed_capabilities": [],
                "allowed_route_ids": [], "max_active_keys": 0, "max_expiry_days": 0,
                "max_overlap_seconds": 0, "budget": {"max_limit_cost_nanos":"0","allowed_modes":[]},
                "rate": {"max_requests_per_minute":0,"max_input_units_per_minute":0},
                "concurrency": {"max_limit":0,"allowed_modes":[]}
            }
        }))
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO users(id,kind,status,display_name,created_by_principal,etag_token)
             VALUES ($1,'human','active','Runtime owner','{}',$2)",
        )
        .bind(user_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO memberships(id,organization_id,user_id,role,status,llm_scope_ceiling,
                llm_capability_ceiling,llm_route_ceiling,created_by_principal,etag_token)
             VALUES ($1,$2,$3,'owner','active','[\"llm:invoke\",\"llm:stream\"]','[]',
                $4,'{}',$5)",
        )
        .bind(membership_id)
        .bind(organization_id)
        .bind(user_id)
        .bind(json!({"kind":"routes","route_ids":[route_id.to_string()]}))
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO egress_network_policies(id,name,dns_policy,address_policy,tls_policy,
                redirect_policy,connection_policy,body_policy,status,created_by_principal,etag_token)
             VALUES ($1,$2,'{}','{}','{}','{}','{}','{}','active','{}',$3)",
        )
        .bind(network_id)
        .bind(format!("runtime-network-{network_id}"))
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO upstream_endpoints(id,name,adapter_kind,base_url,network_policy_id,
                safe_headers,status,created_by_principal,etag_token)
             VALUES ($1,$2,'openai_api','https://api.openai.example/v1/',$3,
                '{\"x-owlrora-fixture\":\"runtime\"}','active','{}',$4)",
        )
        .bind(endpoint_id)
        .bind(format!("runtime-endpoint-{endpoint_id}"))
        .bind(network_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO upstream_credentials(id,resource_scope_kind,organization_id,name,
                credential_kind,secret_source_kind,injection_kind,sharing_policy,
                administrative_status,authentication_status,current_secret_version,
                created_by_principal,etag_token)
             VALUES ($1,'organization',$2,$3,'static_api_key','encrypted_database','bearer',
                'exclusive','active','ready',1,'{}',$4)",
        )
        .bind(credential_id)
        .bind(organization_id)
        .bind(format!("runtime-credential-{credential_id}"))
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO protected_secret_versions(id,scope_kind,organization_id,owner_kind,
                owner_id,owner_generation,secret_version,field_purpose,custody_provider_id,
                provider_format_version,context_version,opaque_envelope)
             VALUES ($1,'organization',$2,'upstream_credential',$3,1,1,
                'upstream_credential_material','software-xchacha20-poly1305',1,1,$4)",
        )
        .bind(protected_id)
        .bind(organization_id)
        .bind(credential_id)
        .bind(envelope)
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO upstream_credential_secret_versions(id,credential_id,version,
                credential_state_identity_version,protected_secret_version_id,safe_fingerprint,state)
             VALUES ($1,$2,1,1,$3,$4,'current')",
        )
        .bind(secret_version_id)
        .bind(credential_id)
        .bind(protected_id)
        .bind(safe_fingerprint.to_vec())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO organization_endpoint_grants(organization_id,endpoint_id,status,
                created_by_principal,etag_token) VALUES ($1,$2,'active','{}',$3)",
        )
        .bind(organization_id)
        .bind(endpoint_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        let reliability = valid_reliability_components();
        sqlx::query(
            "INSERT INTO reliability_policies(id,name,attempt_policy,deadline_policy,retry_policy,
                failover_policy,commitment_policy,health_policy,circuit_policy,probe_policy,
                status,created_by_principal,etag_token)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'active','{}',$11)",
        )
        .bind(reliability_id)
        .bind(format!("runtime-reliability-{reliability_id}"))
        .bind(&reliability[0])
        .bind(&reliability[1])
        .bind(&reliability[2])
        .bind(&reliability[3])
        .bind(&reliability[4])
        .bind(&reliability[5])
        .bind(&reliability[6])
        .bind(&reliability[7])
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO organization_reliability_policy_grants(organization_id,
                reliability_policy_id,status,created_by_principal,etag_token)
             VALUES ($1,$2,'active','{}',$3)",
        )
        .bind(organization_id)
        .bind(reliability_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO model_deployments(id,resource_scope_kind,organization_id,name,
                endpoint_id,credential_id,transport_kind,upstream_model_id,capability_set,
                context_limits,state_isolation_profile,unpriced,status,created_by_principal,etag_token)
             VALUES ($1,'organization',$2,$3,$4,$5,'openai_responses_http','gpt-runtime',
                '[\"streaming\"]','{}','{}',true,'active','{}',$6)",
        )
        .bind(deployment_id)
        .bind(organization_id)
        .bind(format!("runtime-deployment-{deployment_id}"))
        .bind(endpoint_id)
        .bind(credential_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO model_routes(id,resource_scope_kind,organization_id,owner_user_id,
                owner_membership_id,model_key,ingress_protocol_family,required_base_capabilities,
                selection_policy,reliability_policy_id,request_policy,status,created_by_principal,etag_token)
             VALUES ($1,'organization',$2,$3,$4,'runtime-model','openai_responses',
                '[\"streaming\"]','{}',$5,'{}','active','{}',$6)",
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
        sqlx::query(
            "INSERT INTO route_targets(id,route_id,deployment_id,affinity_identity,priority,
                weight,enabled,etag_token) VALUES ($1,$2,$3,$4,0,256,true,$5)",
        )
        .bind(target_id)
        .bind(route_id)
        .bind(deployment_id)
        .bind(Uuid::new_v4().as_bytes().to_vec())
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO gateway_api_keys(id,organization_id,issuance_policy_class,
                created_by_principal,name,key_prefix,lookup_id,scopes,budget_policy_id,status,etag_token)
             VALUES ($1,$2,'standard','{}',$3,'owlrora_llm_v1',$4,
                '[\"llm:invoke\",\"llm:stream\"]',$5,'active',$6)",
        )
        .bind(key_id)
        .bind(organization_id)
        .bind(format!("runtime-key-{key_id}"))
        .bind(&lookup)
        .bind(budget_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO gateway_key_budget_policies(id,organization_id,gateway_api_key_id,
                status,etag_token) VALUES ($1,$2,$3,'suspended',$4)",
        )
        .bind(budget_id)
        .bind(organization_id)
        .bind(key_id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO gateway_api_key_secret_versions(id,gateway_api_key_id,lookup_id,
                secret_digest,state) VALUES ($1,$2,$3,$4,'current')",
        )
        .bind(Uuid::now_v7())
        .bind(key_id)
        .bind(&lookup)
        .bind(digest.to_vec())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO gateway_api_key_routes(organization_id,gateway_api_key_id,route_id)
             VALUES ($1,$2,$3)",
        )
        .bind(organization_id)
        .bind(key_id)
        .bind(route_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
            .execute(&mut *transaction)
            .await
            .unwrap();
        transaction.commit().await.unwrap();

        let client_key = super::super::CredentialClientKey {
            credential_id: crate::domain::CredentialId::from_uuid(credential_id),
            secret_version: 1,
            endpoint_id: crate::domain::EndpointId::from_uuid(endpoint_id),
            endpoint_config_version: 1,
            transport_kind: crate::domain::TransportKind::OpenaiResponsesHttp,
        };
        RuntimeFixture {
            organization_id,
            route_id,
            deployment_id,
            endpoint_id,
            network_id,
            client_key,
            gateway_key,
            lookup,
        }
    }

    async fn allocate_fixture_revision(store: &PgStore, event_kind: &str, tightening: bool) -> i64 {
        let transaction = store.begin().await.unwrap();
        store
            .commit_command(
                transaction,
                &AuditRecord {
                    actor: None,
                    authentication_evidence: json!({"kind":"runtime_test"}),
                    organization_id: None,
                    target_resource_kind: "runtime_fixture".to_owned(),
                    target_resource_id: None,
                    operation_id: event_kind.to_owned(),
                    outcome: "accepted",
                    request_id: Uuid::now_v7().to_string(),
                    changed_fields: vec!["runtime_fixture".to_owned()],
                    safe_details: json!({}),
                },
                Some(&RuntimeEvent {
                    event_kind: event_kind.to_owned(),
                    affected_scope: json!({"kind":"runtime_fixture"}),
                    security_tightening: tightening,
                }),
            )
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn runtime_generation_atomically_compiles_gateway_graph_and_clients() {
        let _database_guard = shared_database_test_lock().await;
        let Some(store) = connect_from_environment().await else {
            return;
        };
        let secrets = secret_service(91);
        let fixture = insert_runtime_fixture(&store, &secrets).await;
        allocate_fixture_revision(&store, "runtime_fixture.created", false).await;
        let publisher = RuntimePublisher::start(
            store.clone(),
            Arc::clone(&secrets),
            format!("runtime-fixture-{}", Uuid::now_v7()),
        )
        .await
        .unwrap();
        let first = publisher.capture();
        let verifier = first.snapshot.gateway_keys.get(&fixture.lookup).unwrap();
        assert_eq!(
            verifier.organization_id,
            OrganizationId::from_uuid(fixture.organization_id)
        );
        assert_eq!(
            verifier.current_digest,
            gateway_key_digest(&fixture.gateway_key)
        );
        assert!(
            verifier
                .route_ids
                .contains(&RouteId::from_uuid(fixture.route_id))
        );
        let organization = first
            .snapshot
            .organizations
            .get(&OrganizationId::from_uuid(fixture.organization_id))
            .unwrap();
        let route = first
            .snapshot
            .catalog
            .resolve_route(
                organization,
                IngressProtocolFamily::OpenaiResponses,
                "runtime-model",
            )
            .unwrap();
        assert_eq!(route.targets.len(), 1);
        assert_eq!(
            route.targets[0].deployment_id.as_uuid(),
            fixture.deployment_id
        );
        assert!(
            first
                .snapshot
                .catalog
                .deployments
                .get(&crate::domain::DeploymentId::from_uuid(
                    fixture.deployment_id
                ))
                .unwrap()
                .operational
        );
        let first_client = first
            .credential_clients
            .clients
            .get(&fixture.client_key)
            .unwrap()
            .clone();
        assert_eq!(
            first_client.base_url.as_str(),
            "https://api.openai.example/v1/"
        );
        assert!(!format!("{first_client:?}").contains("fixture-upstream-secret"));

        allocate_fixture_revision(&store, "runtime_fixture.noop", false).await;
        publisher.refresh_now().await.unwrap();
        let second = publisher.capture();
        let second_client = second
            .credential_clients
            .clients
            .get(&fixture.client_key)
            .unwrap();
        assert!(Arc::ptr_eq(&first_client, second_client));

        sqlx::query("UPDATE upstream_endpoints SET adapter_kind='anthropic_api' WHERE id=$1")
            .bind(fixture.endpoint_id)
            .execute(store.pool())
            .await
            .unwrap();
        allocate_fixture_revision(&store, "runtime_fixture.corrupt_graph", true).await;
        assert!(publisher.refresh_now().await.is_err());
        assert_eq!(
            publisher.capture().snapshot.revision,
            second.snapshot.revision
        );
        sqlx::query("UPDATE upstream_endpoints SET adapter_kind='openai_api' WHERE id=$1")
            .bind(fixture.endpoint_id)
            .execute(store.pool())
            .await
            .unwrap();

        sqlx::query(
            "UPDATE egress_network_policies
             SET redirect_policy='{\"max_redirects\":1}', config_version=config_version+1
             WHERE id=$1",
        )
        .bind(fixture.network_id)
        .execute(store.pool())
        .await
        .unwrap();
        allocate_fixture_revision(&store, "runtime_fixture.unsafe_egress_policy", true).await;
        publisher.refresh_now().await.unwrap();
        let unavailable = publisher.capture();
        assert!(
            !unavailable
                .credential_clients
                .clients
                .contains_key(&fixture.client_key)
        );
        assert_eq!(
            unavailable
                .credential_clients
                .unavailable
                .get(&fixture.client_key),
            Some(&"egress_policy_unsupported_or_unsafe")
        );
        assert!(
            !unavailable
                .snapshot
                .catalog
                .deployments
                .get(&crate::domain::DeploymentId::from_uuid(
                    fixture.deployment_id
                ))
                .unwrap()
                .operational
        );
        assert_eq!(
            unavailable.snapshot.security_revision,
            unavailable.snapshot.revision
        );
        publisher.shutdown().await;
    }

    #[test]
    fn admission_uses_confirmed_security_revision_not_generation_build_age() {
        let now = Utc::now();
        let mut status = PublicationStatus {
            database_revision: 9,
            database_security_revision: 4,
            applied_revision: 8,
            built_at: now - chrono::TimeDelta::hours(24),
            confirmed_at: now - chrono::TimeDelta::seconds(1),
            last_error: Some("ordinary revision failed to compile".to_owned()),
        };
        assert!(security_revision_is_current(
            4,
            &status,
            now,
            Duration::from_secs(5),
        ));

        status.database_security_revision = 5;
        assert!(!security_revision_is_current(
            4,
            &status,
            now,
            Duration::from_secs(5),
        ));

        status.database_security_revision = 4;
        status.confirmed_at = now - chrono::TimeDelta::seconds(6);
        assert!(!security_revision_is_current(
            4,
            &status,
            now,
            Duration::from_secs(5),
        ));
    }

    #[test]
    fn gateway_key_fixture_wire_value_is_canonical() {
        let key = generate_gateway_key();
        let wire = key.expose_once();
        assert_eq!(
            GatewayKeyMaterial::parse(&wire).unwrap().lookup_text(),
            key.lookup_text()
        );
        assert!(!URL_SAFE_NO_PAD.encode(gateway_key_digest(&key)).is_empty());
    }
}
