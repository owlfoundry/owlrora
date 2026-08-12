use std::{
    collections::{BTreeSet, HashMap},
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
        KeyCachePolicy, KeyId, ManagementOrganizationCeiling, ManagementScope, ManagementScopeSet,
        OrganizationId, OrganizationRole, PolicyId, ResourceScope, UserId,
    },
};

use super::{
    ExternalIssuerSnapshot, IdentitySnapshot, IssuerVerifierMaterial, ManagementKeyVerifier,
    MembershipSnapshot, RuntimeGeneration, RuntimeSnapshot,
};

#[derive(Clone, Debug, Serialize)]
pub struct PublicationStatus {
    pub database_revision: i64,
    pub applied_revision: i64,
    pub built_at: DateTime<Utc>,
    pub confirmed_at: DateTime<Utc>,
    pub last_error: Option<String>,
}

pub struct RuntimePublisher {
    generation: ArcSwap<RuntimeGeneration>,
    status: ArcSwap<PublicationStatus>,
    shutdown: watch::Sender<bool>,
    refresh: tokio::sync::Mutex<()>,
    task: tokio::sync::Mutex<Option<JoinHandle<()>>>,
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
    pub async fn start(store: PgStore, node_id: String) -> Result<Arc<Self>, StoreError> {
        let initial = compile_generation(&store).await?;
        let status = PublicationStatus {
            database_revision: initial.snapshot.revision,
            applied_revision: initial.snapshot.revision,
            built_at: initial.snapshot.built_at,
            confirmed_at: Utc::now(),
            last_error: None,
        };
        let (shutdown, receiver) = watch::channel(false);
        let publisher = Arc::new(Self {
            generation: ArcSwap::from_pointee(initial),
            status: ArcSwap::from_pointee(status),
            shutdown,
            refresh: tokio::sync::Mutex::new(()),
            task: tokio::sync::Mutex::new(None),
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

    pub async fn refresh_now(&self, store: &PgStore) -> Result<i64, StoreError> {
        let _refresh = self.refresh.lock().await;
        let candidate = compile_generation(store).await?;
        let revision = candidate.snapshot.revision;
        if revision > self.capture().snapshot.revision {
            self.generation.store(Arc::new(candidate));
        }
        self.status.store(Arc::new(PublicationStatus {
            database_revision: revision,
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
                let database_revision = store.current_revision().await;
                match database_revision {
                    Ok(revision) if revision > publisher.capture().snapshot.revision => {
                        match publisher.refresh_now(&store).await {
                            Ok(applied) => {
                                let _ = update_watermark(&store, &node_id, applied, None).await;
                            }
                            Err(error) => {
                                let applied = publisher.capture().snapshot.revision;
                                publisher.status.store(Arc::new(PublicationStatus {
                                    database_revision: revision,
                                    applied_revision: applied,
                                    built_at: publisher.capture().snapshot.built_at,
                                    confirmed_at: publisher.status().confirmed_at,
                                    last_error: Some(error.to_string()),
                                }));
                                let _ = update_watermark(&store, &node_id, applied, Some("publication_failed")).await;
                            }
                        }
                    }
                    Ok(revision) => {
                        let applied = publisher.capture().snapshot.revision;
                        publisher.status.store(Arc::new(PublicationStatus {
                            database_revision: revision,
                            applied_revision: applied,
                            built_at: publisher.capture().snapshot.built_at,
                            confirmed_at: Utc::now(),
                            last_error: None,
                        }));
                        let _ = update_watermark(&store, &node_id, applied, None).await;
                    }
                    Err(error) => {
                        let current = publisher.status();
                        publisher.status.store(Arc::new(PublicationStatus {
                            database_revision: current.database_revision,
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

async fn compile_generation(store: &PgStore) -> Result<RuntimeGeneration, StoreError> {
    let mut transaction = store.pool().begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let revision = sqlx::query_scalar::<_, i64>(
        "SELECT current_revision FROM runtime_revision_counter WHERE singleton = true",
    )
    .fetch_one(&mut *transaction)
    .await?;
    let identity = load_identity(&mut transaction).await?;
    transaction.commit().await?;
    Ok(RuntimeGeneration {
        snapshot: Arc::new(RuntimeSnapshot {
            revision,
            built_at: Utc::now(),
            identity,
        }),
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
        "SELECT organization_id, user_id, role FROM memberships WHERE status = 'active'",
    )
    .fetch_all(&mut **transaction)
    .await?
    {
        let role = parse_role(&row.try_get::<String, _>("role")?)?;
        identity.memberships.insert(
            (
                OrganizationId::from_uuid(row.try_get("organization_id")?),
                UserId::from_uuid(row.try_get("user_id")?),
            ),
            MembershipSnapshot { role },
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
                i.management_organization_ceiling, i.capability_claim_policy,
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
        let management_scopes = parse_optional_scopes(row.try_get("management_scope_ceiling")?)?;
        let management_capabilities = if jwt_capability_ceiling.contains("management:access") {
            Capability::ALL.into_iter().collect()
        } else {
            BTreeSet::new()
        };
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
            management_organization_ceiling:
                serde_json::from_value::<ManagementOrganizationCeiling>(
                    row.try_get("management_organization_ceiling")?,
                )
                .map_err(|_| StoreError::Invariant("invalid issuer organization ceiling"))?,
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

async fn update_watermark(
    store: &PgStore,
    node_id: &str,
    applied_revision: i64,
    error: Option<&str>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO node_watermarks(
            node_id, applied_revision, applied_security_revision, last_success_at,
            last_failure_at, safe_failure_class, heartbeat_at
         ) VALUES ($1,$2,$2,CASE WHEN $3::text IS NULL THEN now() END,
                   CASE WHEN $3::text IS NOT NULL THEN now() END,$3,now())
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
    .bind(error)
    .execute(store.pool())
    .await?;
    Ok(())
}
