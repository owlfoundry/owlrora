use std::{collections::BTreeMap, net::IpAddr};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use owlrora_key_provider::{
    ContextVersion, FieldPurpose, InstallationId, MaterialId, OpaqueEnvelope, OwnerId, OwnerKind,
    ProtectionContext, ProtectionContextParts, ProviderFormatVersion, ProviderId, SecretPlaintext,
    SecretScope,
};
use rand::RngCore as _;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    adapters::postgres::{AuditRecord, RuntimeEvent},
    domain::{
        Actor, BrowserClientAuthentication, Capability, IssuerId, IssuerStatus, JwksSource,
        ManagementScope, constant_time_digest_matches,
    },
};

use super::identity_egress::read_bounded_response;
use super::{
    Application, ApplicationError, AuthorizationTarget, BrowserLoginIssuer, BrowserLoginValidation,
    OidcCallbackResult, OidcLoginRedirect, ReplaceBrowserClientSecret, RequestIdentity,
};

const STATE_PREFIX: &str = "owlrora_oidc_state_v1";
const TRANSACTION_PREFIX: &str = "owlrora_oidc_transaction_v1";
const MAX_TOKEN_RESPONSE_BYTES: usize = 131_072;

fn require_protected_browser_client(row: &sqlx::postgres::PgRow) -> Result<(), ApplicationError> {
    let profile = serde_json::from_value::<crate::domain::BrowserLoginProfile>(
        row.try_get::<Option<Value>, _>("browser_login")?
            .ok_or_else(|| {
                ApplicationError::Conflict("browser login is not configured".to_owned())
            })?,
    )
    .map_err(|_| ApplicationError::Internal)?;
    if profile.client_authentication == BrowserClientAuthentication::ProtectedClientSecret {
        Ok(())
    } else {
        Err(ApplicationError::Conflict(
            "issuer browser login uses a public client".to_owned(),
        ))
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

impl Application {
    pub async fn list_browser_login_issuers(
        &self,
    ) -> Result<Vec<BrowserLoginIssuer>, ApplicationError> {
        let generation = self.security_generation()?;
        let rows = sqlx::query(
            "SELECT id, name, display_name, browser_login
             FROM external_identity_issuers
             WHERE status='active' AND browser_login IS NOT NULL
               AND jwt_capability_ceiling ? 'management:access'
               AND jsonb_array_length(management_scope_ceiling) > 0
               AND management_organization_ceiling->>'kind' <> 'none'
               AND (
                   browser_login->>'client_authentication' = 'public'
                   OR EXISTS (
                       SELECT 1 FROM protected_secret_versions s
                       WHERE s.owner_kind='identity_issuer' AND s.owner_id=external_identity_issuers.id
                         AND s.field_purpose='oidc_client_secret'
                   )
               )
             ORDER BY display_name, id LIMIT 33",
        )
        .fetch_all(self.store.pool())
        .await?;
        if rows.len() > 32 {
            return Err(ApplicationError::DependencyUnavailable);
        }
        let mut issuers = Vec::new();
        for row in rows {
            let issuer_id = IssuerId::from_uuid(row.try_get("id")?);
            let Some(snapshot) = generation
                .snapshot
                .identity
                .external_issuers_by_id
                .get(&issuer_id)
            else {
                continue;
            };
            if !snapshot.verifier_material.as_ref().is_some_and(|material| {
                matches!(snapshot.jwks_source, JwksSource::Static { .. })
                    || material.accepted_until > Utc::now()
            }) {
                continue;
            }
            let profile = serde_json::from_value::<crate::domain::BrowserLoginProfile>(
                row.try_get("browser_login")?,
            )
            .map_err(|_| ApplicationError::Internal)?;
            if profile.status == IssuerStatus::Active {
                issuers.push(BrowserLoginIssuer {
                    name: row.try_get("name")?,
                    display_name: row.try_get("display_name")?,
                });
            }
        }
        Ok(issuers)
    }

    pub async fn begin_oidc_login(
        &self,
        issuer_name: &str,
        return_to: Option<&str>,
        source_address: IpAddr,
    ) -> Result<OidcLoginRedirect, ApplicationError> {
        self.oidc_login_rate
            .lock()
            .map_err(|_| ApplicationError::Internal)?
            .check(source_address, issuer_name)?;
        let _permit = self
            .oidc_login_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApplicationError::RateLimited)?;
        let generation = self.security_generation()?;
        let issuer = generation
            .snapshot
            .identity
            .external_issuers_by_id
            .values()
            .find(|issuer| issuer.name == issuer_name && issuer.active)
            .filter(|issuer| {
                issuer.verifier_material.as_ref().is_some_and(|material| {
                    matches!(issuer.jwks_source, JwksSource::Static { .. })
                        || material.accepted_until > Utc::now()
                })
            })
            .ok_or(ApplicationError::NotFound)?;
        let profile = issuer
            .browser_login
            .as_ref()
            .filter(|profile| profile.status == IssuerStatus::Active)
            .ok_or(ApplicationError::NotFound)?;
        let return_to = validate_return_to(return_to.unwrap_or("/"))?;
        let state_id = Uuid::now_v7();
        let state = generate_opaque_value(STATE_PREFIX);
        let transaction_token = generate_opaque_value(TRANSACTION_PREFIX);
        let nonce = generate_random_value();
        let pkce_verifier = Zeroizing::new(generate_random_value());
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce_verifier.as_bytes()));
        let state_digest = digest_nonrecoverable(b"oidc-state", state.as_bytes());
        let transaction_digest =
            digest_nonrecoverable(b"oidc-transaction", transaction_token.as_bytes());
        let nonce_digest = digest_nonrecoverable(b"oidc-nonce", nonce.as_bytes());
        let context = state_protection_context(
            self.store.installation_id(),
            state_id,
            self.secrets.write_pair(),
        )?;
        let plaintext = SecretPlaintext::new(pkce_verifier.as_bytes().to_vec())
            .map_err(|_| ApplicationError::Internal)?;
        let envelope = self
            .secrets
            .seal(&context, &plaintext)
            .await
            .map_err(|_| ApplicationError::Internal)?;
        let envelope_bytes = envelope.expose(<[u8]>::to_vec);
        let mut transaction = self.store.begin().await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('owlrora:oidc-login-capacity', 0))",
        )
        .execute(&mut *transaction)
        .await?;
        let global_active = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM oidc_login_states
             WHERE consumed_at IS NULL AND expires_at > now()",
        )
        .fetch_one(&mut *transaction)
        .await?;
        let issuer_active = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM oidc_login_states
             WHERE issuer_id=$1 AND consumed_at IS NULL AND expires_at > now()",
        )
        .bind(issuer.id.as_uuid())
        .fetch_one(&mut *transaction)
        .await?;
        if global_active >= 20_000 || issuer_active >= 2_000 {
            return Err(ApplicationError::RateLimited);
        }
        sqlx::query(
            "INSERT INTO oidc_login_states(
                id,state_digest,issuer_id,pkce_verifier_envelope,pkce_custody_provider_id,
                pkce_provider_format_version,pkce_context_version,nonce_digest,return_to,
                issuer_policy_version,transaction_digest,expires_at
             ) VALUES ($1,$2,$3,$4,$5,$6,1,$7,$8,$9,$10,now()+interval '10 minutes')",
        )
        .bind(state_id)
        .bind(state_digest.to_vec())
        .bind(issuer.id.as_uuid())
        .bind(envelope_bytes)
        .bind(context.parts().provider_id.as_str())
        .bind(
            i32::try_from(context.parts().provider_format_version.get())
                .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(nonce_digest.to_vec())
        .bind(&return_to)
        .bind(issuer.policy_version)
        .bind(transaction_digest.to_vec())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;

        let redirect_uri = self.issuer_callback_uri(issuer_name)?;
        let mut authorization_url = profile.authorization_endpoint.clone();
        authorization_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &profile.client_id)
            .append_pair("redirect_uri", redirect_uri.as_str())
            .append_pair(
                "scope",
                &profile.scopes.iter().cloned().collect::<Vec<_>>().join(" "),
            )
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &code_challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(OidcLoginRedirect {
            authorization_url: authorization_url.to_string(),
            transaction_token,
        })
    }

    pub async fn complete_oidc_login(
        &self,
        issuer_name: &str,
        state: &str,
        transaction_token: &str,
        code: &str,
        request_id: String,
    ) -> Result<OidcCallbackResult, ApplicationError> {
        if code.is_empty() || code.len() > 4096 {
            return Err(ApplicationError::InvalidCredential);
        }
        let _callback_permit = self
            .oidc_callback_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApplicationError::RateLimited)?;
        let generation = self.security_generation()?;
        let state_digest = parse_opaque_value(STATE_PREFIX, state, b"oidc-state")?;
        let transaction_digest =
            parse_opaque_value(TRANSACTION_PREFIX, transaction_token, b"oidc-transaction")?;
        let row = sqlx::query(
            "UPDATE oidc_login_states SET consumed_at=now()
             WHERE state_digest=$1 AND transaction_digest=$2
               AND consumed_at IS NULL AND expires_at > now()
             RETURNING id,issuer_id,pkce_verifier_envelope,pkce_custody_provider_id,
                       pkce_provider_format_version,pkce_context_version,nonce_digest,return_to,
                       issuer_policy_version",
        )
        .bind(state_digest.to_vec())
        .bind(transaction_digest.to_vec())
        .fetch_optional(self.store.pool())
        .await?
        .ok_or(ApplicationError::InvalidCredential)?;
        let state_id: Uuid = row.try_get("id")?;
        let issuer_id = IssuerId::from_uuid(row.try_get("issuer_id")?);
        let stored_nonce = digest_array(row.try_get("nonce_digest")?)?;
        let return_to: String = row.try_get("return_to")?;
        let issuer_policy_version: i64 = row.try_get("issuer_policy_version")?;
        if row.try_get::<i32, _>("pkce_context_version")? != 1 {
            return Err(ApplicationError::Internal);
        }
        let pair = crate::secrets::CustodyPair::new(
            ProviderId::new(row.try_get::<String, _>("pkce_custody_provider_id")?)
                .map_err(|_| ApplicationError::Internal)?,
            ProviderFormatVersion::new(
                u32::try_from(row.try_get::<i32, _>("pkce_provider_format_version")?)
                    .map_err(|_| ApplicationError::Internal)?,
            )
            .map_err(|_| ApplicationError::Internal)?,
        );
        let context = state_protection_context(self.store.installation_id(), state_id, &pair)?;
        let envelope = OpaqueEnvelope::new(row.try_get::<Vec<u8>, _>("pkce_verifier_envelope")?)
            .map_err(|_| ApplicationError::Internal)?;
        let verifier_plaintext = self
            .secrets
            .open(&context, &envelope)
            .await
            .map_err(|_| ApplicationError::Internal)?;
        let pkce_verifier = Zeroizing::new(
            verifier_plaintext
                .expose(|bytes| String::from_utf8(bytes.to_vec()))
                .map_err(|_| ApplicationError::Internal)?,
        );

        let issuer = generation
            .snapshot
            .identity
            .external_issuers_by_id
            .get(&issuer_id)
            .filter(|issuer| {
                issuer.active
                    && issuer.name == issuer_name
                    && issuer.policy_version == issuer_policy_version
            })
            .ok_or(ApplicationError::InvalidCredential)?;
        let profile = issuer
            .browser_login
            .as_ref()
            .filter(|profile| profile.status == IssuerStatus::Active)
            .ok_or(ApplicationError::InvalidCredential)?;
        let redirect_uri = self.issuer_callback_uri(issuer_name)?;
        let mut form = BTreeMap::from([
            ("grant_type", "authorization_code".to_owned()),
            ("code", code.to_owned()),
            ("redirect_uri", redirect_uri.to_string()),
            ("client_id", profile.client_id.clone()),
            ("code_verifier", pkce_verifier.to_string()),
        ]);
        if profile.client_authentication == BrowserClientAuthentication::ProtectedClientSecret {
            form.insert(
                "client_secret",
                self.open_browser_client_secret(issuer_id)
                    .await?
                    .to_string(),
            );
        }
        let identity_http = self.identity_http_client(&profile.token_endpoint).await?;
        let request = identity_http
            .post(profile.token_endpoint.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&form);
        for value in form.values_mut() {
            value.zeroize();
        }
        let response = request
            .send()
            .await
            .map_err(|_| ApplicationError::DependencyUnavailable)?;
        if !response.status().is_success() {
            return Err(ApplicationError::InvalidCredential);
        }
        let bytes = read_bounded_response(response, MAX_TOKEN_RESPONSE_BYTES).await?;
        let token_response: TokenResponse =
            serde_json::from_slice(&bytes).map_err(|_| ApplicationError::InvalidCredential)?;
        if token_response.id_token.len()
            > usize::try_from(issuer.key_cache_policy.max_token_bytes).unwrap_or(0)
        {
            return Err(ApplicationError::InvalidCredential);
        }
        let (token_issuer_id, external_subject, claims) =
            self.verify_external_jwt_evidence(&token_response.id_token, &generation)?;
        if token_issuer_id != issuer_id || !oidc_audience_matches(&claims, &profile.client_id) {
            return Err(ApplicationError::InvalidCredential);
        }
        let nonce = claims
            .get("nonce")
            .and_then(Value::as_str)
            .filter(|nonce| !nonce.is_empty() && nonce.len() <= 512)
            .ok_or(ApplicationError::InvalidCredential)?;
        let nonce_digest = digest_nonrecoverable(b"oidc-nonce", nonce.as_bytes());
        if !constant_time_digest_matches(&nonce_digest, &stored_nonce) {
            return Err(ApplicationError::InvalidCredential);
        }
        self.validate_external_management_evidence(issuer, &claims)?;
        let requires_provisioning = !generation
            .snapshot
            .identity
            .external_bindings
            .contains_key(&(issuer_id, external_subject.clone()));
        let current_generation = if requires_provisioning {
            self.provision_oidc_subject(
                issuer,
                &external_subject,
                &claims,
                &request_id,
                &generation,
            )
            .await?
        } else {
            generation
        };
        let (direct_identity, _) = self.verify_external_jwt_in_generation(
            &token_response.id_token,
            request_id,
            current_generation,
        )?;
        let session = self.create_external_session(&direct_identity).await?;
        Ok(OidcCallbackResult { session, return_to })
    }

    pub async fn replace_browser_client_secret(
        &self,
        identity: &RequestIdentity,
        issuer_id: IssuerId,
        input: ReplaceBrowserClientSecret,
    ) -> Result<(), ApplicationError> {
        self.authorize(
            identity,
            &[
                ManagementScope::Write,
                ManagementScope::Secrets,
                ManagementScope::Authority,
            ],
            AuthorizationTarget::System {
                capability: Capability::ManageIdentity,
            },
        )?;
        if input.client_secret.len() < 8
            || input.client_secret.len() > 4096
            || input.client_secret.chars().any(char::is_control)
        {
            return Err(ApplicationError::Validation(
                "client secret must contain 8 to 4096 safe characters".to_owned(),
            ));
        }
        let plaintext = SecretPlaintext::new(input.client_secret.into_bytes())
            .map_err(|_| ApplicationError::Validation("client secret is empty".to_owned()))?;
        let captured = sqlx::query(
            "SELECT browser_login, policy_version FROM external_identity_issuers WHERE id=$1",
        )
        .bind(issuer_id.as_uuid())
        .fetch_optional(self.store.pool())
        .await?
        .ok_or(ApplicationError::NotFound)?;
        require_protected_browser_client(&captured)?;
        let captured_policy_version: i64 = captured.try_get("policy_version")?;
        let secret_version = sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(max(secret_version),0)+1 FROM protected_secret_versions
             WHERE owner_kind='identity_issuer' AND owner_id=$1
               AND field_purpose='oidc_client_secret'",
        )
        .bind(issuer_id.as_uuid())
        .fetch_one(self.store.pool())
        .await?;
        let material_id = Uuid::now_v7();
        let owner_generation =
            u64::try_from(captured_policy_version).map_err(|_| ApplicationError::Internal)?;
        let context = issuer_secret_context(
            self.store.installation_id(),
            issuer_id,
            material_id,
            owner_generation,
            u64::try_from(secret_version).map_err(|_| ApplicationError::Internal)?,
            self.secrets.write_pair(),
        )?;
        let envelope = self
            .secrets
            .seal(&context, &plaintext)
            .await
            .map_err(|_| ApplicationError::DependencyUnavailable)?;

        let mut transaction = self.store.begin().await?;
        let current = sqlx::query(
            "SELECT browser_login, policy_version FROM external_identity_issuers
             WHERE id=$1 FOR UPDATE",
        )
        .bind(issuer_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        require_protected_browser_client(&current)?;
        if current.try_get::<i64, _>("policy_version")? != captured_policy_version {
            return Err(ApplicationError::Conflict(
                "issuer changed while the browser client secret was being protected".to_owned(),
            ));
        }
        sqlx::query(
            "INSERT INTO protected_secret_versions(
                id, scope_kind, owner_kind, owner_id, owner_generation, secret_version,
                field_purpose, custody_provider_id, provider_format_version,
                context_version, opaque_envelope
             ) VALUES ($1,'system','identity_issuer',$2,$3,$4,'oidc_client_secret',$5,$6,1,$7)",
        )
        .bind(material_id)
        .bind(issuer_id.as_uuid())
        .bind(i64::try_from(owner_generation).map_err(|_| ApplicationError::Internal)?)
        .bind(secret_version)
        .bind(context.parts().provider_id.as_str())
        .bind(
            i32::try_from(context.parts().provider_format_version.get())
                .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(envelope.expose(<[u8]>::to_vec))
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "DELETE FROM protected_secret_versions
             WHERE owner_kind='identity_issuer' AND owner_id=$1
               AND field_purpose='oidc_client_secret' AND id<>$2",
        )
        .bind(issuer_id.as_uuid())
        .bind(material_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE external_identity_issuers
             SET policy_version=policy_version+1, etag_token=$2, updated_at=now()
             WHERE id=$1",
        )
        .bind(issuer_id.as_uuid())
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        self.store
            .commit_command(
                transaction,
                &AuditRecord {
                    actor: Some(Actor::from(&identity.principal)),
                    authentication_evidence: json!({"method":identity.principal.authentication_method}),
                    organization_id: None,
                    target_resource_kind: "external_identity_issuer".to_owned(),
                    target_resource_id: Some(issuer_id.to_string()),
                    operation_id: "identity_issuers.browser_login.replace_client_secret".to_owned(),
                    outcome: "accepted",
                    request_id: identity.request_id.clone(),
                    changed_fields: vec!["browser_login.client_secret".to_owned()],
                    safe_details: json!({}),
                },
                Some(&RuntimeEvent {
                    event_kind: "external_identity_issuer.secret_changed".to_owned(),
                    affected_scope: json!({"issuer_id":issuer_id}),
                    security_tightening: true,
                }),
            )
            .await?;
        self.publish_committed_runtime(
            &identity.request_id,
            "identity_issuers.browser_login.replace_client_secret",
        )
        .await;
        Ok(())
    }

    pub async fn validate_browser_login(
        &self,
        identity: &RequestIdentity,
        issuer_id: IssuerId,
    ) -> Result<BrowserLoginValidation, ApplicationError> {
        self.authorize(
            identity,
            &[
                ManagementScope::Write,
                ManagementScope::Secrets,
                ManagementScope::Authority,
            ],
            AuthorizationTarget::System {
                capability: Capability::ManageIdentity,
            },
        )?;
        let row =
            sqlx::query("SELECT name, browser_login FROM external_identity_issuers WHERE id=$1")
                .bind(issuer_id.as_uuid())
                .fetch_optional(self.store.pool())
                .await?
                .ok_or(ApplicationError::NotFound)?;
        let issuer_name: String = row.try_get("name")?;
        let profile = serde_json::from_value::<crate::domain::BrowserLoginProfile>(
            row.try_get::<Option<Value>, _>("browser_login")?
                .ok_or_else(|| {
                    ApplicationError::Conflict("browser login is not configured".to_owned())
                })?,
        )
        .map_err(|_| ApplicationError::Internal)?;

        let redirect_uri = self.issuer_callback_uri(&issuer_name)?;
        let mut verifier_bytes = [0_u8; 32];
        rand::rng().fill_bytes(&mut verifier_bytes);
        let mut verifier = Zeroizing::new(URL_SAFE_NO_PAD.encode(verifier_bytes));
        verifier_bytes.zeroize();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let probe_id = Uuid::now_v7().to_string();
        let scopes = profile.scopes.iter().cloned().collect::<Vec<_>>().join(" ");

        let authorization_http = self
            .identity_http_client(&profile.authorization_endpoint)
            .await?;
        let mut authorization_url = profile.authorization_endpoint.clone();
        authorization_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &profile.client_id)
            .append_pair("redirect_uri", redirect_uri.as_str())
            .append_pair("scope", &scopes)
            .append_pair("state", &probe_id)
            .append_pair("nonce", &probe_id)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        let authorization_response = authorization_http
            .get(authorization_url)
            .send()
            .await
            .map_err(|_| ApplicationError::DependencyUnavailable)?;
        let authorization_status = authorization_response.status();
        let _ = read_bounded_response(authorization_response, MAX_TOKEN_RESPONSE_BYTES).await?;
        if authorization_status.is_server_error() {
            return Err(ApplicationError::DependencyUnavailable);
        }

        let mut form = BTreeMap::from([
            ("grant_type", "authorization_code".to_owned()),
            ("code", format!("owlrora-validation-{probe_id}")),
            ("redirect_uri", redirect_uri.to_string()),
            ("client_id", profile.client_id.clone()),
            ("code_verifier", verifier.to_string()),
        ]);
        if profile.client_authentication == BrowserClientAuthentication::ProtectedClientSecret {
            form.insert(
                "client_secret",
                self.open_browser_client_secret(issuer_id)
                    .await?
                    .to_string(),
            );
        }
        let token_http = self.identity_http_client(&profile.token_endpoint).await?;
        let token_request = token_http
            .post(profile.token_endpoint.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&form);
        for value in form.values_mut() {
            value.zeroize();
        }
        verifier.zeroize();
        let token_response = token_request
            .send()
            .await
            .map_err(|_| ApplicationError::DependencyUnavailable)?;
        let token_status = token_response.status();
        let token_body = read_bounded_response(token_response, MAX_TOKEN_RESPONSE_BYTES).await?;
        if token_status.is_server_error() {
            return Err(ApplicationError::DependencyUnavailable);
        }
        let oauth_error = serde_json::from_slice::<Value>(&token_body)
            .ok()
            .and_then(|body| body.get("error")?.as_str().map(str::to_owned));
        let client_accepted = match oauth_error.as_deref() {
            Some("invalid_client" | "unauthorized_client") => Some(false),
            Some("invalid_grant") => Some(true),
            _ if token_status.is_success() => Some(true),
            _ if token_status == reqwest::StatusCode::UNAUTHORIZED => Some(false),
            _ => None,
        };
        let result = BrowserLoginValidation {
            authorization_endpoint_status: authorization_status.as_u16(),
            token_endpoint_status: token_status.as_u16(),
            client_accepted,
            validated_at: Utc::now(),
        };
        let transaction = self.store.begin().await?;
        self.store
            .commit_command(
                transaction,
                &AuditRecord {
                    actor: Some(Actor::from(&identity.principal)),
                    authentication_evidence: json!({"method":identity.principal.authentication_method}),
                    organization_id: None,
                    target_resource_kind: "external_identity_issuer".to_owned(),
                    target_resource_id: Some(issuer_id.to_string()),
                    operation_id: "identity_issuers.browser_login.validate".to_owned(),
                    outcome: "accepted",
                    request_id: identity.request_id.clone(),
                    changed_fields: Vec::new(),
                    safe_details: json!({
                        "authorization_endpoint_status": result.authorization_endpoint_status,
                        "token_endpoint_status": result.token_endpoint_status,
                        "client_accepted": result.client_accepted,
                    }),
                },
                None,
            )
            .await?;
        Ok(result)
    }

    pub(crate) async fn cleanup_expired_oidc_login_states(&self) -> Result<u64, ApplicationError> {
        const BATCH_SIZE: u64 = 500;
        let mut total = 0_u64;
        loop {
            let deleted = sqlx::query(
                "DELETE FROM oidc_login_states
                 WHERE id IN (
                     SELECT state.id
                     FROM oidc_login_states state
                     JOIN (
                         (SELECT id FROM oidc_login_states WHERE expires_at < now()
                          ORDER BY expires_at, id LIMIT 500)
                         UNION
                         (SELECT id FROM oidc_login_states
                          WHERE consumed_at < now()-interval '1 hour'
                          ORDER BY consumed_at, id LIMIT 500)
                     ) candidate USING (id)
                     ORDER BY state.expires_at, state.id
                     LIMIT 500 FOR UPDATE OF state SKIP LOCKED
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

    async fn open_browser_client_secret(
        &self,
        issuer_id: IssuerId,
    ) -> Result<Zeroizing<String>, ApplicationError> {
        let row = sqlx::query(
            "SELECT id,owner_generation,secret_version,opaque_envelope,custody_provider_id,
                    provider_format_version,context_version
             FROM protected_secret_versions
             WHERE owner_kind='identity_issuer' AND owner_id=$1
               AND field_purpose='oidc_client_secret'
             ORDER BY secret_version DESC LIMIT 1",
        )
        .bind(issuer_id.as_uuid())
        .fetch_optional(self.store.pool())
        .await?
        .ok_or_else(|| {
            ApplicationError::Conflict("browser client secret is not configured".to_owned())
        })?;
        let material_id: Uuid = row.try_get("id")?;
        if row.try_get::<i32, _>("context_version")? != 1 {
            return Err(ApplicationError::Internal);
        }
        let pair = crate::secrets::CustodyPair::new(
            ProviderId::new(row.try_get::<String, _>("custody_provider_id")?)
                .map_err(|_| ApplicationError::Internal)?,
            ProviderFormatVersion::new(
                u32::try_from(row.try_get::<i32, _>("provider_format_version")?)
                    .map_err(|_| ApplicationError::Internal)?,
            )
            .map_err(|_| ApplicationError::Internal)?,
        );
        let context = issuer_secret_context(
            self.store.installation_id(),
            issuer_id,
            material_id,
            u64::try_from(row.try_get::<i64, _>("owner_generation")?)
                .map_err(|_| ApplicationError::Internal)?,
            u64::try_from(row.try_get::<i64, _>("secret_version")?)
                .map_err(|_| ApplicationError::Internal)?,
            &pair,
        )?;
        let envelope = OpaqueEnvelope::new(row.try_get::<Vec<u8>, _>("opaque_envelope")?)
            .map_err(|_| ApplicationError::Internal)?;
        let plaintext = self
            .secrets
            .open(&context, &envelope)
            .await
            .map_err(|_| ApplicationError::DependencyUnavailable)?;
        let secret = plaintext
            .expose(|bytes| String::from_utf8(bytes.to_vec()))
            .map_err(|_| ApplicationError::Internal)?;
        Ok(Zeroizing::new(secret))
    }

    fn issuer_callback_uri(&self, issuer_name: &str) -> Result<Url, ApplicationError> {
        self.config
            .public_origin
            .as_ref()
            .ok_or(ApplicationError::Internal)?
            .join(&format!("auth/v1/issuers/{issuer_name}/callback"))
            .map_err(|_| ApplicationError::Internal)
    }
}

fn oidc_audience_matches(claims: &Value, client_id: &str) -> bool {
    let audiences = match claims.get("aud") {
        Some(Value::String(value)) => vec![value.as_str()],
        Some(Value::Array(values)) => {
            let Some(audiences) = values.iter().map(Value::as_str).collect::<Option<Vec<_>>>()
            else {
                return false;
            };
            audiences
        }
        _ => return false,
    };
    if audiences.is_empty() || !audiences.contains(&client_id) {
        return false;
    }
    let authorized_party = claims.get("azp").and_then(Value::as_str);
    if audiences.len() > 1 {
        authorized_party == Some(client_id)
    } else {
        authorized_party.is_none_or(|value| value == client_id)
    }
}

fn validate_return_to(value: &str) -> Result<String, ApplicationError> {
    if value.is_empty()
        || value.len() > 1024
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('\n')
        || value.contains('\r')
        || value.contains("\\")
    {
        return Err(ApplicationError::Validation(
            "return_to must be a bounded same-origin console path".to_owned(),
        ));
    }
    let allowed = value == "/"
        || value == "/admin"
        || value.starts_with("/admin/")
        || value == "/profile"
        || value.starts_with("/profile/")
        || value.starts_with("/organizations/");
    if !allowed {
        return Err(ApplicationError::Validation(
            "return_to is outside the console route allowlist".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn generate_random_value() -> String {
    let mut random = [0_u8; 32];
    rand::rng().fill_bytes(&mut random);
    URL_SAFE_NO_PAD.encode(random)
}

fn generate_opaque_value(prefix: &str) -> String {
    format!("{prefix}.{}", generate_random_value())
}

fn parse_opaque_value(
    prefix: &str,
    raw: &str,
    domain: &[u8],
) -> Result<[u8; 32], ApplicationError> {
    let (actual_prefix, encoded) = raw
        .split_once('.')
        .ok_or(ApplicationError::InvalidCredential)?;
    if actual_prefix != prefix || encoded.contains('=') {
        return Err(ApplicationError::InvalidCredential);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ApplicationError::InvalidCredential)?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded) != encoded {
        return Err(ApplicationError::InvalidCredential);
    }
    Ok(digest_nonrecoverable(domain, raw.as_bytes()))
}

fn digest_nonrecoverable(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"owlrora/nonrecoverable/v1\0");
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    digest.update(value);
    digest.finalize().into()
}

fn digest_array(value: Vec<u8>) -> Result<[u8; 32], ApplicationError> {
    value.try_into().map_err(|_| ApplicationError::Internal)
}

fn state_protection_context(
    installation_id: Uuid,
    state_id: Uuid,
    pair: &crate::secrets::CustodyPair,
) -> Result<ProtectionContext, ApplicationError> {
    protection_context(
        installation_id,
        state_id,
        "oidc_login_state",
        state_id,
        1,
        1,
        "pkce_verifier",
        pair,
    )
}

fn issuer_secret_context(
    installation_id: Uuid,
    issuer_id: IssuerId,
    material_id: Uuid,
    owner_generation: u64,
    secret_version: u64,
    pair: &crate::secrets::CustodyPair,
) -> Result<ProtectionContext, ApplicationError> {
    protection_context(
        installation_id,
        material_id,
        "identity_issuer",
        issuer_id.as_uuid(),
        owner_generation,
        secret_version,
        "oidc_client_secret",
        pair,
    )
}

fn protection_context(
    installation_id: Uuid,
    material_id: Uuid,
    owner_kind: &str,
    owner_id: Uuid,
    owner_generation: u64,
    secret_version: u64,
    purpose: &str,
    pair: &crate::secrets::CustodyPair,
) -> Result<ProtectionContext, ApplicationError> {
    ProtectionContext::new(ProtectionContextParts {
        version: ContextVersion::V1,
        installation_id: InstallationId::new(installation_id.to_string())
            .map_err(|_| ApplicationError::Internal)?,
        scope: SecretScope::System,
        material_id: MaterialId::new(material_id.to_string())
            .map_err(|_| ApplicationError::Internal)?,
        owner_kind: OwnerKind::new(owner_kind).map_err(|_| ApplicationError::Internal)?,
        owner_id: OwnerId::new(owner_id.to_string()).map_err(|_| ApplicationError::Internal)?,
        owner_generation,
        secret_version,
        field_purpose: FieldPurpose::new(purpose).map_err(|_| ApplicationError::Internal)?,
        provider_id: pair.provider_id().clone(),
        provider_format_version: pair.format_version(),
    })
    .map_err(|_| ApplicationError::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_paths_are_same_origin_and_console_bounded() {
        assert_eq!(validate_return_to("/admin/users").unwrap(), "/admin/users");
        assert!(validate_return_to("https://evil.example/").is_err());
        assert!(validate_return_to("//evil.example/").is_err());
        assert!(validate_return_to("/api/v1/users").is_err());
    }

    #[test]
    fn oidc_audience_requires_client_and_azp_for_multiple_audiences() {
        assert!(oidc_audience_matches(
            &json!({"aud":"console-client"}),
            "console-client"
        ));
        assert!(oidc_audience_matches(
            &json!({"aud":["api","console-client"],"azp":"console-client"}),
            "console-client"
        ));
        assert!(!oidc_audience_matches(
            &json!({"aud":["api","console-client"]}),
            "console-client"
        ));
        assert!(!oidc_audience_matches(
            &json!({"aud":["api","console-client"],"azp":"other-client"}),
            "console-client"
        ));
    }

    #[test]
    fn oidc_state_values_are_canonical_and_domain_separated() {
        let state = generate_opaque_value(STATE_PREFIX);
        let digest = parse_opaque_value(STATE_PREFIX, &state, b"oidc-state").unwrap();
        assert_ne!(
            digest,
            digest_nonrecoverable(b"oidc-nonce", state.as_bytes())
        );
        assert!(parse_opaque_value(STATE_PREFIX, "invalid", b"oidc-state").is_err());
    }
}
