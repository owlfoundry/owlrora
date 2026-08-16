use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngCore as _;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use sqlx::{Executor, Postgres, Row as _};
use uuid::Uuid;

use crate::{
    adapters::postgres::{AuditRecord, RuntimeEvent},
    domain::{
        Actor, Capability, InvitationId, JwtRouteCeiling, LlmScope, ManagementScope,
        OrganizationId, OrganizationRole, Principal, RouteId, UserId,
    },
};

use super::{
    AcceptInvitation, Application, ApplicationError, AuthorizationTarget, CreateInvitation,
    Invitation, OneTimeInvitation, Page, RequestIdentity,
};

const INVITATION_PREFIX: &str = "owlrora_invitation_v1";

impl Application {
    pub async fn list_invitations(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<Invitation>, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read],
            AuthorizationTarget::Organization {
                organization_id,
                capability: Capability::ReadMembers,
            },
        )?;
        let family = format!("invitations:{organization_id}");
        let (cursor, limit) = super::resources::page_parameters(&family, cursor, limit)?;
        let rows = sqlx::query(
            "SELECT id, organization_id, intended_email, intended_role, llm_scope_ceiling,
                    llm_capability_ceiling, llm_route_ceiling,
                    state, expires_at, accepted_by_user_id, created_at, updated_at
             FROM invitations
             WHERE organization_id=$1 AND ($2::uuid IS NULL OR id < $2)
             ORDER BY id DESC LIMIT $3",
        )
        .bind(organization_id.as_uuid())
        .bind(cursor)
        .bind(i64::from(limit) + 1)
        .fetch_all(self.store.pool())
        .await?;
        super::resources::page_from_rows(rows, limit, &family, invitation_from_row)
    }

    pub async fn get_invitation(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        invitation_id: InvitationId,
    ) -> Result<Invitation, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read],
            AuthorizationTarget::Organization {
                organization_id,
                capability: Capability::ReadMembers,
            },
        )?;
        load_invitation(self.store.pool(), organization_id, invitation_id).await
    }

    pub async fn create_invitation(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        input: CreateInvitation,
    ) -> Result<OneTimeInvitation, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Write, ManagementScope::Secrets],
            AuthorizationTarget::Organization {
                organization_id,
                capability: if input.intended_role == OrganizationRole::Owner {
                    Capability::ManageOwners
                } else {
                    Capability::ManageMembers
                },
            },
        )?;
        if input.expires_at <= Utc::now()
            || input.expires_at > Utc::now() + chrono::Duration::days(30)
        {
            return Err(ApplicationError::Validation(
                "invitation expiry must be within the next 30 days".to_owned(),
            ));
        }
        if input
            .intended_email
            .as_ref()
            .is_some_and(|email| email.len() > 320 || !email.contains('@'))
        {
            return Err(ApplicationError::Validation(
                "intended_email is invalid".to_owned(),
            ));
        }
        validate_llm_scopes(&input.llm_scope_ceiling)?;
        validate_route_ceiling(&input.llm_route_ceiling)?;
        let (token, digest) = generate_invitation_token();
        let invitation_id = InvitationId::new();
        let mut transaction = self.store.begin().await?;
        let status = sqlx::query_scalar::<_, String>(
            "SELECT status FROM organizations WHERE id=$1 FOR UPDATE",
        )
        .bind(organization_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        if status != "active" {
            return Err(ApplicationError::Conflict(
                "organization is not active".to_owned(),
            ));
        }
        sqlx::query(
            "INSERT INTO invitations(
                id, organization_id, intended_email, intended_role, llm_scope_ceiling,
                llm_capability_ceiling, llm_route_ceiling,
                token_digest, state, expires_at, created_by_principal, etag_token
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,$10,$11)",
        )
        .bind(invitation_id.as_uuid())
        .bind(organization_id.as_uuid())
        .bind(input.intended_email.as_deref())
        .bind(role_str(input.intended_role))
        .bind(
            serde_json::to_value(&input.llm_scope_ceiling)
                .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(
            serde_json::to_value(&input.llm_capability_ceiling)
                .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(
            serde_json::to_value(&input.llm_route_ceiling)
                .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(digest.to_vec())
        .bind(input.expires_at)
        .bind(
            serde_json::to_value(Actor::from(&identity.principal))
                .map_err(|_| ApplicationError::Internal)?,
        )
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let invitation = load_invitation(&mut *transaction, organization_id, invitation_id).await?;
        self.store
            .commit_command(
                transaction,
                &invitation_audit(
                    identity,
                    organization_id,
                    invitation_id,
                    "organizations.invitations.create",
                    &[
                        "intended_role",
                        "llm_scope_ceiling",
                        "llm_capability_ceiling",
                        "llm_route_ceiling",
                        "expires_at",
                    ],
                ),
                Some(&RuntimeEvent {
                    event_kind: "invitation.changed".to_owned(),
                    affected_scope: json!({"organization_id":organization_id,"invitation_id":invitation_id}),
                    security_tightening: false,
                }),
            )
            .await?;
        Ok(OneTimeInvitation { invitation, token })
    }

    pub async fn resend_invitation(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        invitation_id: InvitationId,
    ) -> Result<OneTimeInvitation, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Write, ManagementScope::Secrets],
            AuthorizationTarget::Organization {
                organization_id,
                capability: Capability::ManageMembers,
            },
        )?;
        let (token, digest) = generate_invitation_token();
        let mut transaction = self.store.begin().await?;
        let row = sqlx::query(
            "SELECT state, expires_at, intended_role FROM invitations
             WHERE organization_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(organization_id.as_uuid())
        .bind(invitation_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        if row.try_get::<String, _>("state")? != "pending"
            || row.try_get::<chrono::DateTime<Utc>, _>("expires_at")? <= Utc::now()
        {
            return Err(ApplicationError::Conflict(
                "only an unexpired pending invitation can be resent".to_owned(),
            ));
        }
        if row.try_get::<String, _>("intended_role")? == "owner" {
            self.authorize(
                identity,
                &[ManagementScope::Write, ManagementScope::Secrets],
                AuthorizationTarget::Organization {
                    organization_id,
                    capability: Capability::ManageOwners,
                },
            )?;
        }
        sqlx::query(
            "UPDATE invitations SET token_digest=$3, updated_at=now(), etag_token=$4
             WHERE organization_id=$1 AND id=$2",
        )
        .bind(organization_id.as_uuid())
        .bind(invitation_id.as_uuid())
        .bind(digest.to_vec())
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let invitation = load_invitation(&mut *transaction, organization_id, invitation_id).await?;
        self.store
            .commit_command(
                transaction,
                &invitation_audit(
                    identity,
                    organization_id,
                    invitation_id,
                    "organizations.invitations.resend",
                    &["token_digest"],
                ),
                None,
            )
            .await?;
        Ok(OneTimeInvitation { invitation, token })
    }

    pub async fn revoke_invitation(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        invitation_id: InvitationId,
    ) -> Result<(), ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Write],
            AuthorizationTarget::Organization {
                organization_id,
                capability: Capability::ManageMembers,
            },
        )?;
        let mut transaction = self.store.begin().await?;
        let changed = sqlx::query(
            "UPDATE invitations SET state='revoked', revoked_at=now(), updated_at=now(),
                    etag_token=$3
             WHERE organization_id=$1 AND id=$2 AND state='pending'",
        )
        .bind(organization_id.as_uuid())
        .bind(invitation_id.as_uuid())
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed == 0 {
            return Err(ApplicationError::NotFound);
        }
        self.store
            .commit_command(
                transaction,
                &invitation_audit(
                    identity,
                    organization_id,
                    invitation_id,
                    "organizations.invitations.revoke",
                    &["state"],
                ),
                None,
            )
            .await?;
        Ok(())
    }

    pub async fn accept_invitation(
        &self,
        identity: &RequestIdentity,
        input: AcceptInvitation,
    ) -> Result<Invitation, ApplicationError> {
        let user_id = match identity.principal.principal {
            Principal::LocalUser { user_id } => user_id,
            _ => return Err(ApplicationError::Forbidden),
        };
        self.authorize(
            identity,
            &[ManagementScope::Write],
            AuthorizationTarget::CurrentPrincipal,
        )?;
        let digest = parse_invitation_token(&input.token)?;
        let mut transaction = self.store.begin().await?;
        let row = sqlx::query(
            "SELECT id, organization_id, intended_role, llm_scope_ceiling,
                    llm_capability_ceiling, llm_route_ceiling, state, expires_at
             FROM invitations WHERE token_digest=$1 FOR UPDATE",
        )
        .bind(digest.to_vec())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::InvalidCredential)?;
        if row.try_get::<String, _>("state")? != "pending"
            || row.try_get::<chrono::DateTime<Utc>, _>("expires_at")? <= Utc::now()
        {
            return Err(ApplicationError::Conflict(
                "invitation is no longer active".to_owned(),
            ));
        }
        let invitation_id = InvitationId::from_uuid(row.try_get("id")?);
        let organization_id = OrganizationId::from_uuid(row.try_get("organization_id")?);
        sqlx::query("SELECT id FROM organizations WHERE id=$1 AND status='active' FOR UPDATE")
            .bind(organization_id.as_uuid())
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(ApplicationError::Conflict(
                "organization is not active".to_owned(),
            ))?;
        let role: String = row.try_get("intended_role")?;
        let scopes: serde_json::Value = row.try_get("llm_scope_ceiling")?;
        let llm_capabilities: serde_json::Value = row.try_get("llm_capability_ceiling")?;
        let llm_routes: serde_json::Value = row.try_get("llm_route_ceiling")?;
        sqlx::query(
            "INSERT INTO memberships(
                id, organization_id, user_id, role, status, llm_scope_ceiling,
                llm_capability_ceiling, llm_route_ceiling, etag_token, created_by_principal
             ) VALUES ($1,$2,$3,$4,'active',$5,$6,$7,$8,$9)",
        )
        .bind(Uuid::now_v7())
        .bind(organization_id.as_uuid())
        .bind(user_id.as_uuid())
        .bind(role)
        .bind(scopes)
        .bind(llm_capabilities)
        .bind(llm_routes)
        .bind(Uuid::now_v7())
        .bind(
            serde_json::to_value(Actor::from(&identity.principal))
                .map_err(|_| ApplicationError::Internal)?,
        )
        .execute(&mut *transaction)
        .await
        .map_err(|error| {
            if error.as_database_error().is_some() {
                ApplicationError::Conflict("user is already an active member".to_owned())
            } else {
                error.into()
            }
        })?;
        sqlx::query(
            "UPDATE invitations SET state='accepted', accepted_by_user_id=$3,
                    accepted_at=now(), updated_at=now(), etag_token=$4
             WHERE organization_id=$1 AND id=$2",
        )
        .bind(organization_id.as_uuid())
        .bind(invitation_id.as_uuid())
        .bind(user_id.as_uuid())
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let invitation = load_invitation(&mut *transaction, organization_id, invitation_id).await?;
        self.store
            .commit_command(
                transaction,
                &invitation_audit(
                    identity,
                    organization_id,
                    invitation_id,
                    "invitations.accept",
                    &["state", "accepted_by_user_id", "membership"],
                ),
                Some(&RuntimeEvent {
                    event_kind: "membership.changed".to_owned(),
                    affected_scope: json!({"organization_id":organization_id,"user_id":user_id}),
                    security_tightening: false,
                }),
            )
            .await?;
        self.publish_committed_runtime(&identity.request_id, "invitations.accept")
            .await;
        Ok(invitation)
    }
}

fn generate_invitation_token() -> (String, [u8; 32]) {
    let mut random = [0_u8; 32];
    rand::rng().fill_bytes(&mut random);
    let token = format!("{INVITATION_PREFIX}.{}", URL_SAFE_NO_PAD.encode(random));
    let digest = invitation_digest(&token);
    (token, digest)
}

fn parse_invitation_token(token: &str) -> Result<[u8; 32], ApplicationError> {
    let (prefix, encoded) = token
        .split_once('.')
        .ok_or(ApplicationError::InvalidCredential)?;
    if prefix != INVITATION_PREFIX || encoded.contains('=') {
        return Err(ApplicationError::InvalidCredential);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ApplicationError::InvalidCredential)?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded) != encoded {
        return Err(ApplicationError::InvalidCredential);
    }
    Ok(invitation_digest(token))
}

fn invitation_digest(token: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"owlrora/invitation-token/v1\0");
    digest.update(token.as_bytes());
    digest.finalize().into()
}

async fn load_invitation<'executor>(
    executor: impl Executor<'executor, Database = Postgres>,
    organization_id: OrganizationId,
    invitation_id: InvitationId,
) -> Result<Invitation, ApplicationError> {
    let row = sqlx::query(
        "SELECT id, organization_id, intended_email, intended_role, llm_scope_ceiling,
                llm_capability_ceiling, llm_route_ceiling,
                state, expires_at, accepted_by_user_id, created_at, updated_at
         FROM invitations WHERE organization_id=$1 AND id=$2",
    )
    .bind(organization_id.as_uuid())
    .bind(invitation_id.as_uuid())
    .fetch_optional(executor)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    invitation_from_row(row)
}

fn invitation_from_row(row: sqlx::postgres::PgRow) -> Result<Invitation, ApplicationError> {
    Ok(Invitation {
        id: InvitationId::from_uuid(row.try_get("id")?),
        organization_id: OrganizationId::from_uuid(row.try_get("organization_id")?),
        intended_email: row.try_get("intended_email")?,
        intended_role: parse_role(&row.try_get::<String, _>("intended_role")?)?,
        llm_scope_ceiling: serde_json::from_value(row.try_get("llm_scope_ceiling")?)
            .map_err(|_| ApplicationError::Internal)?,
        llm_capability_ceiling: serde_json::from_value(row.try_get("llm_capability_ceiling")?)
            .map_err(|_| ApplicationError::Internal)?,
        llm_route_ceiling: serde_json::from_value(row.try_get("llm_route_ceiling")?)
            .map_err(|_| ApplicationError::Internal)?,
        state: row.try_get("state")?,
        expires_at: row.try_get("expires_at")?,
        accepted_by_user_id: row
            .try_get::<Option<Uuid>, _>("accepted_by_user_id")?
            .map(UserId::from_uuid),
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn invitation_audit(
    identity: &RequestIdentity,
    organization_id: OrganizationId,
    invitation_id: InvitationId,
    operation_id: &str,
    changed_fields: &[&str],
) -> AuditRecord {
    AuditRecord {
        actor: Some(Actor::from(&identity.principal)),
        authentication_evidence: json!({"method":identity.principal.authentication_method}),
        organization_id: Some(organization_id),
        target_resource_kind: "invitation".to_owned(),
        target_resource_id: Some(invitation_id.to_string()),
        operation_id: operation_id.to_owned(),
        outcome: "accepted",
        request_id: identity.request_id.clone(),
        changed_fields: changed_fields
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        safe_details: json!({}),
    }
}

fn parse_role(value: &str) -> Result<OrganizationRole, ApplicationError> {
    match value {
        "owner" => Ok(OrganizationRole::Owner),
        "admin" => Ok(OrganizationRole::Admin),
        "member" => Ok(OrganizationRole::Member),
        _ => Err(ApplicationError::Internal),
    }
}

const fn role_str(role: OrganizationRole) -> &'static str {
    match role {
        OrganizationRole::Owner => "owner",
        OrganizationRole::Admin => "admin",
        OrganizationRole::Member => "member",
    }
}

fn validate_llm_scopes(scopes: &[String]) -> Result<(), ApplicationError> {
    let parsed = scopes
        .iter()
        .map(|scope| scope.parse::<LlmScope>())
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| {
            ApplicationError::Validation("llm_scope_ceiling contains an unknown scope".to_owned())
        })?;
    if parsed.len() != scopes.len() {
        return Err(ApplicationError::Validation(
            "llm_scope_ceiling contains duplicate scopes".to_owned(),
        ));
    }
    if !parsed.is_empty() && !parsed.contains(&LlmScope::Invoke) {
        return Err(ApplicationError::Validation(
            "a non-empty llm_scope_ceiling must contain llm:invoke".to_owned(),
        ));
    }
    Ok(())
}

fn validate_route_ceiling(ceiling: &JwtRouteCeiling) -> Result<(), ApplicationError> {
    if let JwtRouteCeiling::Routes { route_ids } = ceiling
        && (route_ids.is_empty()
            || route_ids
                .iter()
                .any(|route_id| route_id.parse::<RouteId>().is_err()))
    {
        return Err(ApplicationError::Validation(
            "an exact route ceiling must contain valid route IDs; use kind=none to deny".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitation_tokens_are_canonical_digest_only_values() {
        let (token, digest) = generate_invitation_token();
        assert_eq!(parse_invitation_token(&token).unwrap(), digest);
        assert!(parse_invitation_token("owlrora_invitation_v1.AA=").is_err());
    }

    #[test]
    fn invitation_llm_ceilings_reject_incomplete_or_empty_exact_values() {
        assert!(validate_llm_scopes(&[]).is_ok());
        assert!(validate_llm_scopes(&["llm:stream".to_owned()]).is_err());
        assert!(
            validate_route_ceiling(&JwtRouteCeiling::Routes {
                route_ids: BTreeSet::new(),
            })
            .is_err()
        );
        assert!(validate_route_ceiling(&JwtRouteCeiling::None).is_ok());
    }
}
