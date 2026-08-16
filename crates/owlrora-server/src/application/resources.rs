use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::{
    adapters::postgres::{AuditRecord, RuntimeEvent},
    domain::{
        Actor, Capability, JwtRouteCeiling, LlmFeatureCapability, LlmScope, ManagementScope,
        OrganizationId, OrganizationRole, ResourceScope, RouteId, UserId,
    },
};

use super::{
    Application, ApplicationError, AuthorizationTarget, CreateMembership, CreateOrganization,
    CreateUser, EntityTag, IdempotencyDecision, IdempotentCommand, Membership, Organization,
    OrganizationKind, OrganizationStatus, Page, RequestIdentity, UpdateField, UpdateMembership,
    UpdateOrganization, UpdateUser, User, UserKind, UserStatus,
};

const DEFAULT_LIMIT: u32 = 50;
const MAX_LIMIT: u32 = 100;

impl Application {
    pub async fn list_users(
        &self,
        identity: &RequestIdentity,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<User>, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read],
            AuthorizationTarget::System {
                capability: Capability::ManageSystemUsers,
            },
        )?;
        let (cursor, limit) = page_parameters("users", cursor, limit)?;
        let rows = sqlx::query(
            "SELECT id, kind, status, display_name, primary_email, created_by_principal,
                    created_at, updated_at
             FROM users WHERE ($1::uuid IS NULL OR id < $1)
             ORDER BY id DESC LIMIT $2",
        )
        .bind(cursor)
        .bind(i64::from(limit) + 1)
        .fetch_all(self.store.pool())
        .await?;
        page_from_rows(rows, limit, "users", user_from_row)
    }

    pub async fn get_user(
        &self,
        identity: &RequestIdentity,
        user_id: UserId,
    ) -> Result<(User, EntityTag), ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read],
            AuthorizationTarget::System {
                capability: Capability::ManageSystemUsers,
            },
        )?;
        load_user(self.store.pool(), user_id).await
    }

    pub async fn create_user(
        &self,
        identity: &RequestIdentity,
        input: CreateUser,
        idempotency_key: Option<&str>,
    ) -> Result<IdempotentCommand<(User, EntityTag)>, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Write],
            AuthorizationTarget::System {
                capability: Capability::ManageSystemUsers,
            },
        )?;
        validate_display_name(&input.display_name)?;
        validate_email(input.primary_email.as_deref())?;
        let id = UserId::new();
        let token = Uuid::now_v7();
        let actor_value = serde_json::to_value(Actor::from(&identity.principal))
            .map_err(|_| ApplicationError::Internal)?;
        let mut transaction = self.store.begin().await?;
        let handle = match self
            .begin_idempotent_command(
                &mut transaction,
                identity,
                &ResourceScope::Deployment,
                "system.users.create",
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
            "INSERT INTO users(
                id, kind, status, display_name, primary_email, created_by_principal, etag_token
             ) VALUES ($1,$2,'active',$3,$4,$5,$6)",
        )
        .bind(id.as_uuid())
        .bind(input.kind.as_str())
        .bind(input.display_name.trim())
        .bind(input.primary_email.as_deref().map(str::trim))
        .bind(actor_value)
        .bind(token)
        .execute(&mut *transaction)
        .await?;
        let result = load_user(&mut *transaction, id).await?;
        self.complete_idempotent_command(
            &mut transaction,
            handle,
            200,
            &result.0,
            Some(result.1.as_str()),
        )
        .await?;
        self.store
            .commit_command(
                transaction,
                &command_audit(
                    identity,
                    None,
                    "user",
                    id.to_string(),
                    "system.users.create",
                    &["kind", "status", "display_name", "primary_email"],
                ),
                Some(&runtime_event(
                    "user.changed",
                    json!({"user_id": id}),
                    false,
                )),
            )
            .await?;
        Ok(IdempotentCommand::Executed(result))
    }

    pub async fn update_user(
        &self,
        identity: &RequestIdentity,
        user_id: UserId,
        if_match: Option<&str>,
        input: UpdateUser,
    ) -> Result<(User, EntityTag), ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Write],
            AuthorizationTarget::System {
                capability: Capability::ManageSystemUsers,
            },
        )?;
        require_nonempty_update([
            input.display_name.is_omitted(),
            input.primary_email.is_omitted(),
            input.status.is_omitted(),
        ])?;
        let mut transaction = self.store.begin().await?;
        let row = sqlx::query(
            "SELECT display_name, primary_email, status, etag_token
             FROM users WHERE id = $1 FOR UPDATE",
        )
        .bind(user_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        let current_tag =
            EntityTag::for_resource("user", user_id.as_uuid(), row.try_get("etag_token")?);
        require_etag(if_match, &current_tag)?;
        let mut display_name: String = row.try_get("display_name")?;
        let mut primary_email: Option<String> = row.try_get("primary_email")?;
        let mut status: String = row.try_get("status")?;
        let mut changed = Vec::new();
        match input.display_name {
            UpdateField::Omitted => {}
            UpdateField::Null => {
                return Err(ApplicationError::Validation(
                    "display_name cannot be null".to_owned(),
                ));
            }
            UpdateField::Value(value) => {
                validate_display_name(&value)?;
                display_name = value.trim().to_owned();
                changed.push("display_name");
            }
        }
        match input.primary_email {
            UpdateField::Omitted => {}
            UpdateField::Null => {
                primary_email = None;
                changed.push("primary_email");
            }
            UpdateField::Value(value) => {
                validate_email(Some(&value))?;
                primary_email = Some(value.trim().to_owned());
                changed.push("primary_email");
            }
        }
        match input.status {
            UpdateField::Omitted => {}
            UpdateField::Null => {
                return Err(ApplicationError::Validation(
                    "status cannot be null".to_owned(),
                ));
            }
            UpdateField::Value(value) => {
                status = value.as_str().to_owned();
                changed.push("status");
            }
        }
        let security_tightening = status == "disabled";
        sqlx::query(
            "UPDATE users SET display_name=$2, primary_email=$3, status=$4,
                    etag_token=$5, updated_at=now() WHERE id=$1",
        )
        .bind(user_id.as_uuid())
        .bind(display_name)
        .bind(primary_email)
        .bind(status)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        if security_tightening {
            let principal_id = user_id.to_string();
            sqlx::query(
                "UPDATE web_sessions SET status='revoked', revoked_at=now()
                 WHERE status='active' AND principal->>'kind'='local_user'
                   AND principal->>'user_id'=$1",
            )
            .bind(principal_id)
            .execute(&mut *transaction)
            .await?;
        }
        let result = load_user(&mut *transaction, user_id).await?;
        self.store
            .commit_command(
                transaction,
                &command_audit(
                    identity,
                    None,
                    "user",
                    user_id.to_string(),
                    "system.users.update",
                    &changed,
                ),
                Some(&runtime_event(
                    "user.changed",
                    json!({"user_id": user_id}),
                    security_tightening,
                )),
            )
            .await?;
        Ok(result)
    }

    pub async fn list_system_organizations(
        &self,
        identity: &RequestIdentity,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<Organization>, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read],
            AuthorizationTarget::System {
                capability: Capability::ManageSystemOrganizations,
            },
        )?;
        let (cursor, limit) = page_parameters("organizations", cursor, limit)?;
        let rows = sqlx::query(
            "SELECT id, kind, status, name, slug, created_by_principal,
                    created_at, updated_at
             FROM organizations WHERE ($1::uuid IS NULL OR id < $1)
             ORDER BY id DESC LIMIT $2",
        )
        .bind(cursor)
        .bind(i64::from(limit) + 1)
        .fetch_all(self.store.pool())
        .await?;
        page_from_rows(rows, limit, "organizations", organization_from_row)
    }

    pub async fn get_organization(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        system_path: bool,
    ) -> Result<(Organization, EntityTag), ApplicationError> {
        let target = if system_path {
            AuthorizationTarget::System {
                capability: Capability::ManageSystemOrganizations,
            }
        } else {
            AuthorizationTarget::Organization {
                organization_id,
                capability: Capability::ReadOrganization,
            }
        };
        self.authorize(identity, &[ManagementScope::Read], target)?;
        load_organization(self.store.pool(), organization_id).await
    }

    pub async fn create_organization(
        &self,
        identity: &RequestIdentity,
        input: CreateOrganization,
        idempotency_key: Option<&str>,
    ) -> Result<IdempotentCommand<(Organization, EntityTag)>, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Write],
            AuthorizationTarget::System {
                capability: Capability::ManageSystemOrganizations,
            },
        )?;
        validate_display_name(&input.name)?;
        validate_slug(input.slug.as_deref())?;
        let organization_id = OrganizationId::new();
        let membership_id = Uuid::now_v7();
        let actor_value = serde_json::to_value(Actor::from(&identity.principal))
            .map_err(|_| ApplicationError::Internal)?;
        let mut transaction = self.store.begin().await?;
        let handle = match self
            .begin_idempotent_command(
                &mut transaction,
                identity,
                &ResourceScope::Deployment,
                "system.organizations.create",
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
        let owner_status =
            sqlx::query_scalar::<_, String>("SELECT status FROM users WHERE id=$1 FOR SHARE")
                .bind(input.initial_owner_user_id.as_uuid())
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(ApplicationError::Validation(
                    "initial owner does not exist".to_owned(),
                ))?;
        if owner_status != "active" {
            return Err(ApplicationError::Validation(
                "initial owner must be active".to_owned(),
            ));
        }
        sqlx::query(
            "INSERT INTO organizations(
                id, kind, status, name, slug, created_by_principal, etag_token
             ) VALUES ($1,$2,'active',$3,$4,$5,$6)",
        )
        .bind(organization_id.as_uuid())
        .bind(input.kind.as_str())
        .bind(input.name.trim())
        .bind(input.slug.as_deref())
        .bind(&actor_value)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_conflict)?;
        sqlx::query(
            "INSERT INTO memberships(
                id, organization_id, user_id, role, status, llm_scope_ceiling,
                etag_token, created_by_principal
             ) VALUES ($1,$2,$3,'owner','active','[]'::jsonb,$4,$5)",
        )
        .bind(membership_id)
        .bind(organization_id.as_uuid())
        .bind(input.initial_owner_user_id.as_uuid())
        .bind(Uuid::now_v7())
        .bind(&actor_value)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO organization_api_key_policies(organization_id, policy, etag_token)
             VALUES ($1,$2,$3)",
        )
        .bind(organization_id.as_uuid())
        .bind(default_organization_api_key_policy())
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let result = load_organization(&mut *transaction, organization_id).await?;
        self.complete_idempotent_command(
            &mut transaction,
            handle,
            200,
            &result.0,
            Some(result.1.as_str()),
        )
        .await?;
        self.store
            .commit_command(
                transaction,
                &command_audit(
                    identity,
                    Some(organization_id),
                    "organization",
                    organization_id.to_string(),
                    "system.organizations.create",
                    &["kind", "status", "name", "slug", "initial_owner"],
                ),
                Some(&runtime_event(
                    "organization.changed",
                    json!({"organization_id": organization_id}),
                    false,
                )),
            )
            .await?;
        Ok(IdempotentCommand::Executed(result))
    }

    pub async fn update_organization(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        system_path: bool,
        if_match: Option<&str>,
        input: UpdateOrganization,
    ) -> Result<(Organization, EntityTag), ApplicationError> {
        let target = if system_path {
            AuthorizationTarget::System {
                capability: Capability::ManageSystemOrganizations,
            }
        } else {
            AuthorizationTarget::Organization {
                organization_id,
                capability: Capability::UpdateOrganization,
            }
        };
        self.authorize(identity, &[ManagementScope::Write], target)?;
        require_nonempty_update([
            input.name.is_omitted(),
            input.slug.is_omitted(),
            input.status.is_omitted(),
        ])?;
        if !system_path && !input.status.is_omitted() {
            return Err(ApplicationError::Forbidden);
        }
        let mut transaction = self.store.begin().await?;
        let row = sqlx::query(
            "SELECT name, slug, status, etag_token FROM organizations WHERE id=$1 FOR UPDATE",
        )
        .bind(organization_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        let current_tag = EntityTag::for_resource(
            "organization",
            organization_id.as_uuid(),
            row.try_get("etag_token")?,
        );
        require_etag(if_match, &current_tag)?;
        let mut name: String = row.try_get("name")?;
        let mut slug: Option<String> = row.try_get("slug")?;
        let mut status: String = row.try_get("status")?;
        let mut changed = Vec::new();
        match input.name {
            UpdateField::Omitted => {}
            UpdateField::Null => {
                return Err(ApplicationError::Validation(
                    "name cannot be null".to_owned(),
                ));
            }
            UpdateField::Value(value) => {
                validate_display_name(&value)?;
                name = value.trim().to_owned();
                changed.push("name");
            }
        }
        match input.slug {
            UpdateField::Omitted => {}
            UpdateField::Null => {
                slug = None;
                changed.push("slug");
            }
            UpdateField::Value(value) => {
                validate_slug(Some(&value))?;
                slug = Some(value);
                changed.push("slug");
            }
        }
        match input.status {
            UpdateField::Omitted => {}
            UpdateField::Null => {
                return Err(ApplicationError::Validation(
                    "status cannot be null".to_owned(),
                ));
            }
            UpdateField::Value(value) => {
                status = value.as_str().to_owned();
                changed.push("status");
            }
        }
        let security_tightening = status == "suspended";
        sqlx::query(
            "UPDATE organizations SET name=$2, slug=$3, status=$4,
                    etag_token=$5, updated_at=now() WHERE id=$1",
        )
        .bind(organization_id.as_uuid())
        .bind(name)
        .bind(slug)
        .bind(status)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_conflict)?;
        if security_tightening {
            sqlx::query(
                "UPDATE web_sessions SET status='revoked', revoked_at=now()
                 WHERE status='active' AND (
                     (principal->>'kind'='organization_management_api_key'
                      AND principal->>'organization_id'=$1)
                     OR
                     (authentication_method='external_session'
                      AND captured_organization_capabilities ? $1)
                 )",
            )
            .bind(organization_id.to_string())
            .execute(&mut *transaction)
            .await?;
        }
        let result = load_organization(&mut *transaction, organization_id).await?;
        self.store
            .commit_command(
                transaction,
                &command_audit(
                    identity,
                    Some(organization_id),
                    "organization",
                    organization_id.to_string(),
                    if system_path {
                        "system.organizations.update"
                    } else {
                        "organizations.update"
                    },
                    &changed,
                ),
                Some(&runtime_event(
                    "organization.changed",
                    json!({"organization_id": organization_id}),
                    security_tightening,
                )),
            )
            .await?;
        Ok(result)
    }

    pub async fn list_memberships(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Page<Membership>, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read],
            AuthorizationTarget::Organization {
                organization_id,
                capability: Capability::ReadMembers,
            },
        )?;
        let family = format!("memberships:{organization_id}");
        let (cursor, limit) = page_parameters(&family, cursor, limit)?;
        let rows = sqlx::query(
            "SELECT id, organization_id, user_id, role, status, llm_scope_ceiling,
                    llm_capability_ceiling, llm_route_ceiling, created_at, updated_at
             FROM memberships
             WHERE organization_id=$1 AND ($2::uuid IS NULL OR id < $2)
             ORDER BY id DESC LIMIT $3",
        )
        .bind(organization_id.as_uuid())
        .bind(cursor)
        .bind(i64::from(limit) + 1)
        .fetch_all(self.store.pool())
        .await?;
        page_from_rows(rows, limit, &family, membership_from_row)
    }

    pub async fn get_membership(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        user_id: UserId,
    ) -> Result<(Membership, EntityTag), ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read],
            AuthorizationTarget::Organization {
                organization_id,
                capability: Capability::ReadMembers,
            },
        )?;
        load_membership(self.store.pool(), organization_id, user_id).await
    }

    pub async fn create_membership(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        input: CreateMembership,
        idempotency_key: Option<&str>,
    ) -> Result<IdempotentCommand<(Membership, EntityTag)>, ApplicationError> {
        let capability = if input.role == OrganizationRole::Owner {
            Capability::ManageOwners
        } else {
            Capability::ManageMembers
        };
        self.authorize(
            identity,
            &[ManagementScope::Write],
            AuthorizationTarget::Organization {
                organization_id,
                capability,
            },
        )?;
        validate_llm_scopes(&input.llm_scope_ceiling)?;
        validate_route_ceiling(&input.llm_route_ceiling)?;
        let mut transaction = self.store.begin().await?;
        let handle = match self
            .begin_idempotent_command(
                &mut transaction,
                identity,
                &ResourceScope::Organization { organization_id },
                "organization.memberships.create",
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
        lock_active_organization(&mut transaction, organization_id).await?;
        require_active_user(&mut transaction, input.user_id).await?;
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO memberships(
                id, organization_id, user_id, role, status, llm_scope_ceiling,
                llm_capability_ceiling, llm_route_ceiling, etag_token, created_by_principal
             ) VALUES ($1,$2,$3,$4,'active',$5,$6,$7,$8,$9)",
        )
        .bind(id)
        .bind(organization_id.as_uuid())
        .bind(input.user_id.as_uuid())
        .bind(role_str(input.role))
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
        .bind(Uuid::now_v7())
        .bind(
            serde_json::to_value(Actor::from(&identity.principal))
                .map_err(|_| ApplicationError::Internal)?,
        )
        .execute(&mut *transaction)
        .await
        .map_err(map_database_conflict)?;
        let result = load_membership(&mut *transaction, organization_id, input.user_id).await?;
        self.complete_idempotent_command(
            &mut transaction,
            handle,
            200,
            &result.0,
            Some(result.1.as_str()),
        )
        .await?;
        self.store
            .commit_command(
                transaction,
                &command_audit(
                    identity,
                    Some(organization_id),
                    "membership",
                    id.to_string(),
                    "organizations.members.create",
                    &[
                        "user_id",
                        "role",
                        "llm_scope_ceiling",
                        "llm_capability_ceiling",
                        "llm_route_ceiling",
                    ],
                ),
                Some(&runtime_event(
                    "membership.changed",
                    json!({"organization_id":organization_id,"user_id":input.user_id}),
                    false,
                )),
            )
            .await?;
        Ok(IdempotentCommand::Executed(result))
    }

    pub async fn update_membership(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        user_id: UserId,
        if_match: Option<&str>,
        input: UpdateMembership,
    ) -> Result<(Membership, EntityTag), ApplicationError> {
        require_nonempty_update([
            input.role.is_omitted(),
            input.llm_scope_ceiling.is_omitted(),
            input.llm_capability_ceiling.is_omitted(),
            input.llm_route_ceiling.is_omitted(),
        ])?;
        let mut transaction = self.store.begin().await?;
        lock_active_organization(&mut transaction, organization_id).await?;
        let row = sqlx::query(
            "SELECT id, role, llm_scope_ceiling, llm_capability_ceiling,
                    llm_route_ceiling, etag_token
             FROM memberships
             WHERE organization_id=$1 AND user_id=$2 AND status='active' FOR UPDATE",
        )
        .bind(organization_id.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        let id: Uuid = row.try_get("id")?;
        let current_role = parse_role(&row.try_get::<String, _>("role")?)?;
        let mut role = current_role;
        let mut scopes: Vec<String> = serde_json::from_value(row.try_get("llm_scope_ceiling")?)
            .map_err(|_| ApplicationError::Internal)?;
        let mut llm_capabilities: BTreeSet<LlmFeatureCapability> =
            serde_json::from_value(row.try_get("llm_capability_ceiling")?)
                .map_err(|_| ApplicationError::Internal)?;
        let mut llm_routes: JwtRouteCeiling =
            serde_json::from_value(row.try_get("llm_route_ceiling")?)
                .map_err(|_| ApplicationError::Internal)?;
        validate_llm_scopes(&scopes).map_err(|_| ApplicationError::Internal)?;
        validate_route_ceiling(&llm_routes).map_err(|_| ApplicationError::Internal)?;
        let current_scopes = scopes.clone();
        let current_llm_capabilities = llm_capabilities.clone();
        let current_llm_routes = llm_routes.clone();
        match input.role {
            UpdateField::Omitted => {}
            UpdateField::Null => {
                return Err(ApplicationError::Validation(
                    "role cannot be null".to_owned(),
                ));
            }
            UpdateField::Value(value) => role = value,
        }
        let owner_transition =
            current_role == OrganizationRole::Owner || role == OrganizationRole::Owner;
        self.authorize(
            identity,
            &[ManagementScope::Write],
            AuthorizationTarget::Organization {
                organization_id,
                capability: if owner_transition {
                    Capability::ManageOwners
                } else {
                    Capability::ManageMembers
                },
            },
        )?;
        match input.llm_scope_ceiling {
            UpdateField::Omitted => {}
            UpdateField::Null => {
                return Err(ApplicationError::Validation(
                    "llm_scope_ceiling cannot be null".to_owned(),
                ));
            }
            UpdateField::Value(value) => {
                validate_llm_scopes(&value)?;
                scopes = value;
            }
        }
        match input.llm_capability_ceiling {
            UpdateField::Omitted => {}
            UpdateField::Null => {
                return Err(ApplicationError::Validation(
                    "llm_capability_ceiling cannot be null".to_owned(),
                ));
            }
            UpdateField::Value(value) => llm_capabilities = value,
        }
        match input.llm_route_ceiling {
            UpdateField::Omitted => {}
            UpdateField::Null => {
                return Err(ApplicationError::Validation(
                    "llm_route_ceiling cannot be null".to_owned(),
                ));
            }
            UpdateField::Value(value) => {
                validate_route_ceiling(&value)?;
                llm_routes = value;
            }
        }
        let current_tag = EntityTag::for_resource("membership", id, row.try_get("etag_token")?);
        require_etag(if_match, &current_tag)?;
        if current_role == OrganizationRole::Owner && role != OrganizationRole::Owner {
            ensure_not_final_owner(&mut transaction, organization_id, id).await?;
        }
        sqlx::query(
            "UPDATE memberships SET role=$3, llm_scope_ceiling=$4,
                    llm_capability_ceiling=$5, llm_route_ceiling=$6,
                    etag_token=$7, updated_at=now()
             WHERE organization_id=$1 AND id=$2",
        )
        .bind(organization_id.as_uuid())
        .bind(id)
        .bind(role_str(role))
        .bind(serde_json::to_value(&scopes).map_err(|_| ApplicationError::Internal)?)
        .bind(serde_json::to_value(&llm_capabilities).map_err(|_| ApplicationError::Internal)?)
        .bind(serde_json::to_value(&llm_routes).map_err(|_| ApplicationError::Internal)?)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        let security_tightening = role_rank(role) < role_rank(current_role)
            || !llm_scopes_are_superset(&scopes, &current_scopes)
            || !llm_capabilities.is_superset(&current_llm_capabilities)
            || !route_ceiling_is_superset(&llm_routes, &current_llm_routes);
        if role != current_role {
            revoke_external_sessions_for_membership(&mut transaction, organization_id, user_id)
                .await?;
        }
        let result = load_membership(&mut *transaction, organization_id, user_id).await?;
        self.store
            .commit_command(
                transaction,
                &command_audit(
                    identity,
                    Some(organization_id),
                    "membership",
                    id.to_string(),
                    "organizations.members.update",
                    &[
                        "role",
                        "llm_scope_ceiling",
                        "llm_capability_ceiling",
                        "llm_route_ceiling",
                    ],
                ),
                Some(&runtime_event(
                    "membership.changed",
                    json!({"organization_id":organization_id,"user_id":user_id}),
                    security_tightening,
                )),
            )
            .await?;
        Ok(result)
    }

    pub async fn remove_membership(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        user_id: UserId,
    ) -> Result<(), ApplicationError> {
        let mut transaction = self.store.begin().await?;
        lock_active_organization(&mut transaction, organization_id).await?;
        let row = sqlx::query(
            "SELECT id, role FROM memberships
             WHERE organization_id=$1 AND user_id=$2 AND status='active' FOR UPDATE",
        )
        .bind(organization_id.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApplicationError::NotFound)?;
        let id: Uuid = row.try_get("id")?;
        let role = parse_role(&row.try_get::<String, _>("role")?)?;
        self.authorize(
            identity,
            &[ManagementScope::Write],
            AuthorizationTarget::Organization {
                organization_id,
                capability: if role == OrganizationRole::Owner {
                    Capability::ManageOwners
                } else {
                    Capability::ManageMembers
                },
            },
        )?;
        if role == OrganizationRole::Owner {
            ensure_not_final_owner(&mut transaction, organization_id, id).await?;
        }
        sqlx::query(
            "UPDATE memberships SET status='removed', removed_at=now(),
                    updated_at=now(), etag_token=$3
             WHERE organization_id=$1 AND id=$2",
        )
        .bind(organization_id.as_uuid())
        .bind(id)
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await?;
        revoke_external_sessions_for_membership(&mut transaction, organization_id, user_id).await?;
        self.store
            .commit_command(
                transaction,
                &command_audit(
                    identity,
                    Some(organization_id),
                    "membership",
                    id.to_string(),
                    "organizations.members.remove",
                    &["status"],
                ),
                Some(&runtime_event(
                    "membership.changed",
                    json!({"organization_id":organization_id,"user_id":user_id}),
                    true,
                )),
            )
            .await?;
        Ok(())
    }
}

async fn revoke_external_sessions_for_membership(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    user_id: UserId,
) -> Result<(), ApplicationError> {
    sqlx::query(
        "UPDATE web_sessions SET status='revoked', revoked_at=now()
         WHERE authentication_method='external_session' AND status='active'
           AND principal->>'kind'='local_user' AND principal->>'user_id'=$1
           AND captured_organization_capabilities ? $2",
    )
    .bind(user_id.to_string())
    .bind(organization_id.to_string())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub(super) fn page_parameters(
    family: &str,
    cursor: Option<&str>,
    limit: Option<u32>,
) -> Result<(Option<Uuid>, u32), ApplicationError> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT);
    if limit == 0 || limit > MAX_LIMIT {
        return Err(ApplicationError::Validation(format!(
            "limit must be between 1 and {MAX_LIMIT}"
        )));
    }
    let cursor = cursor
        .map(|cursor| decode_cursor(family, cursor))
        .transpose()?;
    Ok((cursor, limit))
}

fn encode_cursor(family: &str, id: Uuid) -> String {
    URL_SAFE_NO_PAD.encode(format!("{family}\0{id}"))
}

fn decode_cursor(family: &str, cursor: &str) -> Result<Uuid, ApplicationError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| ApplicationError::Validation("invalid cursor".to_owned()))?;
    let value = String::from_utf8(bytes)
        .map_err(|_| ApplicationError::Validation("invalid cursor".to_owned()))?;
    let (actual_family, id) = value
        .split_once('\0')
        .ok_or_else(|| ApplicationError::Validation("invalid cursor".to_owned()))?;
    if actual_family != family {
        return Err(ApplicationError::Validation(
            "cursor does not match this collection".to_owned(),
        ));
    }
    Uuid::parse_str(id).map_err(|_| ApplicationError::Validation("invalid cursor".to_owned()))
}

pub(super) fn page_from_rows<T>(
    mut rows: Vec<sqlx::postgres::PgRow>,
    limit: u32,
    family: &str,
    mapper: fn(sqlx::postgres::PgRow) -> Result<T, ApplicationError>,
) -> Result<Page<T>, ApplicationError> {
    let has_more = rows.len() > usize::try_from(limit).map_err(|_| ApplicationError::Internal)?;
    if has_more {
        rows.pop();
    }
    let next_cursor = if has_more {
        rows.last()
            .map(|row| row.try_get::<Uuid, _>("id"))
            .transpose()?
            .map(|id| encode_cursor(family, id))
    } else {
        None
    };
    let items = rows.into_iter().map(mapper).collect::<Result<_, _>>()?;
    Ok(Page { items, next_cursor })
}

fn user_from_row(row: sqlx::postgres::PgRow) -> Result<User, ApplicationError> {
    Ok(User {
        id: UserId::from_uuid(row.try_get("id")?),
        kind: parse_user_kind(&row.try_get::<String, _>("kind")?)?,
        status: parse_user_status(&row.try_get::<String, _>("status")?)?,
        display_name: row.try_get("display_name")?,
        primary_email: row.try_get("primary_email")?,
        created_by_principal: row.try_get("created_by_principal")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

async fn load_user<'e, E>(
    executor: E,
    user_id: UserId,
) -> Result<(User, EntityTag), ApplicationError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(
        "SELECT id, kind, status, display_name, primary_email, created_by_principal,
                etag_token, created_at, updated_at FROM users WHERE id=$1",
    )
    .bind(user_id.as_uuid())
    .fetch_optional(executor)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    let tag = EntityTag::for_resource("user", user_id.as_uuid(), row.try_get("etag_token")?);
    Ok((user_from_row(row)?, tag))
}

fn organization_from_row(row: sqlx::postgres::PgRow) -> Result<Organization, ApplicationError> {
    Ok(Organization {
        id: OrganizationId::from_uuid(row.try_get("id")?),
        kind: parse_organization_kind(&row.try_get::<String, _>("kind")?)?,
        status: parse_organization_status(&row.try_get::<String, _>("status")?)?,
        name: row.try_get("name")?,
        slug: row.try_get("slug")?,
        created_by_principal: row.try_get("created_by_principal")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

async fn load_organization<'e, E>(
    executor: E,
    organization_id: OrganizationId,
) -> Result<(Organization, EntityTag), ApplicationError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(
        "SELECT id, kind, status, name, slug, created_by_principal,
                etag_token, created_at, updated_at
         FROM organizations WHERE id=$1",
    )
    .bind(organization_id.as_uuid())
    .fetch_optional(executor)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    let tag = EntityTag::for_resource(
        "organization",
        organization_id.as_uuid(),
        row.try_get("etag_token")?,
    );
    Ok((organization_from_row(row)?, tag))
}

fn membership_from_row(row: sqlx::postgres::PgRow) -> Result<Membership, ApplicationError> {
    Ok(Membership {
        id: row.try_get::<Uuid, _>("id")?.to_string(),
        organization_id: OrganizationId::from_uuid(row.try_get("organization_id")?),
        user_id: UserId::from_uuid(row.try_get("user_id")?),
        role: parse_role(&row.try_get::<String, _>("role")?)?,
        status: row.try_get("status")?,
        llm_scope_ceiling: serde_json::from_value(row.try_get("llm_scope_ceiling")?)
            .map_err(|_| ApplicationError::Internal)?,
        llm_capability_ceiling: serde_json::from_value(row.try_get("llm_capability_ceiling")?)
            .map_err(|_| ApplicationError::Internal)?,
        llm_route_ceiling: serde_json::from_value(row.try_get("llm_route_ceiling")?)
            .map_err(|_| ApplicationError::Internal)?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

async fn load_membership<'e, E>(
    executor: E,
    organization_id: OrganizationId,
    user_id: UserId,
) -> Result<(Membership, EntityTag), ApplicationError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(
        "SELECT id, organization_id, user_id, role, status, llm_scope_ceiling,
                llm_capability_ceiling, llm_route_ceiling,
                etag_token, created_at, updated_at
         FROM memberships WHERE organization_id=$1 AND user_id=$2 AND status='active'",
    )
    .bind(organization_id.as_uuid())
    .bind(user_id.as_uuid())
    .fetch_optional(executor)
    .await?
    .ok_or(ApplicationError::NotFound)?;
    let id: Uuid = row.try_get("id")?;
    let tag = EntityTag::for_resource("membership", id, row.try_get("etag_token")?);
    Ok((membership_from_row(row)?, tag))
}

fn require_etag(provided: Option<&str>, current: &EntityTag) -> Result<(), ApplicationError> {
    let provided = provided.ok_or(ApplicationError::PreconditionRequired)?;
    if current.matches(provided) {
        Ok(())
    } else {
        Err(ApplicationError::Stale {
            current_etag: Some(current.to_string()),
        })
    }
}

fn require_nonempty_update<const N: usize>(omitted: [bool; N]) -> Result<(), ApplicationError> {
    if omitted.into_iter().all(|value| value) {
        Err(ApplicationError::Validation(
            "at least one update field is required".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn validate_display_name(value: &str) -> Result<(), ApplicationError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 160 || value.chars().any(char::is_control) {
        return Err(ApplicationError::Validation(
            "display name must contain 1 to 160 safe characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_email(value: Option<&str>) -> Result<(), ApplicationError> {
    if let Some(value) = value {
        let value = value.trim();
        if value.len() < 3
            || value.len() > 320
            || !value.contains('@')
            || value.chars().any(char::is_control)
        {
            return Err(ApplicationError::Validation(
                "primary_email is invalid".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_slug(value: Option<&str>) -> Result<(), ApplicationError> {
    if let Some(value) = value {
        let bytes = value.as_bytes();
        if value.is_empty()
            || value.len() > 63
            || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        {
            return Err(ApplicationError::Validation(
                "slug must use lowercase letters, digits, and hyphens".to_owned(),
            ));
        }
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

fn llm_scopes_are_superset(candidate: &[String], current: &[String]) -> bool {
    let candidate = candidate.iter().collect::<BTreeSet<_>>();
    let current = current.iter().collect::<BTreeSet<_>>();
    candidate.is_superset(&current)
}

fn route_ceiling_is_superset(candidate: &JwtRouteCeiling, current: &JwtRouteCeiling) -> bool {
    match (candidate, current) {
        (JwtRouteCeiling::AllOrganizationGranted, _) | (_, JwtRouteCeiling::None) => true,
        (
            JwtRouteCeiling::Routes {
                route_ids: candidate,
            },
            JwtRouteCeiling::Routes { route_ids: current },
        ) => candidate.is_superset(current),
        (JwtRouteCeiling::None, _)
        | (JwtRouteCeiling::Routes { .. }, JwtRouteCeiling::AllOrganizationGranted) => false,
    }
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
    if status != "active" {
        return Err(ApplicationError::Conflict(
            "organization is not active".to_owned(),
        ));
    }
    Ok(())
}

async fn require_active_user(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: UserId,
) -> Result<(), ApplicationError> {
    let status = sqlx::query_scalar::<_, String>("SELECT status FROM users WHERE id=$1 FOR SHARE")
        .bind(user_id.as_uuid())
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(ApplicationError::Validation(
            "user does not exist".to_owned(),
        ))?;
    if status != "active" {
        return Err(ApplicationError::Validation(
            "user must be active".to_owned(),
        ));
    }
    Ok(())
}

async fn ensure_not_final_owner(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    excluded_membership_id: Uuid,
) -> Result<(), ApplicationError> {
    let another_owner = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
            SELECT 1 FROM memberships
            WHERE organization_id=$1 AND status='active' AND role='owner' AND id<>$2
         )",
    )
    .bind(organization_id.as_uuid())
    .bind(excluded_membership_id)
    .fetch_one(&mut **transaction)
    .await?;
    if another_owner {
        Ok(())
    } else {
        Err(ApplicationError::Conflict(
            "the final active owner cannot be removed or demoted".to_owned(),
        ))
    }
}

fn command_audit(
    identity: &RequestIdentity,
    organization_id: Option<OrganizationId>,
    kind: &str,
    id: String,
    operation: &str,
    changed_fields: &[&str],
) -> AuditRecord {
    AuditRecord {
        actor: Some(Actor::from(&identity.principal)),
        authentication_evidence: json!({
            "method": identity.principal.authentication_method,
            "session_id": identity.principal.session_id,
            "external_issuer_id": identity.principal.external_issuer_id,
        }),
        organization_id,
        target_resource_kind: kind.to_owned(),
        target_resource_id: Some(id),
        operation_id: operation.to_owned(),
        outcome: "accepted",
        request_id: identity.request_id.clone(),
        changed_fields: changed_fields
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        safe_details: json!({}),
    }
}

fn runtime_event(kind: &str, scope: Value, security_tightening: bool) -> RuntimeEvent {
    RuntimeEvent {
        event_kind: kind.to_owned(),
        affected_scope: scope,
        security_tightening,
    }
}

pub(crate) fn default_organization_api_key_policy() -> Value {
    json!({
        "management": {
            "allowed_scopes": ["management:read", "management:write", "management:secrets", "management:authority"],
            "allowed_capabilities": ["read_organization", "update_organization", "read_members", "manage_members", "read_management_keys", "create_management_keys", "manage_management_keys", "update_api_key_policy", "read_gateway_keys", "create_gateway_keys", "manage_gateway_keys", "manage_byok", "configure_routes", "configure_budgets", "read_usage", "read_audit"],
            "max_active_keys": 100,
            "max_expiry_days": 365,
            "max_overlap_seconds": 3600
        },
        "member_self_service": {
            "management_key_creation": false,
            "allowed_scopes": [],
            "allowed_capabilities": [],
            "max_active_keys": 0,
            "max_expiry_days": 0,
            "max_overlap_seconds": 0
        },
        "gateway": {
            "enabled": false,
            "allowed_scopes": ["llm:invoke", "llm:stream", "llm:tools", "llm:multimodal-input", "llm:structured-output"],
            "allowed_capabilities": [],
            "allowed_route_ids": [],
            "max_active_keys": 0,
            "max_expiry_days": 365,
            "max_overlap_seconds": 3600,
            "budget": {"max_limit_cost_nanos": "0", "allowed_modes": ["enforce"]},
            "rate": {"max_requests_per_minute": 0, "max_input_units_per_minute": 0},
            "concurrency": {"max_limit": 0, "allowed_modes": []}
        },
        "gateway_member_self_service": {
            "enabled": false,
            "allowed_scopes": [],
            "allowed_capabilities": [],
            "allowed_route_ids": [],
            "max_active_keys": 0,
            "max_expiry_days": 0,
            "max_overlap_seconds": 0,
            "budget": {"max_limit_cost_nanos": "0", "allowed_modes": []},
            "rate": {"max_requests_per_minute": 0, "max_input_units_per_minute": 0},
            "concurrency": {"max_limit": 0, "allowed_modes": []}
        }
    })
}

fn parse_user_kind(value: &str) -> Result<UserKind, ApplicationError> {
    match value {
        "human" => Ok(UserKind::Human),
        "synthetic" => Ok(UserKind::Synthetic),
        _ => Err(ApplicationError::Internal),
    }
}

fn parse_user_status(value: &str) -> Result<UserStatus, ApplicationError> {
    match value {
        "active" => Ok(UserStatus::Active),
        "disabled" => Ok(UserStatus::Disabled),
        _ => Err(ApplicationError::Internal),
    }
}

fn parse_organization_kind(value: &str) -> Result<OrganizationKind, ApplicationError> {
    match value {
        "ordinary" => Ok(OrganizationKind::Ordinary),
        "synthetic" => Ok(OrganizationKind::Synthetic),
        _ => Err(ApplicationError::Internal),
    }
}

fn parse_organization_status(value: &str) -> Result<OrganizationStatus, ApplicationError> {
    match value {
        "active" => Ok(OrganizationStatus::Active),
        "suspended" => Ok(OrganizationStatus::Suspended),
        _ => Err(ApplicationError::Internal),
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

const fn role_rank(role: OrganizationRole) -> u8 {
    match role {
        OrganizationRole::Owner => 3,
        OrganizationRole::Admin => 2,
        OrganizationRole::Member => 1,
    }
}

fn map_database_conflict(error: sqlx::Error) -> ApplicationError {
    if error.as_database_error().is_some() {
        ApplicationError::Conflict("the resource conflicts with current state".to_owned())
    } else {
        error.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_are_collection_bound() {
        let id = Uuid::now_v7();
        let cursor = encode_cursor("users", id);
        assert_eq!(decode_cursor("users", &cursor).unwrap(), id);
        assert!(decode_cursor("organizations", &cursor).is_err());
    }

    #[test]
    fn validation_rejects_unknown_or_incomplete_llm_scopes_and_unsafe_slugs() {
        assert!(validate_llm_scopes(&[]).is_ok());
        assert!(validate_llm_scopes(&["llm:invoke".to_owned()]).is_ok());
        assert!(validate_llm_scopes(&["llm:stream".to_owned()]).is_err());
        assert!(validate_llm_scopes(&["llm:invoke".to_owned(), "llm:invoke".to_owned()]).is_err());
        assert!(validate_llm_scopes(&["llm:*".to_owned()]).is_err());
        assert!(validate_slug(Some("safe-slug-1")).is_ok());
        assert!(validate_slug(Some("Unsafe")).is_err());
    }

    #[test]
    fn membership_ceiling_narrowing_is_conservative() {
        let route_a = RouteId::new().to_string();
        let route_b = RouteId::new().to_string();
        assert!(!llm_scopes_are_superset(
            &["llm:invoke".to_owned()],
            &["llm:invoke".to_owned(), "llm:stream".to_owned()],
        ));
        assert!(route_ceiling_is_superset(
            &JwtRouteCeiling::AllOrganizationGranted,
            &JwtRouteCeiling::Routes {
                route_ids: BTreeSet::from([route_a.clone()]),
            },
        ));
        assert!(!route_ceiling_is_superset(
            &JwtRouteCeiling::Routes {
                route_ids: BTreeSet::from([route_a]),
            },
            &JwtRouteCeiling::Routes {
                route_ids: BTreeSet::from([route_b]),
            },
        ));
        assert!(!route_ceiling_is_superset(
            &JwtRouteCeiling::None,
            &JwtRouteCeiling::AllOrganizationGranted,
        ));
    }

    #[tokio::test]
    async fn membership_llm_narrowing_journals_security_tightening() {
        use std::{collections::BTreeMap, sync::Arc};

        use crate::{
            adapters::postgres::test_support::{
                connect_from_environment, shared_database_test_lock,
            },
            config::ServerConfig,
            domain::generate_management_key,
            runtime::RuntimePublisher,
            secrets::{CustodyPair, CustodyRegistry, SecretService},
        };

        let _database_guard = shared_database_test_lock().await;
        let Some(store) = connect_from_environment().await else {
            return;
        };
        let Ok(redis_url) = std::env::var("OWLRORA_TEST_REDIS_URL") else {
            return;
        };
        let seed_key = generate_management_key().expose_once();
        let secret_root = URL_SAFE_NO_PAD.encode([11_u8; 32]);
        let config = Arc::new(
            ServerConfig::from_values(&BTreeMap::from([
                (
                    "OWLRORA_DATABASE_URL".to_owned(),
                    std::env::var("OWLRORA_TEST_DATABASE_URL").unwrap(),
                ),
                (
                    "OWLRORA_PUBLIC_ORIGIN".to_owned(),
                    "http://127.0.0.1:8080".to_owned(),
                ),
                ("OWLRORA_REDIS_URL".to_owned(), redis_url),
                (
                    "OWLRORA_NODE_INSTANCE_ID".to_owned(),
                    format!("resources-test-{}", Uuid::now_v7()),
                ),
                ("OWLRORA_SEED_ADMIN_API_KEY".to_owned(), seed_key.clone()),
                ("OWLRORA_SECRET_ROOT".to_owned(), secret_root),
            ]))
            .unwrap(),
        );
        let organization_id = OrganizationId::new();
        let user_id = UserId::new();
        let membership_id = Uuid::now_v7();
        let mut transaction = store.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO users(id,kind,status,display_name,created_by_principal,etag_token)
             VALUES ($1,'human','active','Narrowing member','{}',$2)",
        )
        .bind(user_id.as_uuid())
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO organizations(
                id,kind,status,name,created_by_principal,etag_token
             ) VALUES ($1,'ordinary','active',$2,'{}',$3)",
        )
        .bind(organization_id.as_uuid())
        .bind(format!("narrowing-{organization_id}"))
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO organization_api_key_policies(organization_id,policy,etag_token)
             VALUES ($1,$2,$3)",
        )
        .bind(organization_id.as_uuid())
        .bind(default_organization_api_key_policy())
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO memberships(
                id,organization_id,user_id,role,status,llm_scope_ceiling,
                llm_capability_ceiling,llm_route_ceiling,created_by_principal,etag_token
             ) VALUES ($1,$2,$3,'owner','active',
                '[\"llm:invoke\",\"llm:stream\"]','[\"streaming\"]',
                '{\"kind\":\"all_organization_granted\"}','{}',$4)",
        )
        .bind(membership_id)
        .bind(organization_id.as_uuid())
        .bind(user_id.as_uuid())
        .bind(Uuid::now_v7())
        .execute(&mut *transaction)
        .await
        .unwrap();
        transaction.commit().await.unwrap();

        let secrets = Arc::new(
            SecretService::new(
                config.secret_root.clone(),
                CustodyRegistry::default(),
                CustodyPair::software(),
            )
            .unwrap(),
        );
        let runtime = RuntimePublisher::start(
            store.clone(),
            Arc::clone(&secrets),
            format!("narrowing-test-{}", Uuid::now_v7()),
        )
        .await
        .unwrap();
        let application =
            Application::new(store.clone(), Arc::clone(&runtime), config, secrets).unwrap();
        let identity = application
            .authenticate_management_key(&seed_key, "narrowing-test".to_owned())
            .unwrap();

        let (_, mut etag) = load_membership(store.pool(), organization_id, user_id)
            .await
            .unwrap();
        let updates = [
            UpdateMembership {
                llm_scope_ceiling: UpdateField::Value(vec!["llm:invoke".to_owned()]),
                ..UpdateMembership::default()
            },
            UpdateMembership {
                llm_capability_ceiling: UpdateField::Value(BTreeSet::new()),
                ..UpdateMembership::default()
            },
            UpdateMembership {
                llm_route_ceiling: UpdateField::Value(JwtRouteCeiling::None),
                ..UpdateMembership::default()
            },
        ];
        for update in updates {
            let (_, next_etag) = application
                .update_membership(
                    &identity,
                    organization_id,
                    user_id,
                    Some(etag.as_str()),
                    update,
                )
                .await
                .unwrap();
            etag = next_etag;
            let revision = store.current_revision().await.unwrap();
            let classification = sqlx::query_scalar::<_, String>(
                "SELECT security_classification FROM configuration_journal WHERE revision=$1",
            )
            .bind(revision)
            .fetch_one(store.pool())
            .await
            .unwrap();
            assert_eq!(classification, "tightening");
        }
        runtime.shutdown().await;
    }

    #[test]
    fn default_policy_keeps_module_two_gateway_issuance_disabled() {
        let policy = default_organization_api_key_policy();
        assert_eq!(policy["gateway"]["enabled"], false);
        assert_eq!(policy["gateway"]["max_active_keys"], 0);
        assert_eq!(policy["gateway"]["allowed_scopes"][0], "llm:invoke");
        assert_eq!(
            policy["member_self_service"]["management_key_creation"],
            false
        );
    }
}
