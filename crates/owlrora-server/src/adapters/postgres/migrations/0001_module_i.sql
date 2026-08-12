CREATE TABLE system_installation (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    installation_id uuid NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION reject_immutable_row_change()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'immutable row cannot be changed';
END;
$$;

CREATE TRIGGER system_installation_immutable
BEFORE UPDATE OR DELETE ON system_installation
FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();

CREATE TABLE runtime_revision_counter (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    current_revision bigint NOT NULL CHECK (current_revision >= 0)
);
INSERT INTO runtime_revision_counter(singleton, current_revision) VALUES (true, 0);

CREATE TABLE configuration_journal (
    revision bigint PRIMARY KEY CHECK (revision > 0),
    event_kind text NOT NULL CHECK (char_length(event_kind) BETWEEN 1 AND 96),
    affected_scope jsonb NOT NULL,
    security_classification text NOT NULL CHECK (security_classification IN ('tightening', 'ordinary')),
    committed_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE transactional_outbox (
    id uuid PRIMARY KEY,
    revision bigint REFERENCES configuration_journal(revision) ON DELETE RESTRICT,
    event_kind text NOT NULL CHECK (char_length(event_kind) BETWEEN 1 AND 96),
    payload jsonb NOT NULL,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'leased', 'delivered', 'failed')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    lease_owner text,
    lease_token uuid,
    lease_expires_at timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz
);
CREATE INDEX transactional_outbox_due_idx ON transactional_outbox(next_attempt_at, id)
WHERE state IN ('pending', 'failed');

CREATE TABLE audit_entries (
    id uuid PRIMARY KEY,
    actor jsonb,
    authentication_evidence jsonb NOT NULL,
    organization_id uuid,
    target_resource_kind text NOT NULL CHECK (char_length(target_resource_kind) BETWEEN 1 AND 96),
    target_resource_id text,
    operation_id text NOT NULL CHECK (char_length(operation_id) BETWEEN 1 AND 160),
    outcome text NOT NULL CHECK (outcome IN ('accepted', 'rejected', 'failed')),
    request_id text NOT NULL CHECK (char_length(request_id) BETWEEN 1 AND 128),
    changed_fields jsonb NOT NULL DEFAULT '[]'::jsonb,
    safe_details jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_entries_time_idx ON audit_entries(created_at DESC, id DESC);
CREATE INDEX audit_entries_organization_time_idx ON audit_entries(organization_id, created_at DESC, id DESC);
CREATE TRIGGER audit_entries_immutable
BEFORE UPDATE OR DELETE ON audit_entries
FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();

CREATE TABLE idempotency_records (
    actor_fingerprint text NOT NULL,
    scope_fingerprint text NOT NULL,
    operation_id text NOT NULL,
    idempotency_key text NOT NULL,
    request_fingerprint bytea NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    state text NOT NULL CHECK (state IN ('in_progress', 'completed')),
    response_status integer,
    response_body jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (actor_fingerprint, scope_fingerprint, operation_id, idempotency_key)
);
CREATE INDEX idempotency_records_expiry_idx ON idempotency_records(expires_at);

CREATE TABLE worker_leases (
    worker_kind text NOT NULL,
    item_id text NOT NULL,
    fencing_token bigint NOT NULL CHECK (fencing_token > 0),
    owner text NOT NULL,
    lease_expires_at timestamptz NOT NULL,
    attempt integer NOT NULL DEFAULT 1 CHECK (attempt > 0),
    last_error_class text,
    next_attempt_at timestamptz,
    PRIMARY KEY (worker_kind, item_id)
);

CREATE TABLE node_watermarks (
    node_id text PRIMARY KEY,
    applied_revision bigint NOT NULL DEFAULT 0 CHECK (applied_revision >= 0),
    applied_security_revision bigint NOT NULL DEFAULT 0 CHECK (applied_security_revision >= 0),
    last_success_at timestamptz,
    last_failure_at timestamptz,
    safe_failure_class text,
    heartbeat_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id uuid PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('human', 'synthetic')),
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 160),
    primary_email text CHECK (primary_email IS NULL OR char_length(primary_email) BETWEEN 3 AND 320),
    created_by_principal jsonb NOT NULL,
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX users_status_created_idx ON users(status, created_at DESC, id DESC);

CREATE TABLE organizations (
    id uuid PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('ordinary', 'synthetic')),
    status text NOT NULL CHECK (status IN ('active', 'suspended')),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 160),
    slug text CHECK (slug IS NULL OR slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    created_by_principal jsonb NOT NULL,
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX organizations_slug_unique_idx ON organizations(slug) WHERE slug IS NOT NULL;
CREATE INDEX organizations_status_created_idx ON organizations(status, created_at DESC, id DESC);

CREATE TABLE memberships (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    status text NOT NULL CHECK (status IN ('active', 'removed')),
    llm_scope_ceiling jsonb NOT NULL DEFAULT '[]'::jsonb,
    etag_token uuid NOT NULL,
    created_by_principal jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    removed_at timestamptz,
    UNIQUE (organization_id, id)
);
CREATE UNIQUE INDEX memberships_active_pair_idx ON memberships(organization_id, user_id) WHERE status = 'active';
CREATE INDEX memberships_user_active_idx ON memberships(user_id, organization_id) WHERE status = 'active';
CREATE INDEX memberships_organization_active_idx ON memberships(organization_id, role, id) WHERE status = 'active';

CREATE OR REPLACE FUNCTION enforce_active_organization_owner()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    checked_organization_id uuid;
    organization_is_active boolean;
BEGIN
    checked_organization_id := COALESCE(NEW.organization_id, OLD.organization_id, NEW.id, OLD.id);
    SELECT status = 'active' INTO organization_is_active
    FROM organizations WHERE id = checked_organization_id;
    IF organization_is_active AND NOT EXISTS (
        SELECT 1 FROM memberships
        WHERE organization_id = checked_organization_id
          AND status = 'active' AND role = 'owner'
    ) THEN
        RAISE EXCEPTION 'active organization must retain an active owner';
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE CONSTRAINT TRIGGER memberships_owner_invariant
AFTER INSERT OR UPDATE OR DELETE ON memberships
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION enforce_active_organization_owner();
CREATE CONSTRAINT TRIGGER organizations_owner_invariant
AFTER INSERT OR UPDATE ON organizations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION enforce_active_organization_owner();

CREATE TABLE invitations (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    intended_email text CHECK (intended_email IS NULL OR char_length(intended_email) BETWEEN 3 AND 320),
    intended_role text NOT NULL CHECK (intended_role IN ('owner', 'admin', 'member')),
    llm_scope_ceiling jsonb NOT NULL DEFAULT '[]'::jsonb,
    token_digest bytea NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
    state text NOT NULL CHECK (state IN ('pending', 'accepted', 'revoked', 'expired')),
    expires_at timestamptz NOT NULL,
    accepted_by_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    created_by_principal jsonb NOT NULL,
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    accepted_at timestamptz,
    revoked_at timestamptz
);
CREATE INDEX invitations_organization_state_idx ON invitations(organization_id, state, created_at DESC, id DESC);
CREATE INDEX invitations_expiry_idx ON invitations(expires_at) WHERE state = 'pending';

CREATE TABLE provisioning_policies (
    id uuid PRIMARY KEY,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 160),
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    user_kind text NOT NULL CHECK (user_kind IN ('human', 'synthetic')),
    configuration jsonb NOT NULL,
    created_by_principal jsonb NOT NULL,
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE external_identity_issuers (
    id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE CHECK (name ~ '^[a-z][a-z0-9_-]{0,62}$'),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 160),
    issuer text NOT NULL UNIQUE CHECK (char_length(issuer) BETWEEN 8 AND 2048),
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    jwks_source jsonb NOT NULL,
    current_verifier_material_version_id uuid,
    allowed_algorithms jsonb NOT NULL,
    accepted_audiences jsonb NOT NULL,
    subject_claim text NOT NULL CHECK (char_length(subject_claim) BETWEEN 1 AND 128),
    claim_mapping jsonb NOT NULL DEFAULT '{}'::jsonb,
    jwt_capability_ceiling jsonb NOT NULL DEFAULT '[]'::jsonb,
    management_scope_ceiling jsonb NOT NULL DEFAULT '[]'::jsonb,
    management_organization_ceiling jsonb NOT NULL DEFAULT '{"kind":"none"}'::jsonb,
    capability_claim_policy text NOT NULL CHECK (capability_claim_policy IN ('ignore', 'optional_narrowing', 'required_narrowing')),
    jwt_route_ceiling jsonb NOT NULL DEFAULT '{"kind":"none"}'::jsonb,
    organization_selector jsonb NOT NULL DEFAULT '{"kind":"none"}'::jsonb,
    provisioning_policy_id uuid REFERENCES provisioning_policies(id) ON DELETE RESTRICT,
    browser_login jsonb,
    clock_skew_seconds integer NOT NULL CHECK (clock_skew_seconds BETWEEN 0 AND 300),
    key_cache_policy jsonb NOT NULL,
    policy_version bigint NOT NULL DEFAULT 1 CHECK (policy_version > 0),
    created_by_principal jsonb NOT NULL,
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE issuer_verifier_material_versions (
    id uuid PRIMARY KEY,
    issuer_id uuid NOT NULL REFERENCES external_identity_issuers(id) ON DELETE RESTRICT,
    version bigint NOT NULL CHECK (version > 0),
    jwks jsonb NOT NULL,
    source_evidence jsonb NOT NULL,
    fetched_at timestamptz NOT NULL,
    accepted_until timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (issuer_id, version),
    UNIQUE (issuer_id, id)
);
ALTER TABLE external_identity_issuers
ADD CONSTRAINT external_identity_issuers_material_fk
FOREIGN KEY (id, current_verifier_material_version_id)
REFERENCES issuer_verifier_material_versions(issuer_id, id)
DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE external_identity_bindings (
    id uuid PRIMARY KEY,
    issuer_id uuid NOT NULL REFERENCES external_identity_issuers(id) ON DELETE RESTRICT,
    external_subject text NOT NULL CHECK (char_length(external_subject) BETWEEN 1 AND 512),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    status text NOT NULL CHECK (status IN ('active', 'removed')),
    created_by_principal jsonb NOT NULL,
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (issuer_id, external_subject)
);
CREATE INDEX external_identity_bindings_user_idx ON external_identity_bindings(user_id, issuer_id) WHERE status = 'active';

CREATE TABLE protected_secret_versions (
    id uuid PRIMARY KEY,
    scope_kind text NOT NULL CHECK (scope_kind IN ('system', 'organization')),
    organization_id uuid REFERENCES organizations(id) ON DELETE RESTRICT,
    owner_kind text NOT NULL,
    owner_id uuid NOT NULL,
    owner_generation bigint NOT NULL CHECK (owner_generation > 0),
    secret_version bigint NOT NULL CHECK (secret_version > 0),
    field_purpose text NOT NULL,
    custody_provider_id text NOT NULL,
    provider_format_version integer NOT NULL CHECK (provider_format_version > 0),
    context_version integer NOT NULL CHECK (context_version > 0),
    opaque_envelope bytea NOT NULL CHECK (octet_length(opaque_envelope) BETWEEN 1 AND 1048576),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((scope_kind = 'system' AND organization_id IS NULL) OR (scope_kind = 'organization' AND organization_id IS NOT NULL)),
    UNIQUE (owner_kind, owner_id, owner_generation, secret_version, field_purpose)
);

CREATE TABLE management_api_keys (
    id uuid PRIMARY KEY,
    resource_scope_kind text NOT NULL CHECK (resource_scope_kind IN ('deployment', 'organization')),
    organization_id uuid REFERENCES organizations(id) ON DELETE RESTRICT,
    issuance_policy_class text NOT NULL CHECK (issuance_policy_class IN ('standard', 'member_self_service')),
    created_by_principal jsonb NOT NULL,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 160),
    key_prefix text NOT NULL,
    lookup_id text NOT NULL UNIQUE CHECK (char_length(lookup_id) BETWEEN 22 AND 64),
    scopes jsonb NOT NULL,
    capability_ceiling jsonb NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'disabled', 'revoked')),
    expires_at timestamptz,
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    CHECK ((resource_scope_kind = 'deployment' AND organization_id IS NULL) OR (resource_scope_kind = 'organization' AND organization_id IS NOT NULL)),
    UNIQUE (organization_id, id)
);
CREATE INDEX management_api_keys_organization_idx ON management_api_keys(organization_id, created_at DESC, id DESC) WHERE organization_id IS NOT NULL;
CREATE INDEX management_api_keys_deployment_idx ON management_api_keys(created_at DESC, id DESC) WHERE organization_id IS NULL;

CREATE TABLE management_api_key_secret_versions (
    id uuid PRIMARY KEY,
    management_api_key_id uuid NOT NULL REFERENCES management_api_keys(id) ON DELETE RESTRICT,
    lookup_id text NOT NULL UNIQUE,
    secret_digest bytea NOT NULL CHECK (octet_length(secret_digest) = 32),
    state text NOT NULL CHECK (state IN ('current', 'overlap', 'retired')),
    overlap_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz
);
CREATE UNIQUE INDEX management_key_one_current_idx ON management_api_key_secret_versions(management_api_key_id) WHERE state = 'current';
CREATE UNIQUE INDEX management_key_one_overlap_idx ON management_api_key_secret_versions(management_api_key_id) WHERE state = 'overlap';

CREATE TABLE deployment_management_key_policy (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    policy jsonb NOT NULL,
    etag_token uuid NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE organization_api_key_policies (
    organization_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE RESTRICT,
    policy jsonb NOT NULL,
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE system_administrator_grants (
    id uuid PRIMARY KEY,
    subject_kind text NOT NULL CHECK (subject_kind IN ('local_user', 'deployment_management_api_key')),
    user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    management_api_key_id uuid REFERENCES management_api_keys(id) ON DELETE RESTRICT,
    status text NOT NULL CHECK (status IN ('active', 'revoked')),
    granted_by_principal jsonb NOT NULL,
    revoked_by_principal jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    CHECK (
        (subject_kind = 'local_user' AND user_id IS NOT NULL AND management_api_key_id IS NULL)
        OR
        (subject_kind = 'deployment_management_api_key' AND user_id IS NULL AND management_api_key_id IS NOT NULL)
    )
);
CREATE UNIQUE INDEX system_admin_active_user_idx ON system_administrator_grants(user_id) WHERE status = 'active' AND user_id IS NOT NULL;
CREATE UNIQUE INDEX system_admin_active_key_idx ON system_administrator_grants(management_api_key_id) WHERE status = 'active' AND management_api_key_id IS NOT NULL;

CREATE OR REPLACE FUNCTION enforce_deployment_admin_key_scope()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.subject_kind = 'deployment_management_api_key' AND NOT EXISTS (
        SELECT 1 FROM management_api_keys
        WHERE id = NEW.management_api_key_id AND resource_scope_kind = 'deployment'
    ) THEN
        RAISE EXCEPTION 'system administrator key subject must be deployment scoped';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER system_admin_key_scope
BEFORE INSERT OR UPDATE ON system_administrator_grants
FOR EACH ROW EXECUTE FUNCTION enforce_deployment_admin_key_scope();

CREATE TABLE web_sessions (
    id uuid PRIMARY KEY,
    session_digest bytea NOT NULL UNIQUE CHECK (octet_length(session_digest) = 32),
    csrf_digest bytea NOT NULL CHECK (octet_length(csrf_digest) = 32),
    principal jsonb NOT NULL,
    authentication_method text NOT NULL CHECK (authentication_method IN ('management_api_key_session', 'external_session')),
    management_api_key_id uuid REFERENCES management_api_keys(id) ON DELETE RESTRICT,
    accepted_key_version_id text,
    external_issuer_id uuid REFERENCES external_identity_issuers(id) ON DELETE RESTRICT,
    captured_management_scopes jsonb NOT NULL,
    captured_resource_scope jsonb NOT NULL,
    captured_capability_ceiling jsonb NOT NULL,
    captured_organization_ceiling jsonb,
    status text NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    last_seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX web_sessions_expiry_idx ON web_sessions(expires_at) WHERE status = 'active';
CREATE INDEX web_sessions_key_idx ON web_sessions(management_api_key_id) WHERE status = 'active';

CREATE TABLE oidc_login_states (
    id uuid PRIMARY KEY,
    state_digest bytea NOT NULL UNIQUE CHECK (octet_length(state_digest) = 32),
    issuer_id uuid NOT NULL REFERENCES external_identity_issuers(id) ON DELETE RESTRICT,
    pkce_verifier_envelope bytea NOT NULL,
    nonce_digest bytea NOT NULL CHECK (octet_length(nonce_digest) = 32),
    return_to text NOT NULL CHECK (char_length(return_to) BETWEEN 1 AND 1024),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);
CREATE INDEX oidc_login_states_expiry_idx ON oidc_login_states(expires_at) WHERE consumed_at IS NULL;
