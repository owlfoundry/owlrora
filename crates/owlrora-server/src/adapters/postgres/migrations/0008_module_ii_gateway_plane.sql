-- Module II: durable LLM gateway catalog, authorization, coordination authority, and usage facts.

-- Short-lived OIDC login states predate configurable custody. They cannot be dispatched exactly
-- without persisted provider metadata, so this migration invalidates them and requires exact
-- metadata for every future state.
DELETE FROM oidc_login_states;
ALTER TABLE oidc_login_states
    ADD COLUMN pkce_custody_provider_id text NOT NULL,
    ADD COLUMN pkce_provider_format_version integer NOT NULL
        CHECK (pkce_provider_format_version > 0),
    ADD COLUMN pkce_context_version integer NOT NULL CHECK (pkce_context_version > 0),
    ADD CONSTRAINT oidc_login_states_pkce_envelope_length
        CHECK (octet_length(pkce_verifier_envelope) BETWEEN 1 AND 1048576);

ALTER TABLE memberships
    ADD COLUMN llm_route_ceiling jsonb NOT NULL DEFAULT '{"kind":"none"}'::jsonb,
    ADD COLUMN llm_capability_ceiling jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD CONSTRAINT memberships_scope_ceiling_array CHECK (jsonb_typeof(llm_scope_ceiling) = 'array'),
    ADD CONSTRAINT memberships_route_ceiling_object CHECK (jsonb_typeof(llm_route_ceiling) = 'object'),
    ADD CONSTRAINT memberships_llm_capability_ceiling_array CHECK (jsonb_typeof(llm_capability_ceiling) = 'array'),
    ADD CONSTRAINT memberships_owner_binding_unique UNIQUE (organization_id, id, user_id);

ALTER TABLE invitations
    ADD COLUMN llm_route_ceiling jsonb NOT NULL DEFAULT '{"kind":"none"}'::jsonb,
    ADD COLUMN llm_capability_ceiling jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD CONSTRAINT invitations_scope_ceiling_array CHECK (jsonb_typeof(llm_scope_ceiling) = 'array'),
    ADD CONSTRAINT invitations_route_ceiling_object CHECK (jsonb_typeof(llm_route_ceiling) = 'object'),
    ADD CONSTRAINT invitations_llm_capability_ceiling_array CHECK (jsonb_typeof(llm_capability_ceiling) = 'array');

ALTER TABLE external_identity_issuers
    ADD COLUMN management_capability_ceiling jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN llm_scope_ceiling jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN llm_capability_ceiling jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD CONSTRAINT external_identity_issuers_management_scope_array CHECK (jsonb_typeof(management_scope_ceiling) = 'array'),
    ADD CONSTRAINT external_identity_issuers_management_capability_array CHECK (jsonb_typeof(management_capability_ceiling) = 'array'),
    ADD CONSTRAINT external_identity_issuers_llm_scope_array CHECK (jsonb_typeof(llm_scope_ceiling) = 'array'),
    ADD CONSTRAINT external_identity_issuers_llm_capability_array CHECK (jsonb_typeof(llm_capability_ceiling) = 'array'),
    ADD CONSTRAINT external_identity_issuers_route_ceiling_object CHECK (jsonb_typeof(jwt_route_ceiling) = 'object'),
    ADD CONSTRAINT external_identity_issuers_organization_selector_object CHECK (jsonb_typeof(organization_selector) = 'object');

-- Preserve the exact pre-Module-II management behavior for already persisted issuers, while
-- requiring every issuer created after this migration to opt into a typed capability ceiling.
UPDATE external_identity_issuers
SET management_capability_ceiling = '[
    "system_administration", "read_organization", "update_organization", "read_members",
    "manage_members", "manage_owners", "read_management_keys", "create_management_keys",
    "manage_management_keys", "update_api_key_policy", "read_audit", "manage_identity",
    "manage_system_keys", "manage_system_organizations", "manage_system_users",
    "manage_administrators", "read_operations", "recover_operations"
]'::jsonb
WHERE jwt_capability_ceiling ? 'management:access';

-- Module I stored LLM scopes in the coarse capability array. Normalize those values into the
-- dedicated closed scope ceiling and retain only explicit coarse access classes.
UPDATE external_identity_issuers
SET llm_scope_ceiling = (
    SELECT COALESCE(jsonb_agg(DISTINCT value ORDER BY value), '[]'::jsonb)
    FROM jsonb_array_elements_text(jwt_capability_ceiling) AS capability(value)
    WHERE value IN (
        'llm:invoke', 'llm:stream', 'llm:tools',
        'llm:multimodal-input', 'llm:structured-output'
    )
);
UPDATE external_identity_issuers
SET jwt_capability_ceiling = (
    SELECT COALESCE(jsonb_agg(DISTINCT normalized_value ORDER BY normalized_value), '[]'::jsonb)
    FROM (
        SELECT CASE
            WHEN value = 'management:access' THEN value
            WHEN value = 'llm:access' THEN value
            WHEN value = 'llm:invoke' THEN 'llm:access'
        END AS normalized_value
        FROM jsonb_array_elements_text(jwt_capability_ceiling) AS capability(value)
    ) legacy
    WHERE normalized_value IS NOT NULL
);

CREATE TABLE egress_network_policies (
    id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 160),
    dns_policy jsonb NOT NULL CHECK (jsonb_typeof(dns_policy) = 'object'),
    address_policy jsonb NOT NULL CHECK (jsonb_typeof(address_policy) = 'object'),
    proxy_url text CHECK (proxy_url IS NULL OR char_length(proxy_url) BETWEEN 8 AND 2048),
    tls_policy jsonb NOT NULL CHECK (jsonb_typeof(tls_policy) = 'object'),
    custom_ca_secret_id uuid REFERENCES protected_secret_versions(id) ON DELETE RESTRICT,
    custom_ca_generation bigint NOT NULL DEFAULT 0 CHECK (custom_ca_generation >= 0),
    redirect_policy jsonb NOT NULL CHECK (jsonb_typeof(redirect_policy) = 'object'),
    connection_policy jsonb NOT NULL CHECK (jsonb_typeof(connection_policy) = 'object'),
    body_policy jsonb NOT NULL CHECK (jsonb_typeof(body_policy) = 'object'),
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    config_version bigint NOT NULL DEFAULT 1 CHECK (config_version > 0),
    created_by_principal jsonb NOT NULL,
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((custom_ca_secret_id IS NULL AND custom_ca_generation = 0)
        OR (custom_ca_secret_id IS NOT NULL AND custom_ca_generation > 0))
);
CREATE INDEX egress_network_policies_status_idx ON egress_network_policies(status, id);

CREATE OR REPLACE FUNCTION reject_protected_secret_version_change()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'protected secret versions are immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER protected_secret_versions_immutable
    BEFORE UPDATE ON protected_secret_versions
    FOR EACH ROW EXECUTE FUNCTION reject_protected_secret_version_change();

CREATE TABLE upstream_credentials (
    id uuid PRIMARY KEY,
    resource_scope_kind text NOT NULL CHECK (resource_scope_kind IN ('deployment', 'organization')),
    organization_id uuid REFERENCES organizations(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 160),
    credential_kind text NOT NULL CHECK (credential_kind IN (
        'static_api_key', 'oauth_openai_codex', 'aws_default_chain', 'aws_assume_role',
        'google_application_default', 'google_service_account', 'azure_api_key',
        'azure_workload_identity'
    )),
    secret_source_kind text NOT NULL CHECK (secret_source_kind IN (
        'encrypted_database', 'environment_reference', 'mounted_file_reference', 'workload_identity'
    )),
    source_configuration jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(source_configuration) = 'object'),
    injection_kind text NOT NULL CHECK (injection_kind IN (
        'bearer', 'x_api_key', 'api_key_header', 'aws_sigv4', 'google_oauth', 'azure_bearer'
    )),
    sharing_policy text NOT NULL CHECK (sharing_policy IN ('exclusive', 'same_scope_reusable')),
    administrative_status text NOT NULL CHECK (administrative_status IN ('active', 'disabled', 'revoked')),
    authentication_status text NOT NULL CHECK (authentication_status IN (
        'unvalidated', 'ready', 'login_required', 'login_pending', 'refresh_due', 'refreshing',
        'refresh_error', 'refresh_outcome_unknown', 'invalid', 'expired', 'revoked'
    )),
    current_secret_version bigint CHECK (current_secret_version IS NULL OR current_secret_version > 0),
    state_identity_version bigint NOT NULL DEFAULT 1 CHECK (state_identity_version > 0),
    safe_metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(safe_metadata) = 'object'),
    validation_evidence jsonb CHECK (validation_evidence IS NULL OR jsonb_typeof(validation_evidence) = 'object'),
    created_by_principal jsonb NOT NULL,
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    validated_at timestamptz,
    CHECK (
        (resource_scope_kind = 'deployment' AND organization_id IS NULL)
        OR (resource_scope_kind = 'organization' AND organization_id IS NOT NULL)
    ),
    CHECK (
        resource_scope_kind = 'deployment'
        OR (secret_source_kind = 'encrypted_database' AND credential_kind IN ('static_api_key', 'azure_api_key'))
    ),
    UNIQUE (organization_id, id),
    UNIQUE (resource_scope_kind, organization_id, name)
);
CREATE UNIQUE INDEX upstream_credentials_deployment_name_idx
    ON upstream_credentials(name) WHERE organization_id IS NULL;
CREATE INDEX upstream_credentials_scope_status_idx
    ON upstream_credentials(organization_id, administrative_status, id);

CREATE OR REPLACE FUNCTION reject_upstream_credential_identity_change()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.resource_scope_kind IS DISTINCT FROM OLD.resource_scope_kind
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.credential_kind IS DISTINCT FROM OLD.credential_kind
       OR NEW.secret_source_kind IS DISTINCT FROM OLD.secret_source_kind
       OR NEW.injection_kind IS DISTINCT FROM OLD.injection_kind THEN
        RAISE EXCEPTION 'upstream credential identity fields are immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER upstream_credentials_identity_immutable
    BEFORE UPDATE ON upstream_credentials
    FOR EACH ROW EXECUTE FUNCTION reject_upstream_credential_identity_change();

CREATE TABLE upstream_credential_secret_versions (
    id uuid PRIMARY KEY,
    credential_id uuid NOT NULL REFERENCES upstream_credentials(id) ON DELETE RESTRICT,
    version bigint NOT NULL CHECK (version > 0),
    credential_state_identity_version bigint NOT NULL CHECK (credential_state_identity_version > 0),
    protected_secret_version_id uuid REFERENCES protected_secret_versions(id) ON DELETE RESTRICT,
    source_configuration jsonb CHECK (source_configuration IS NULL OR jsonb_typeof(source_configuration) = 'object'),
    safe_fingerprint bytea NOT NULL CHECK (octet_length(safe_fingerprint) = 32),
    state text NOT NULL CHECK (state IN ('current', 'overlap', 'retired')),
    overlap_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz,
    CHECK (
        (state IN ('current', 'overlap')
         AND ((protected_secret_version_id IS NULL) <> (source_configuration IS NULL)))
        OR (state = 'retired' AND NOT (
            protected_secret_version_id IS NOT NULL AND source_configuration IS NOT NULL
        ))
    ),
    CHECK ((state = 'overlap' AND overlap_until IS NOT NULL) OR (state <> 'overlap' AND overlap_until IS NULL)),
    UNIQUE (credential_id, version),
    UNIQUE (credential_id, id)
);
CREATE UNIQUE INDEX upstream_credential_secret_one_current_idx
    ON upstream_credential_secret_versions(credential_id) WHERE state = 'current';
CREATE UNIQUE INDEX upstream_credential_secret_one_overlap_idx
    ON upstream_credential_secret_versions(credential_id) WHERE state = 'overlap';
ALTER TABLE upstream_credentials
    ADD CONSTRAINT upstream_credentials_current_secret_fk
    FOREIGN KEY (id, current_secret_version)
    REFERENCES upstream_credential_secret_versions(credential_id, version)
    DEFERRABLE INITIALLY DEFERRED;

CREATE OR REPLACE FUNCTION validate_upstream_credential_protected_secret()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    credential_record record;
    protected_record record;
BEGIN
    SELECT * INTO credential_record FROM upstream_credentials WHERE id = NEW.credential_id;
    IF NEW.protected_secret_version_id IS NULL THEN
        IF credential_record.secret_source_kind = 'encrypted_database' AND NEW.state <> 'retired' THEN
            RAISE EXCEPTION 'active database credential version requires a protected secret';
        END IF;
        RETURN NEW;
    END IF;
    SELECT * INTO protected_record FROM protected_secret_versions WHERE id = NEW.protected_secret_version_id;
    IF credential_record.secret_source_kind <> 'encrypted_database'
       OR protected_record.owner_kind <> 'upstream_credential'
       OR NEW.credential_state_identity_version <> credential_record.state_identity_version
       OR protected_record.owner_id <> NEW.credential_id
       OR protected_record.owner_generation <> NEW.credential_state_identity_version
       OR protected_record.secret_version <> NEW.version
       OR protected_record.field_purpose <> 'upstream_credential_material'
       OR protected_record.scope_kind <> (CASE credential_record.resource_scope_kind
            WHEN 'deployment' THEN 'system' ELSE 'organization' END)
       OR protected_record.organization_id IS DISTINCT FROM credential_record.organization_id THEN
        RAISE EXCEPTION 'protected upstream secret owner/scope/version does not match credential';
    END IF;
    RETURN NEW;
END;
$$;
CREATE CONSTRAINT TRIGGER upstream_credential_secret_owner_scope
    AFTER INSERT OR UPDATE ON upstream_credential_secret_versions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_upstream_credential_protected_secret();

CREATE OR REPLACE FUNCTION validate_upstream_credential_selected_secret()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.current_secret_version IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM upstream_credential_secret_versions selected
        WHERE selected.credential_id = NEW.id
          AND selected.version = NEW.current_secret_version
          AND selected.state = 'current'
          AND selected.credential_state_identity_version = NEW.state_identity_version
    ) THEN
        RAISE EXCEPTION 'selected upstream secret does not match credential state identity';
    END IF;
    RETURN NEW;
END;
$$;
CREATE CONSTRAINT TRIGGER upstream_credentials_selected_secret_identity
    AFTER INSERT OR UPDATE ON upstream_credentials
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_upstream_credential_selected_secret();

CREATE OR REPLACE FUNCTION validate_selected_upstream_credential_secret_reverse()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM upstream_credentials credential
        WHERE credential.id = OLD.credential_id
          AND credential.current_secret_version IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM upstream_credential_secret_versions selected
              WHERE selected.credential_id = credential.id
                AND selected.version = credential.current_secret_version
                AND selected.state = 'current'
                AND selected.credential_state_identity_version = credential.state_identity_version
          )
    ) THEN
        RAISE EXCEPTION 'selected upstream secret does not match credential state identity';
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.credential_id IS DISTINCT FROM OLD.credential_id AND EXISTS (
        SELECT 1 FROM upstream_credentials credential
        WHERE credential.id = NEW.credential_id
          AND credential.current_secret_version IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM upstream_credential_secret_versions selected
              WHERE selected.credential_id = credential.id
                AND selected.version = credential.current_secret_version
                AND selected.state = 'current'
                AND selected.credential_state_identity_version = credential.state_identity_version
          )
    ) THEN
        RAISE EXCEPTION 'selected upstream secret does not match credential state identity';
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$;
CREATE CONSTRAINT TRIGGER upstream_credential_secret_selected_reverse
    AFTER UPDATE OR DELETE ON upstream_credential_secret_versions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_selected_upstream_credential_secret_reverse();

CREATE TABLE upstream_credential_auth_state (
    credential_id uuid PRIMARY KEY REFERENCES upstream_credentials(id) ON DELETE RESTRICT,
    credential_state_identity_version bigint NOT NULL CHECK (credential_state_identity_version > 0),
    token_fingerprint bytea CHECK (token_fingerprint IS NULL OR octet_length(token_fingerprint) = 32),
    token_expires_at timestamptz,
    refresh_due_at timestamptz,
    refresh_backoff_until timestamptz,
    refresh_failure_count integer NOT NULL DEFAULT 0 CHECK (refresh_failure_count >= 0),
    last_safe_error jsonb CHECK (last_safe_error IS NULL OR jsonb_typeof(last_safe_error) = 'object'),
    refresh_fence bigint NOT NULL DEFAULT 0 CHECK (refresh_fence >= 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX upstream_credential_auth_refresh_due_idx
    ON upstream_credential_auth_state(refresh_due_at, credential_id)
    WHERE refresh_due_at IS NOT NULL;

CREATE TABLE upstream_credential_login_sessions (
    id uuid PRIMARY KEY,
    credential_id uuid NOT NULL REFERENCES upstream_credentials(id) ON DELETE RESTRICT,
    credential_state_identity_version bigint NOT NULL CHECK (credential_state_identity_version > 0),
    state text NOT NULL CHECK (state IN (
        'pending', 'polling', 'exchanging', 'completed', 'cancelled', 'expired', 'failed'
    )),
    attempt_token uuid,
    claim_expires_at timestamptz,
    login_secret_id uuid REFERENCES protected_secret_versions(id) ON DELETE RESTRICT,
    safe_display jsonb NOT NULL CHECK (jsonb_typeof(safe_display) = 'object'),
    poll_interval_seconds integer NOT NULL CHECK (poll_interval_seconds BETWEEN 1 AND 300),
    expires_at timestamptz NOT NULL,
    next_poll_at timestamptz,
    terminal_cleanup_at timestamptz,
    created_by_principal jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((state IN ('polling', 'exchanging')) = (attempt_token IS NOT NULL)),
    CHECK ((state IN ('polling', 'exchanging')) = (claim_expires_at IS NOT NULL))
);
CREATE UNIQUE INDEX upstream_credential_login_one_active_idx
    ON upstream_credential_login_sessions(credential_id)
    WHERE state IN ('pending', 'polling', 'exchanging');
CREATE INDEX upstream_credential_login_due_idx
    ON upstream_credential_login_sessions(next_poll_at, id)
    WHERE state = 'pending';
CREATE INDEX upstream_credential_login_claim_expiry_idx
    ON upstream_credential_login_sessions(claim_expires_at, id)
    WHERE state IN ('polling', 'exchanging');
CREATE INDEX upstream_credential_login_session_expiry_idx
    ON upstream_credential_login_sessions(expires_at, id)
    WHERE state IN ('pending', 'polling');

CREATE OR REPLACE FUNCTION validate_upstream_login_secret()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    credential_record record;
    protected_record record;
BEGIN
    SELECT * INTO credential_record FROM upstream_credentials WHERE id = NEW.credential_id;
    IF credential_record.resource_scope_kind <> 'deployment'
       OR credential_record.credential_kind <> 'oauth_openai_codex'
       OR credential_record.secret_source_kind <> 'encrypted_database' THEN
        RAISE EXCEPTION 'login session requires a deployment Codex credential';
    END IF;
    IF NEW.state IN ('pending', 'polling', 'exchanging')
       AND NEW.credential_state_identity_version <> credential_record.state_identity_version THEN
        RAISE EXCEPTION 'active login session is fenced by a stale credential identity';
    END IF;
    IF NEW.login_secret_id IS NULL THEN
        IF NEW.state IN ('pending', 'polling', 'exchanging') THEN
            RAISE EXCEPTION 'active login session requires protected polling material';
        END IF;
        RETURN NEW;
    END IF;
    SELECT * INTO protected_record FROM protected_secret_versions WHERE id = NEW.login_secret_id;
    IF protected_record.scope_kind <> 'system'
       OR protected_record.organization_id IS NOT NULL
       OR protected_record.owner_kind <> 'upstream_credential_login_session'
       OR protected_record.owner_id <> NEW.id
       OR protected_record.owner_generation <> NEW.credential_state_identity_version
       OR protected_record.secret_version <> 1
       OR protected_record.field_purpose <> 'codex_device_login_material' THEN
        RAISE EXCEPTION 'protected Codex login secret owner/scope/version does not match session';
    END IF;
    RETURN NEW;
END;
$$;
CREATE CONSTRAINT TRIGGER upstream_credential_login_secret_owner_scope
    AFTER INSERT OR UPDATE ON upstream_credential_login_sessions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_upstream_login_secret();

CREATE TABLE upstream_credential_refresh_leases (
    id uuid PRIMARY KEY,
    credential_id uuid NOT NULL REFERENCES upstream_credentials(id) ON DELETE RESTRICT,
    credential_state_identity_version bigint NOT NULL CHECK (credential_state_identity_version > 0),
    secret_version bigint NOT NULL,
    token_fingerprint bytea CHECK (token_fingerprint IS NULL OR octet_length(token_fingerprint) = 32),
    refresh_fence bigint NOT NULL CHECK (refresh_fence > 0),
    attempt_token uuid NOT NULL UNIQUE,
    state text NOT NULL CHECK (state IN ('refreshing', 'known_success', 'known_failure', 'outcome_unknown')),
    lease_owner text NOT NULL CHECK (char_length(lease_owner) BETWEEN 1 AND 160),
    lease_expires_at timestamptz NOT NULL,
    network_deadline timestamptz NOT NULL,
    safe_outcome jsonb CHECK (safe_outcome IS NULL OR jsonb_typeof(safe_outcome) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    FOREIGN KEY (credential_id, secret_version)
        REFERENCES upstream_credential_secret_versions(credential_id, version) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX upstream_credential_refresh_one_active_idx
    ON upstream_credential_refresh_leases(credential_id) WHERE state = 'refreshing';
CREATE INDEX upstream_credential_refresh_lease_expiry_idx
    ON upstream_credential_refresh_leases(lease_expires_at, id) WHERE state = 'refreshing';

CREATE OR REPLACE FUNCTION validate_upstream_credential_auth_state()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM upstream_credentials credential
        WHERE credential.id=NEW.credential_id
          AND credential.resource_scope_kind='deployment'
          AND credential.credential_kind='oauth_openai_codex'
          AND credential.secret_source_kind='encrypted_database'
          AND credential.state_identity_version=NEW.credential_state_identity_version
    ) THEN
        RAISE EXCEPTION 'Codex auth state does not match credential identity';
    END IF;
    RETURN NEW;
END;
$$;
CREATE CONSTRAINT TRIGGER upstream_credential_auth_state_identity
    AFTER INSERT OR UPDATE ON upstream_credential_auth_state
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_upstream_credential_auth_state();

CREATE OR REPLACE FUNCTION validate_upstream_credential_refresh_lease()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.state <> 'refreshing' THEN
        RETURN NEW;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM upstream_credentials credential
        JOIN upstream_credential_secret_versions secret
          ON secret.credential_id=credential.id AND secret.version=NEW.secret_version
        WHERE credential.id=NEW.credential_id
          AND credential.resource_scope_kind='deployment'
          AND credential.credential_kind='oauth_openai_codex'
          AND credential.secret_source_kind='encrypted_database'
          AND credential.state_identity_version=NEW.credential_state_identity_version
          AND secret.credential_state_identity_version=NEW.credential_state_identity_version
    ) THEN
        RAISE EXCEPTION 'Codex refresh lease does not match credential identity';
    END IF;
    RETURN NEW;
END;
$$;
CREATE CONSTRAINT TRIGGER upstream_credential_refresh_lease_identity
    AFTER INSERT OR UPDATE ON upstream_credential_refresh_leases
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_upstream_credential_refresh_lease();

CREATE TABLE upstream_endpoints (
    id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 160),
    adapter_kind text NOT NULL CHECK (adapter_kind IN (
        'anthropic_api', 'aws_bedrock_runtime', 'google_vertex', 'google_gemini_api',
        'openai_api', 'openai_codex', 'azure_openai'
    )),
    base_url text NOT NULL CHECK (char_length(base_url) BETWEEN 8 AND 2048),
    region text CHECK (region IS NULL OR char_length(region) BETWEEN 1 AND 128),
    api_version text CHECK (api_version IS NULL OR char_length(api_version) BETWEEN 1 AND 128),
    network_policy_id uuid NOT NULL REFERENCES egress_network_policies(id) ON DELETE RESTRICT,
    safe_headers jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(safe_headers) = 'object'),
    status text NOT NULL CHECK (status IN ('active', 'disabled', 'validation_failed')),
    config_version bigint NOT NULL DEFAULT 1 CHECK (config_version > 0),
    validation_evidence jsonb CHECK (validation_evidence IS NULL OR jsonb_typeof(validation_evidence) = 'object'),
    created_by_principal jsonb NOT NULL,
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    validated_at timestamptz,
    CHECK (
        adapter_kind <> 'openai_codex'
        OR base_url = 'https://chatgpt.com/backend-api/codex'
    )
);
CREATE INDEX upstream_endpoints_status_idx ON upstream_endpoints(status, id);

CREATE OR REPLACE FUNCTION validate_egress_custom_ca_secret()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    protected_record record;
BEGIN
    IF NEW.custom_ca_secret_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT * INTO protected_record FROM protected_secret_versions WHERE id = NEW.custom_ca_secret_id;
    IF protected_record.scope_kind <> 'system'
       OR protected_record.organization_id IS NOT NULL
       OR protected_record.owner_kind <> 'egress_network_policy'
       OR protected_record.owner_id <> NEW.id
       OR protected_record.owner_generation <> NEW.custom_ca_generation
       OR protected_record.secret_version <> NEW.custom_ca_generation
       OR protected_record.field_purpose <> 'custom_ca_bundle' THEN
        RAISE EXCEPTION 'protected custom CA owner/scope/version does not match egress policy';
    END IF;
    RETURN NEW;
END;
$$;
CREATE CONSTRAINT TRIGGER egress_custom_ca_owner_scope
    AFTER INSERT OR UPDATE ON egress_network_policies
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_egress_custom_ca_secret();

CREATE TABLE pricing_policies (
    id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 160),
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    desired_version_id uuid,
    current_version_id uuid,
    created_by_principal jsonb NOT NULL,
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, desired_version_id),
    UNIQUE (id, current_version_id)
);

CREATE TABLE pricing_policy_versions (
    id uuid PRIMARY KEY,
    pricing_policy_id uuid NOT NULL REFERENCES pricing_policies(id) ON DELETE RESTRICT,
    generation bigint NOT NULL CHECK (generation > 0),
    rates jsonb NOT NULL CHECK (jsonb_typeof(rates) = 'object'),
    rounding_policy jsonb NOT NULL CHECK (jsonb_typeof(rounding_policy) = 'object'),
    organization_usable boolean NOT NULL DEFAULT false,
    publication_evidence jsonb NOT NULL CHECK (jsonb_typeof(publication_evidence) = 'object'),
    created_by_principal jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (pricing_policy_id, generation),
    UNIQUE (pricing_policy_id, id)
);
CREATE TRIGGER pricing_policy_versions_immutable
    BEFORE UPDATE OR DELETE ON pricing_policy_versions
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
ALTER TABLE pricing_policies
    ADD CONSTRAINT pricing_policies_desired_version_fk
    FOREIGN KEY (id, desired_version_id)
    REFERENCES pricing_policy_versions(pricing_policy_id, id)
    DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT pricing_policies_current_version_fk
    FOREIGN KEY (id, current_version_id)
    REFERENCES pricing_policy_versions(pricing_policy_id, id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE reliability_policies (
    id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 160),
    attempt_policy jsonb NOT NULL CHECK (jsonb_typeof(attempt_policy) = 'object'),
    deadline_policy jsonb NOT NULL CHECK (jsonb_typeof(deadline_policy) = 'object'),
    retry_policy jsonb NOT NULL CHECK (jsonb_typeof(retry_policy) = 'object'),
    failover_policy jsonb NOT NULL CHECK (jsonb_typeof(failover_policy) = 'object'),
    commitment_policy jsonb NOT NULL CHECK (jsonb_typeof(commitment_policy) = 'object'),
    health_policy jsonb NOT NULL CHECK (jsonb_typeof(health_policy) = 'object'),
    circuit_policy jsonb NOT NULL CHECK (jsonb_typeof(circuit_policy) = 'object'),
    probe_policy jsonb NOT NULL CHECK (jsonb_typeof(probe_policy) = 'object'),
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    config_version bigint NOT NULL DEFAULT 1 CHECK (config_version > 0),
    created_by_principal jsonb NOT NULL,
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE model_deployments (
    id uuid PRIMARY KEY,
    resource_scope_kind text NOT NULL CHECK (resource_scope_kind IN ('deployment', 'organization')),
    organization_id uuid REFERENCES organizations(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 160),
    endpoint_id uuid NOT NULL REFERENCES upstream_endpoints(id) ON DELETE RESTRICT,
    credential_id uuid NOT NULL REFERENCES upstream_credentials(id) ON DELETE RESTRICT,
    transport_kind text NOT NULL CHECK (transport_kind IN (
        'anthropic_messages_native', 'anthropic_messages_bedrock', 'anthropic_messages_vertex',
        'openai_chat_completions', 'openai_responses_http', 'openai_responses_websocket',
        'openai_codex_responses', 'azure_openai_chat_completions', 'azure_openai_responses',
        'google_gemini_generate_content', 'google_vertex_generate_content'
    )),
    upstream_model_id text NOT NULL CHECK (char_length(upstream_model_id) BETWEEN 1 AND 512),
    model_family text CHECK (model_family IS NULL OR char_length(model_family) BETWEEN 1 AND 160),
    capability_set jsonb NOT NULL CHECK (jsonb_typeof(capability_set) = 'array'),
    context_limits jsonb NOT NULL CHECK (jsonb_typeof(context_limits) = 'object'),
    state_isolation_profile jsonb NOT NULL CHECK (jsonb_typeof(state_isolation_profile) = 'object'),
    pricing_policy_version_id uuid REFERENCES pricing_policy_versions(id) ON DELETE RESTRICT,
    unpriced boolean NOT NULL DEFAULT false,
    status text NOT NULL CHECK (status IN ('active', 'disabled', 'validation_failed')),
    config_version bigint NOT NULL DEFAULT 1 CHECK (config_version > 0),
    validation_evidence jsonb CHECK (validation_evidence IS NULL OR jsonb_typeof(validation_evidence) = 'object'),
    created_by_principal jsonb NOT NULL,
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    validated_at timestamptz,
    CHECK (
        (resource_scope_kind = 'deployment' AND organization_id IS NULL)
        OR (resource_scope_kind = 'organization' AND organization_id IS NOT NULL)
    ),
    CHECK (unpriced <> (pricing_policy_version_id IS NOT NULL)),
    UNIQUE (organization_id, id),
    UNIQUE (resource_scope_kind, organization_id, name)
);
CREATE UNIQUE INDEX model_deployments_deployment_name_idx
    ON model_deployments(name) WHERE organization_id IS NULL;
CREATE INDEX model_deployments_scope_status_idx
    ON model_deployments(organization_id, status, id);

CREATE OR REPLACE FUNCTION reject_model_deployment_identity_change()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.resource_scope_kind IS DISTINCT FROM OLD.resource_scope_kind
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.endpoint_id IS DISTINCT FROM OLD.endpoint_id
       OR NEW.credential_id IS DISTINCT FROM OLD.credential_id
       OR NEW.transport_kind IS DISTINCT FROM OLD.transport_kind
       OR NEW.upstream_model_id IS DISTINCT FROM OLD.upstream_model_id THEN
        RAISE EXCEPTION 'model deployment identity/binding fields are immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER model_deployments_identity_immutable
    BEFORE UPDATE ON model_deployments
    FOR EACH ROW EXECUTE FUNCTION reject_model_deployment_identity_change();

CREATE TABLE model_routes (
    id uuid PRIMARY KEY,
    resource_scope_kind text NOT NULL CHECK (resource_scope_kind IN ('deployment', 'organization')),
    organization_id uuid REFERENCES organizations(id) ON DELETE RESTRICT,
    owner_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    owner_membership_id uuid,
    model_key text NOT NULL CHECK (char_length(model_key) BETWEEN 1 AND 512),
    ingress_protocol_family text NOT NULL CHECK (ingress_protocol_family IN (
        'anthropic_messages', 'openai_chat_completions', 'openai_responses', 'google_gemini'
    )),
    required_base_capabilities jsonb NOT NULL CHECK (jsonb_typeof(required_base_capabilities) = 'array'),
    selection_policy jsonb NOT NULL CHECK (jsonb_typeof(selection_policy) = 'object'),
    reliability_policy_id uuid NOT NULL REFERENCES reliability_policies(id) ON DELETE RESTRICT,
    request_policy jsonb NOT NULL CHECK (jsonb_typeof(request_policy) = 'object'),
    status text NOT NULL CHECK (status IN ('draft', 'active', 'disabled')),
    config_version bigint NOT NULL DEFAULT 1 CHECK (config_version > 0),
    created_by_principal jsonb NOT NULL,
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (resource_scope_kind = 'deployment' AND organization_id IS NULL AND owner_user_id IS NULL AND owner_membership_id IS NULL)
        OR (resource_scope_kind = 'organization' AND organization_id IS NOT NULL AND owner_user_id IS NOT NULL AND owner_membership_id IS NOT NULL)
    ),
    FOREIGN KEY (organization_id, owner_membership_id, owner_user_id)
        REFERENCES memberships(organization_id, id, user_id) ON DELETE RESTRICT,
    UNIQUE (organization_id, id)
);
CREATE UNIQUE INDEX model_routes_deployment_namespace_idx
    ON model_routes(ingress_protocol_family, model_key) WHERE organization_id IS NULL;
CREATE UNIQUE INDEX model_routes_organization_namespace_idx
    ON model_routes(organization_id, ingress_protocol_family, model_key) WHERE organization_id IS NOT NULL;
CREATE INDEX model_routes_scope_status_idx ON model_routes(organization_id, status, id);

CREATE OR REPLACE FUNCTION reject_model_route_identity_change()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.resource_scope_kind IS DISTINCT FROM OLD.resource_scope_kind
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.model_key IS DISTINCT FROM OLD.model_key
       OR NEW.ingress_protocol_family IS DISTINCT FROM OLD.ingress_protocol_family THEN
        RAISE EXCEPTION 'model route namespace/scope fields are immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER model_routes_identity_immutable
    BEFORE UPDATE ON model_routes
    FOR EACH ROW EXECUTE FUNCTION reject_model_route_identity_change();

CREATE OR REPLACE FUNCTION validate_model_route_owner_membership()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    checked_route_id uuid;
    checked_membership_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'model_routes' THEN
        checked_route_id := COALESCE(NEW.id, OLD.id);
    ELSE
        checked_membership_id := COALESCE(NEW.id, OLD.id);
    END IF;
    IF EXISTS (
        SELECT 1 FROM model_routes route
        LEFT JOIN memberships membership
          ON membership.id = route.owner_membership_id
         AND membership.organization_id = route.organization_id
         AND membership.user_id = route.owner_user_id
         AND membership.status = 'active'
        WHERE route.resource_scope_kind = 'organization'
          AND (checked_route_id IS NULL OR route.id = checked_route_id)
          AND (checked_membership_id IS NULL OR route.owner_membership_id = checked_membership_id)
          AND membership.id IS NULL
    ) THEN
        RAISE EXCEPTION 'organization route owner must be the exact active membership';
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$;
CREATE CONSTRAINT TRIGGER model_routes_active_owner_membership
    AFTER INSERT OR UPDATE ON model_routes
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_model_route_owner_membership();

CREATE TABLE retired_route_target_identities (
    target_id uuid PRIMARY KEY,
    affinity_identity bytea NOT NULL UNIQUE CHECK (octet_length(affinity_identity) = 16),
    route_id uuid NOT NULL,
    deployment_id uuid NOT NULL,
    retired_at timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER retired_route_target_identities_immutable
    BEFORE UPDATE OR DELETE ON retired_route_target_identities
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();

CREATE TABLE route_targets (
    id uuid PRIMARY KEY,
    route_id uuid NOT NULL REFERENCES model_routes(id) ON DELETE RESTRICT,
    deployment_id uuid NOT NULL REFERENCES model_deployments(id) ON DELETE RESTRICT,
    affinity_identity bytea NOT NULL UNIQUE CHECK (octet_length(affinity_identity) = 16),
    priority smallint NOT NULL CHECK (priority BETWEEN 0 AND 255),
    weight smallint NOT NULL CHECK (weight BETWEEN 1 AND 256),
    enabled boolean NOT NULL DEFAULT true,
    narrowing_constraints jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(narrowing_constraints) = 'object'),
    timeout_overrides jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(timeout_overrides) = 'object'),
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (route_id, deployment_id)
);
CREATE INDEX route_targets_route_tier_idx ON route_targets(route_id, enabled, priority, id);

CREATE OR REPLACE FUNCTION reject_route_target_identity_change()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.route_id IS DISTINCT FROM OLD.route_id
       OR NEW.deployment_id IS DISTINCT FROM OLD.deployment_id
       OR NEW.affinity_identity IS DISTINCT FROM OLD.affinity_identity THEN
        RAISE EXCEPTION 'route target binding/affinity fields are immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER route_targets_identity_immutable
    BEFORE UPDATE ON route_targets
    FOR EACH ROW EXECUTE FUNCTION reject_route_target_identity_change();

CREATE TABLE organization_catalog_grant_sets (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    grant_kind text NOT NULL CHECK (grant_kind IN (
        'system_route', 'endpoint', 'deployment', 'reliability_policy'
    )),
    etag_token uuid NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, grant_kind)
);

CREATE OR REPLACE FUNCTION create_organization_catalog_grant_sets()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO organization_catalog_grant_sets(organization_id, grant_kind, etag_token)
    SELECT NEW.id, grant_kind, gen_random_uuid()
    FROM unnest(ARRAY[
        'system_route', 'endpoint', 'deployment', 'reliability_policy'
    ]::text[]) AS grant_kind;
    RETURN NEW;
END;
$$;
CREATE TRIGGER organizations_create_catalog_grant_sets
    AFTER INSERT ON organizations
    FOR EACH ROW EXECUTE FUNCTION create_organization_catalog_grant_sets();
INSERT INTO organization_catalog_grant_sets(organization_id, grant_kind, etag_token)
SELECT organization.id, grant_kind, gen_random_uuid()
FROM organizations organization
CROSS JOIN unnest(ARRAY[
    'system_route', 'endpoint', 'deployment', 'reliability_policy'
]::text[]) AS grant_kind
ON CONFLICT DO NOTHING;

CREATE TABLE organization_route_grants (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    route_id uuid NOT NULL REFERENCES model_routes(id) ON DELETE RESTRICT,
    ceilings jsonb NOT NULL CHECK (jsonb_typeof(ceilings) = 'object'),
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    created_by_principal jsonb NOT NULL,
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, route_id)
);

CREATE TABLE organization_endpoint_grants (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    endpoint_id uuid NOT NULL REFERENCES upstream_endpoints(id) ON DELETE RESTRICT,
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    created_by_principal jsonb NOT NULL,
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, endpoint_id)
);

CREATE TABLE organization_deployment_grants (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    deployment_id uuid NOT NULL REFERENCES model_deployments(id) ON DELETE RESTRICT,
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    created_by_principal jsonb NOT NULL,
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, deployment_id)
);

CREATE TABLE organization_reliability_policy_grants (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    reliability_policy_id uuid NOT NULL REFERENCES reliability_policies(id) ON DELETE RESTRICT,
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    created_by_principal jsonb NOT NULL,
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, reliability_policy_id)
);

CREATE OR REPLACE FUNCTION validate_deployment_resource_grant()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME = 'organization_route_grants' AND NOT EXISTS (
        SELECT 1 FROM model_routes route
        WHERE route.id = (to_jsonb(NEW)->>'route_id')::uuid
          AND route.resource_scope_kind = 'deployment'
    ) THEN
        RAISE EXCEPTION 'organization route grants require a deployment route';
    END IF;
    IF TG_TABLE_NAME = 'organization_deployment_grants' AND NOT EXISTS (
        SELECT 1 FROM model_deployments deployment
        WHERE deployment.id = (to_jsonb(NEW)->>'deployment_id')::uuid
          AND deployment.resource_scope_kind = 'deployment'
    ) THEN
        RAISE EXCEPTION 'organization deployment grants require a deployment resource';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER organization_route_grants_scope
    BEFORE INSERT OR UPDATE ON organization_route_grants
    FOR EACH ROW EXECUTE FUNCTION validate_deployment_resource_grant();
CREATE TRIGGER organization_deployment_grants_scope
    BEFORE INSERT OR UPDATE ON organization_deployment_grants
    FOR EACH ROW EXECUTE FUNCTION validate_deployment_resource_grant();

CREATE OR REPLACE FUNCTION validate_route_target_graph()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    checked_route_id uuid;
    route_record record;
    tier_weight integer;
BEGIN
    IF TG_TABLE_NAME = 'route_targets' THEN
        checked_route_id := COALESCE(NEW.route_id, OLD.route_id);
    ELSE
        checked_route_id := COALESCE(NEW.id, OLD.id);
    END IF;
    SELECT * INTO route_record FROM model_routes WHERE id = checked_route_id;
    IF NOT FOUND THEN
        RETURN COALESCE(NEW, OLD);
    END IF;

    SELECT COALESCE(MAX(total_weight), 0) INTO tier_weight
    FROM (
        SELECT SUM(weight)::integer AS total_weight
        FROM route_targets
        WHERE route_id = checked_route_id
        GROUP BY priority
    ) weighted_tiers;
    IF tier_weight > 256 THEN
        RAISE EXCEPTION 'route target tier weight exceeds 256';
    END IF;

    IF route_record.status = 'active' AND NOT EXISTS (
        SELECT 1 FROM route_targets WHERE route_id = checked_route_id
    ) THEN
        RAISE EXCEPTION 'active route must have at least one structural target';
    END IF;

    IF route_record.resource_scope_kind = 'deployment' AND EXISTS (
        SELECT 1 FROM route_targets target
        JOIN model_deployments deployment ON deployment.id = target.deployment_id
        WHERE target.route_id = checked_route_id
          AND deployment.resource_scope_kind <> 'deployment'
    ) THEN
        RAISE EXCEPTION 'deployment route cannot target an organization deployment';
    END IF;

    IF route_record.resource_scope_kind = 'organization' AND EXISTS (
        SELECT 1 FROM route_targets target
        JOIN model_deployments deployment ON deployment.id = target.deployment_id
        WHERE target.route_id = checked_route_id
          AND (
            (deployment.resource_scope_kind = 'organization' AND deployment.organization_id <> route_record.organization_id)
            OR (deployment.resource_scope_kind = 'deployment' AND NOT EXISTS (
                SELECT 1 FROM organization_deployment_grants grant_row
                WHERE grant_row.organization_id = route_record.organization_id
                  AND grant_row.deployment_id = deployment.id
                  AND grant_row.status = 'active'
            ))
          )
    ) THEN
        RAISE EXCEPTION 'organization route target is outside the organization grant boundary';
    END IF;

    RETURN COALESCE(NEW, OLD);
END;
$$;
CREATE CONSTRAINT TRIGGER route_targets_graph_invariant
    AFTER INSERT OR UPDATE OR DELETE ON route_targets
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_route_target_graph();
CREATE CONSTRAINT TRIGGER model_routes_graph_invariant
    AFTER INSERT OR UPDATE ON model_routes
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_route_target_graph();
CREATE OR REPLACE FUNCTION preserve_route_target_identity()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO retired_route_target_identities(
        target_id, affinity_identity, route_id, deployment_id, retired_at
    ) VALUES (OLD.id, OLD.affinity_identity, OLD.route_id, OLD.deployment_id, now());
    RETURN OLD;
END;
$$;
CREATE TRIGGER route_targets_preserve_identity
    AFTER DELETE ON route_targets
    FOR EACH ROW EXECUTE FUNCTION preserve_route_target_identity();

CREATE OR REPLACE FUNCTION reject_retired_route_target_identity()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM retired_route_target_identities
        WHERE target_id = NEW.id OR affinity_identity = NEW.affinity_identity
    ) THEN
        RAISE EXCEPTION 'retired route target identity cannot be reused';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER route_targets_reuse_guard
    BEFORE INSERT OR UPDATE OF id, affinity_identity ON route_targets
    FOR EACH ROW EXECUTE FUNCTION reject_retired_route_target_identity();

CREATE OR REPLACE FUNCTION validate_catalog_binding()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    credential_record record;
    endpoint_adapter text;
BEGIN
    SELECT * INTO credential_record FROM upstream_credentials WHERE id = NEW.credential_id;
    SELECT adapter_kind INTO endpoint_adapter FROM upstream_endpoints WHERE id = NEW.endpoint_id;

    IF NEW.resource_scope_kind = 'deployment' AND credential_record.resource_scope_kind <> 'deployment' THEN
        RAISE EXCEPTION 'deployment model deployment requires deployment credential';
    END IF;
    IF NEW.resource_scope_kind = 'organization' AND (
        credential_record.resource_scope_kind <> 'organization'
        OR credential_record.organization_id <> NEW.organization_id
    ) THEN
        RAISE EXCEPTION 'organization model deployment requires same-organization credential';
    END IF;
    IF NEW.resource_scope_kind = 'organization' AND NOT EXISTS (
        SELECT 1 FROM organization_endpoint_grants
        WHERE organization_id = NEW.organization_id
          AND endpoint_id = NEW.endpoint_id
          AND status = 'active'
    ) THEN
        RAISE EXCEPTION 'organization model deployment requires an active endpoint grant';
    END IF;

    IF NOT (
        (endpoint_adapter = 'anthropic_api' AND credential_record.credential_kind = 'static_api_key' AND NEW.transport_kind = 'anthropic_messages_native')
        OR (endpoint_adapter = 'aws_bedrock_runtime' AND credential_record.credential_kind IN ('aws_default_chain', 'aws_assume_role') AND NEW.transport_kind = 'anthropic_messages_bedrock')
        OR (endpoint_adapter = 'google_vertex' AND credential_record.credential_kind IN ('google_application_default', 'google_service_account') AND NEW.transport_kind IN ('anthropic_messages_vertex', 'google_vertex_generate_content'))
        OR (endpoint_adapter = 'google_gemini_api' AND credential_record.credential_kind IN ('static_api_key', 'google_application_default', 'google_service_account') AND NEW.transport_kind = 'google_gemini_generate_content')
        OR (endpoint_adapter = 'openai_api' AND credential_record.credential_kind = 'static_api_key' AND NEW.transport_kind IN ('openai_chat_completions', 'openai_responses_http', 'openai_responses_websocket'))
        OR (endpoint_adapter = 'openai_codex' AND credential_record.credential_kind = 'oauth_openai_codex' AND NEW.transport_kind = 'openai_codex_responses')
        OR (endpoint_adapter = 'azure_openai' AND credential_record.credential_kind IN ('azure_api_key', 'azure_workload_identity') AND NEW.transport_kind IN ('azure_openai_chat_completions', 'azure_openai_responses'))
    ) THEN
        RAISE EXCEPTION 'catalog endpoint, credential, and transport tuple is unsupported';
    END IF;
    RETURN NEW;
END;
$$;
CREATE CONSTRAINT TRIGGER model_deployments_catalog_binding
    AFTER INSERT OR UPDATE ON model_deployments
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_catalog_binding();
CREATE TABLE gateway_api_keys (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    issuance_policy_class text NOT NULL CHECK (issuance_policy_class IN ('standard', 'member_self_service')),
    created_by_principal jsonb NOT NULL,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 160),
    key_prefix text NOT NULL CHECK (key_prefix = 'owlrora_llm_v1'),
    lookup_id text NOT NULL UNIQUE CHECK (char_length(lookup_id) BETWEEN 22 AND 43),
    scopes jsonb NOT NULL CHECK (jsonb_typeof(scopes) = 'array' AND scopes ? 'llm:invoke'),
    budget_policy_id uuid NOT NULL,
    rate_policy_id uuid,
    status text NOT NULL CHECK (status IN ('active', 'disabled', 'revoked')),
    expires_at timestamptz,
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, name)
);
CREATE INDEX gateway_api_keys_organization_status_idx
    ON gateway_api_keys(organization_id, status, created_at DESC, id DESC);

CREATE OR REPLACE FUNCTION reject_gateway_key_identity_change()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.issuance_policy_class IS DISTINCT FROM OLD.issuance_policy_class
       OR NEW.key_prefix IS DISTINCT FROM OLD.key_prefix
       OR NEW.budget_policy_id IS DISTINCT FROM OLD.budget_policy_id THEN
        RAISE EXCEPTION 'gateway key organization, issuance class, prefix, and budget identity are immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER gateway_api_keys_identity_immutable
    BEFORE UPDATE ON gateway_api_keys
    FOR EACH ROW EXECUTE FUNCTION reject_gateway_key_identity_change();

CREATE TABLE gateway_api_key_secret_versions (
    id uuid PRIMARY KEY,
    gateway_api_key_id uuid NOT NULL REFERENCES gateway_api_keys(id) ON DELETE RESTRICT,
    lookup_id text NOT NULL UNIQUE CHECK (char_length(lookup_id) BETWEEN 22 AND 43),
    secret_digest bytea NOT NULL CHECK (octet_length(secret_digest) = 32),
    state text NOT NULL CHECK (state IN ('current', 'overlap', 'retired')),
    overlap_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz,
    CHECK ((state = 'overlap' AND overlap_until IS NOT NULL) OR (state <> 'overlap' AND overlap_until IS NULL))
);
CREATE UNIQUE INDEX gateway_key_one_current_idx
    ON gateway_api_key_secret_versions(gateway_api_key_id) WHERE state = 'current';
CREATE UNIQUE INDEX gateway_key_one_overlap_idx
    ON gateway_api_key_secret_versions(gateway_api_key_id) WHERE state = 'overlap';

CREATE OR REPLACE FUNCTION validate_gateway_key_selected_secret()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    checked_key_id uuid;
    current_lookup text;
    current_count integer;
BEGIN
    IF TG_TABLE_NAME = 'gateway_api_keys' THEN
        checked_key_id := COALESCE(NEW.id, OLD.id);
    ELSE
        checked_key_id := COALESCE(NEW.gateway_api_key_id, OLD.gateway_api_key_id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM gateway_api_keys WHERE id = checked_key_id) THEN
        RETURN COALESCE(NEW, OLD);
    END IF;
    SELECT count(*)::integer, min(lookup_id)
      INTO current_count, current_lookup
      FROM gateway_api_key_secret_versions
     WHERE gateway_api_key_id = checked_key_id AND state = 'current';
    IF current_count <> 1 OR NOT EXISTS (
        SELECT 1 FROM gateway_api_keys
         WHERE id = checked_key_id AND lookup_id = current_lookup
    ) THEN
        RAISE EXCEPTION 'gateway key must have exactly one matching current secret lookup';
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$;
CREATE CONSTRAINT TRIGGER gateway_api_keys_selected_secret
    AFTER INSERT OR UPDATE ON gateway_api_keys
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_gateway_key_selected_secret();
CREATE CONSTRAINT TRIGGER gateway_api_key_secret_selected_reverse
    AFTER INSERT OR UPDATE OR DELETE ON gateway_api_key_secret_versions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_gateway_key_selected_secret();

CREATE TABLE gateway_api_key_routes (
    organization_id uuid NOT NULL,
    gateway_api_key_id uuid NOT NULL,
    route_id uuid NOT NULL REFERENCES model_routes(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (gateway_api_key_id, route_id),
    FOREIGN KEY (organization_id, gateway_api_key_id)
        REFERENCES gateway_api_keys(organization_id, id) ON DELETE RESTRICT
);
CREATE INDEX gateway_api_key_routes_route_idx ON gateway_api_key_routes(route_id, gateway_api_key_id);

CREATE OR REPLACE FUNCTION owlrora_uuid_v7()
RETURNS uuid LANGUAGE plpgsql VOLATILE AS $$
DECLARE
    value bytea := uuid_send(gen_random_uuid());
    epoch_millis bigint := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
    value := set_byte(value, 0, ((epoch_millis >> 40) & 255)::integer);
    value := set_byte(value, 1, ((epoch_millis >> 32) & 255)::integer);
    value := set_byte(value, 2, ((epoch_millis >> 24) & 255)::integer);
    value := set_byte(value, 3, ((epoch_millis >> 16) & 255)::integer);
    value := set_byte(value, 4, ((epoch_millis >> 8) & 255)::integer);
    value := set_byte(value, 5, (epoch_millis & 255)::integer);
    value := set_byte(value, 6, (get_byte(value, 6) & 15) | 112);
    value := set_byte(value, 8, (get_byte(value, 8) & 63) | 128);
    RETURN encode(value, 'hex')::uuid;
END;
$$;

CREATE TABLE gateway_policy_ceilings (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    key_budget_max_limit_cost_nanos numeric(38,0) NOT NULL CHECK (key_budget_max_limit_cost_nanos > 0),
    byok_origin_budget_max_limit_cost_nanos numeric(38,0) NOT NULL CHECK (byok_origin_budget_max_limit_cost_nanos > 0),
    max_recovery_incident_cap_nanos numeric(38,0) NOT NULL CHECK (max_recovery_incident_cap_nanos >= 0),
    max_recovery_epoch_cap_nanos numeric(38,0) NOT NULL CHECK (
        max_recovery_epoch_cap_nanos >= max_recovery_incident_cap_nanos
    ),
    max_requests_per_minute integer NOT NULL CHECK (max_requests_per_minute > 0),
    max_input_units_per_minute bigint NOT NULL CHECK (max_input_units_per_minute > 0),
    max_concurrency integer NOT NULL CHECK (max_concurrency > 0),
    max_stream_seconds integer NOT NULL CHECK (max_stream_seconds BETWEEN 1 AND 86400),
    allowed_budget_modes jsonb NOT NULL CHECK (jsonb_typeof(allowed_budget_modes) = 'array'),
    allowed_rate_grant_modes jsonb NOT NULL CHECK (jsonb_typeof(allowed_rate_grant_modes) = 'array'),
    allowed_concurrency_modes jsonb NOT NULL CHECK (jsonb_typeof(allowed_concurrency_modes) = 'array'),
    etag_token uuid NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO gateway_policy_ceilings(
    singleton,key_budget_max_limit_cost_nanos,byok_origin_budget_max_limit_cost_nanos,
    max_recovery_incident_cap_nanos,max_recovery_epoch_cap_nanos,max_requests_per_minute,
    max_input_units_per_minute,max_concurrency,max_stream_seconds,allowed_budget_modes,
    allowed_rate_grant_modes,allowed_concurrency_modes,etag_token
) VALUES (
    true,1000000000000000000,1000000000000000000,10000000000000000,
    50000000000000000,1000000,1000000000000,100000,86400,
    '["enforce","record_only"]','["local_grants","strict"]',
    '["approximate","strict"]',owlrora_uuid_v7()
);

CREATE TABLE gateway_key_budget_policies (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    gateway_api_key_id uuid NOT NULL UNIQUE,
    desired_version_id uuid,
    active_version_id uuid,
    status text NOT NULL CHECK (status IN ('suspended', 'active', 'disabled')),
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, gateway_api_key_id)
        REFERENCES gateway_api_keys(organization_id, id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, gateway_api_key_id, id),
    UNIQUE (id, desired_version_id),
    UNIQUE (id, active_version_id)
);

CREATE TABLE organization_origin_budget_policies (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    origin text NOT NULL CHECK (origin IN ('system_provided', 'organization_byok')),
    desired_version_id uuid,
    active_version_id uuid,
    status text NOT NULL DEFAULT 'suspended' CHECK (status IN ('suspended', 'active', 'disabled')),
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, origin),
    UNIQUE (organization_id, id),
    UNIQUE (id, desired_version_id),
    UNIQUE (id, active_version_id)
);

ALTER TABLE organization_origin_budget_policies
    ADD CONSTRAINT organization_origin_budget_identity_unique
    UNIQUE (organization_id, id, origin);

CREATE TABLE budget_policy_versions (
    id uuid PRIMARY KEY,
    policy_kind text NOT NULL CHECK (policy_kind IN ('gateway_key_budget', 'organization_origin_budget')),
    gateway_key_budget_policy_id uuid REFERENCES gateway_key_budget_policies(id) ON DELETE RESTRICT,
    organization_origin_budget_policy_id uuid REFERENCES organization_origin_budget_policies(id) ON DELETE RESTRICT,
    generation bigint NOT NULL CHECK (generation > 0),
    limit_cost_nanos numeric(38,0) NOT NULL CHECK (limit_cost_nanos >= 0),
    recovery_incident_cap_nanos numeric(38,0) NOT NULL CHECK (
        recovery_incident_cap_nanos >= 0 AND recovery_incident_cap_nanos <= limit_cost_nanos
    ),
    recovery_epoch_cap_nanos numeric(38,0) NOT NULL CHECK (
        recovery_epoch_cap_nanos >= recovery_incident_cap_nanos
        AND recovery_epoch_cap_nanos <= limit_cost_nanos
    ),
    epoch text NOT NULL CHECK (char_length(epoch) BETWEEN 1 AND 160),
    mode text NOT NULL CHECK (mode IN ('enforce', 'record_only')),
    estimate_policy jsonb NOT NULL CHECK (jsonb_typeof(estimate_policy) = 'object'),
    allowance_policy jsonb NOT NULL CHECK (jsonb_typeof(allowance_policy) = 'object'),
    failure_policy jsonb NOT NULL CHECK (jsonb_typeof(failure_policy) = 'object'),
    recovery_policy jsonb NOT NULL CHECK (jsonb_typeof(recovery_policy) = 'object'),
    created_by_principal jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (policy_kind = 'gateway_key_budget' AND gateway_key_budget_policy_id IS NOT NULL AND organization_origin_budget_policy_id IS NULL)
        OR (policy_kind = 'organization_origin_budget' AND gateway_key_budget_policy_id IS NULL AND organization_origin_budget_policy_id IS NOT NULL)
    )
);
CREATE UNIQUE INDEX budget_policy_versions_gateway_generation_idx
    ON budget_policy_versions(gateway_key_budget_policy_id, generation)
    WHERE gateway_key_budget_policy_id IS NOT NULL;
CREATE UNIQUE INDEX budget_policy_versions_origin_generation_idx
    ON budget_policy_versions(organization_origin_budget_policy_id, generation)
    WHERE organization_origin_budget_policy_id IS NOT NULL;
ALTER TABLE budget_policy_versions
    ADD CONSTRAINT budget_policy_versions_gateway_identity_unique
        UNIQUE (gateway_key_budget_policy_id, id),
    ADD CONSTRAINT budget_policy_versions_origin_identity_unique
        UNIQUE (organization_origin_budget_policy_id, id),
    ADD CONSTRAINT budget_policy_versions_gateway_capture_unique
        UNIQUE (gateway_key_budget_policy_id, id, generation, epoch),
    ADD CONSTRAINT budget_policy_versions_origin_capture_unique
        UNIQUE (organization_origin_budget_policy_id, id, generation, epoch);
CREATE TRIGGER budget_policy_versions_immutable
    BEFORE UPDATE OR DELETE ON budget_policy_versions
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
ALTER TABLE gateway_key_budget_policies
    ADD CONSTRAINT gateway_key_budget_desired_version_fk
    FOREIGN KEY (id, desired_version_id)
    REFERENCES budget_policy_versions(gateway_key_budget_policy_id, id)
    DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT gateway_key_budget_active_version_fk
    FOREIGN KEY (id, active_version_id)
    REFERENCES budget_policy_versions(gateway_key_budget_policy_id, id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE organization_origin_budget_policies
    ADD CONSTRAINT origin_budget_desired_version_fk
    FOREIGN KEY (id, desired_version_id)
    REFERENCES budget_policy_versions(organization_origin_budget_policy_id, id)
    DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT origin_budget_active_version_fk
    FOREIGN KEY (id, active_version_id)
    REFERENCES budget_policy_versions(organization_origin_budget_policy_id, id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE gateway_api_keys
    ADD CONSTRAINT gateway_api_keys_budget_policy_fk
    FOREIGN KEY (organization_id, id, budget_policy_id)
    REFERENCES gateway_key_budget_policies(organization_id, gateway_api_key_id, id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE gateway_key_rate_policies (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    gateway_api_key_id uuid NOT NULL UNIQUE,
    desired_version_id uuid,
    active_version_id uuid,
    status text NOT NULL CHECK (status IN ('suspended', 'active', 'disabled')),
    etag_token uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, gateway_api_key_id)
        REFERENCES gateway_api_keys(organization_id, id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, gateway_api_key_id, id),
    UNIQUE (id, desired_version_id),
    UNIQUE (id, active_version_id)
);

CREATE TABLE gateway_key_rate_policy_versions (
    id uuid PRIMARY KEY,
    rate_policy_id uuid NOT NULL REFERENCES gateway_key_rate_policies(id) ON DELETE RESTRICT,
    generation bigint NOT NULL CHECK (generation > 0),
    epoch text NOT NULL CHECK (char_length(epoch) BETWEEN 1 AND 160),
    requests_per_minute integer NOT NULL CHECK (requests_per_minute > 0),
    input_units_per_minute bigint CHECK (input_units_per_minute IS NULL OR input_units_per_minute > 0),
    grant_mode text NOT NULL CHECK (grant_mode IN ('local_grants', 'strict')),
    grant_policy jsonb NOT NULL CHECK (jsonb_typeof(grant_policy) = 'object'),
    concurrency_mode text CHECK (concurrency_mode IS NULL OR concurrency_mode IN ('approximate', 'strict')),
    concurrency_limit integer CHECK (concurrency_limit IS NULL OR concurrency_limit > 0),
    lease_seconds integer CHECK (lease_seconds IS NULL OR lease_seconds BETWEEN 2 AND 90000),
    max_stream_seconds integer NOT NULL CHECK (max_stream_seconds BETWEEN 1 AND 86400),
    created_by_principal jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((concurrency_mode IS NULL) = (concurrency_limit IS NULL)),
    CHECK (
        (concurrency_mode = 'strict' AND lease_seconds > max_stream_seconds)
        OR (concurrency_mode IS DISTINCT FROM 'strict' AND lease_seconds IS NULL)
    ),
    UNIQUE (rate_policy_id, generation),
    UNIQUE (rate_policy_id, id)
);
CREATE TRIGGER gateway_key_rate_policy_versions_immutable
    BEFORE UPDATE OR DELETE ON gateway_key_rate_policy_versions
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
ALTER TABLE gateway_key_rate_policies
    ADD CONSTRAINT gateway_key_rate_desired_version_fk
    FOREIGN KEY (id, desired_version_id)
    REFERENCES gateway_key_rate_policy_versions(rate_policy_id, id)
    DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT gateway_key_rate_active_version_fk
    FOREIGN KEY (id, active_version_id)
    REFERENCES gateway_key_rate_policy_versions(rate_policy_id, id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE gateway_api_keys
    ADD CONSTRAINT gateway_api_keys_rate_policy_fk
    FOREIGN KEY (organization_id, id, rate_policy_id)
    REFERENCES gateway_key_rate_policies(organization_id, gateway_api_key_id, id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE OR REPLACE FUNCTION require_gateway_key_routes()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    checked_key_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'gateway_api_keys' THEN
        checked_key_id := COALESCE(NEW.id, OLD.id);
    ELSE
        checked_key_id := COALESCE(NEW.gateway_api_key_id, OLD.gateway_api_key_id);
    END IF;
    IF EXISTS (SELECT 1 FROM gateway_api_keys WHERE id = checked_key_id AND status = 'active')
       AND NOT EXISTS (SELECT 1 FROM gateway_api_key_routes WHERE gateway_api_key_id = checked_key_id) THEN
        RAISE EXCEPTION 'active gateway key requires a non-empty route allowlist';
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$;
CREATE CONSTRAINT TRIGGER gateway_api_keys_route_invariant
    AFTER INSERT OR UPDATE ON gateway_api_keys
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION require_gateway_key_routes();
CREATE CONSTRAINT TRIGGER gateway_api_key_routes_nonempty_invariant
    AFTER DELETE ON gateway_api_key_routes
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION require_gateway_key_routes();

CREATE OR REPLACE FUNCTION validate_gateway_key_route_scope()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    route_record record;
BEGIN
    SELECT * INTO route_record FROM model_routes WHERE id = NEW.route_id;
    IF route_record.resource_scope_kind = 'organization' AND route_record.organization_id <> NEW.organization_id THEN
        RAISE EXCEPTION 'gateway key route must belong to the same organization';
    END IF;
    IF route_record.resource_scope_kind = 'deployment' AND NOT EXISTS (
        SELECT 1 FROM organization_route_grants
        WHERE organization_id = NEW.organization_id AND route_id = NEW.route_id AND status = 'active'
    ) THEN
        RAISE EXCEPTION 'gateway key system route requires active organization route grant';
    END IF;
    RETURN NEW;
END;
$$;
CREATE CONSTRAINT TRIGGER gateway_api_key_routes_scope_invariant
    AFTER INSERT OR UPDATE ON gateway_api_key_routes
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_gateway_key_route_scope();

CREATE OR REPLACE FUNCTION create_origin_budget_policies()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO organization_origin_budget_policies(
        id, organization_id, origin, status, etag_token
    ) VALUES
        (owlrora_uuid_v7(), NEW.id, 'system_provided', 'suspended', owlrora_uuid_v7()),
        (owlrora_uuid_v7(), NEW.id, 'organization_byok', 'suspended', owlrora_uuid_v7())
    ON CONFLICT (organization_id, origin) DO NOTHING;
    RETURN NEW;
END;
$$;
CREATE TRIGGER organizations_create_origin_budget_policies
    AFTER INSERT ON organizations
    FOR EACH ROW EXECUTE FUNCTION create_origin_budget_policies();
INSERT INTO organization_origin_budget_policies(id, organization_id, origin, status, etag_token)
SELECT owlrora_uuid_v7(), organization.id, origin.value, 'suspended', owlrora_uuid_v7()
FROM organizations organization
CROSS JOIN (VALUES ('system_provided'), ('organization_byok')) AS origin(value)
ON CONFLICT (organization_id, origin) DO NOTHING;

CREATE TABLE policy_activations (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    policy_kind text NOT NULL CHECK (policy_kind IN (
        'gateway_key_budget', 'organization_origin_budget', 'gateway_key_request_limits'
    )),
    policy_id uuid NOT NULL,
    desired_epoch text NOT NULL CHECK (char_length(desired_epoch) BETWEEN 1 AND 160),
    desired_version_id uuid NOT NULL,
    desired_generation bigint NOT NULL CHECK (desired_generation > 0),
    active_epoch text CHECK (active_epoch IS NULL OR char_length(active_epoch) BETWEEN 1 AND 160),
    active_version_id uuid,
    active_generation bigint CHECK (active_generation IS NULL OR active_generation > 0),
    prior_epoch text CHECK (prior_epoch IS NULL OR char_length(prior_epoch) BETWEEN 1 AND 160),
    prior_version_id uuid,
    prior_generation bigint CHECK (prior_generation IS NULL OR prior_generation > 0),
    candidate_fence uuid NOT NULL,
    state text NOT NULL CHECK (state IN (
        'desired', 'coordinator_staged', 'coordinator_armed', 'active', 'finalized',
        'superseded', 'failed'
    )),
    tightening_deadline timestamptz,
    prior_cutoff_at timestamptz,
    safe_error jsonb CHECK (safe_error IS NULL OR jsonb_typeof(safe_error) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (active_version_id IS NULL AND active_generation IS NULL AND active_epoch IS NULL)
        OR (active_version_id IS NOT NULL AND active_generation IS NOT NULL AND active_epoch IS NOT NULL)
    ),
    CHECK (
        (prior_version_id IS NULL AND prior_generation IS NULL AND prior_epoch IS NULL)
        OR (prior_version_id IS NOT NULL AND prior_generation IS NOT NULL AND prior_epoch IS NOT NULL)
    ),
    CHECK (prior_cutoff_at IS NULL OR state IN ('active', 'finalized')),
    UNIQUE (policy_kind, policy_id, desired_generation),
    UNIQUE (id, organization_id)
);
CREATE UNIQUE INDEX policy_activations_one_unfinished_idx
    ON policy_activations(policy_kind, policy_id)
    WHERE state NOT IN ('finalized', 'superseded', 'failed');
CREATE INDEX policy_activations_due_idx
    ON policy_activations(state, tightening_deadline, id)
    WHERE state NOT IN ('finalized', 'superseded', 'failed');

CREATE OR REPLACE FUNCTION validate_policy_activation_identity()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    matches integer;
BEGIN
    IF NEW.policy_kind = 'gateway_key_budget' THEN
        SELECT COUNT(*) INTO matches
        FROM gateway_key_budget_policies policy
        JOIN budget_policy_versions desired
          ON desired.gateway_key_budget_policy_id = policy.id
         AND desired.id = NEW.desired_version_id
         AND desired.generation = NEW.desired_generation
         AND desired.epoch = NEW.desired_epoch
        LEFT JOIN budget_policy_versions active
          ON active.gateway_key_budget_policy_id = policy.id
         AND active.id = NEW.active_version_id
         AND active.generation = NEW.active_generation
         AND active.epoch = NEW.active_epoch
        LEFT JOIN budget_policy_versions prior
          ON prior.gateway_key_budget_policy_id = policy.id
         AND prior.id = NEW.prior_version_id
         AND prior.generation = NEW.prior_generation
         AND prior.epoch = NEW.prior_epoch
        WHERE policy.id = NEW.policy_id
          AND policy.organization_id = NEW.organization_id
          AND (NEW.active_version_id IS NULL OR active.id IS NOT NULL)
          AND (NEW.prior_version_id IS NULL OR prior.id IS NOT NULL);
    ELSIF NEW.policy_kind = 'organization_origin_budget' THEN
        SELECT COUNT(*) INTO matches
        FROM organization_origin_budget_policies policy
        JOIN budget_policy_versions desired
          ON desired.organization_origin_budget_policy_id = policy.id
         AND desired.id = NEW.desired_version_id
         AND desired.generation = NEW.desired_generation
         AND desired.epoch = NEW.desired_epoch
        LEFT JOIN budget_policy_versions active
          ON active.organization_origin_budget_policy_id = policy.id
         AND active.id = NEW.active_version_id
         AND active.generation = NEW.active_generation
         AND active.epoch = NEW.active_epoch
        LEFT JOIN budget_policy_versions prior
          ON prior.organization_origin_budget_policy_id = policy.id
         AND prior.id = NEW.prior_version_id
         AND prior.generation = NEW.prior_generation
         AND prior.epoch = NEW.prior_epoch
        WHERE policy.id = NEW.policy_id
          AND policy.organization_id = NEW.organization_id
          AND (NEW.active_version_id IS NULL OR active.id IS NOT NULL)
          AND (NEW.prior_version_id IS NULL OR prior.id IS NOT NULL);
    ELSE
        SELECT COUNT(*) INTO matches
        FROM gateway_key_rate_policies policy
        JOIN gateway_key_rate_policy_versions desired
          ON desired.rate_policy_id = policy.id
         AND desired.id = NEW.desired_version_id
         AND desired.generation = NEW.desired_generation
         AND desired.epoch = NEW.desired_epoch
        LEFT JOIN gateway_key_rate_policy_versions active
          ON active.rate_policy_id = policy.id
         AND active.id = NEW.active_version_id
         AND active.generation = NEW.active_generation
         AND active.epoch = NEW.active_epoch
        LEFT JOIN gateway_key_rate_policy_versions prior
          ON prior.rate_policy_id = policy.id
         AND prior.id = NEW.prior_version_id
         AND prior.generation = NEW.prior_generation
         AND prior.epoch = NEW.prior_epoch
        WHERE policy.id = NEW.policy_id
          AND policy.organization_id = NEW.organization_id
          AND (NEW.active_version_id IS NULL OR active.id IS NOT NULL)
          AND (NEW.prior_version_id IS NULL OR prior.id IS NOT NULL);
    END IF;
    IF matches <> 1 THEN
        RAISE EXCEPTION 'policy activation identity/version/epoch does not resolve exactly';
    END IF;
    RETURN NEW;
END;
$$;
CREATE CONSTRAINT TRIGGER policy_activations_typed_identity
    AFTER INSERT OR UPDATE ON policy_activations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_policy_activation_identity();

CREATE OR REPLACE FUNCTION validate_policy_activation_transition()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND (
        NEW.id IS DISTINCT FROM OLD.id
        OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
        OR NEW.policy_kind IS DISTINCT FROM OLD.policy_kind
        OR NEW.policy_id IS DISTINCT FROM OLD.policy_id
        OR NEW.desired_epoch IS DISTINCT FROM OLD.desired_epoch
        OR NEW.desired_version_id IS DISTINCT FROM OLD.desired_version_id
        OR NEW.desired_generation IS DISTINCT FROM OLD.desired_generation
        OR NEW.candidate_fence IS DISTINCT FROM OLD.candidate_fence
        OR NEW.tightening_deadline IS DISTINCT FROM OLD.tightening_deadline
    ) THEN
        RAISE EXCEPTION 'policy activation identity and desired candidate are immutable';
    END IF;
    IF TG_OP = 'UPDATE' AND NOT (
        (OLD.state = 'desired' AND NEW.state IN ('coordinator_staged', 'superseded', 'failed'))
        OR (OLD.state = 'coordinator_staged' AND NEW.state IN ('coordinator_armed', 'superseded', 'failed'))
        OR (OLD.state = 'coordinator_armed' AND NEW.state IN ('active', 'superseded', 'failed'))
        OR (OLD.state = 'active' AND NEW.state IN ('finalized', 'superseded', 'failed'))
    ) THEN
        RAISE EXCEPTION 'invalid policy activation state transition';
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.state = 'coordinator_armed' AND NEW.state = 'active' THEN
        IF NEW.active_version_id IS DISTINCT FROM NEW.desired_version_id
           OR NEW.active_generation IS DISTINCT FROM NEW.desired_generation
           OR NEW.active_epoch IS DISTINCT FROM NEW.desired_epoch
           OR NEW.prior_version_id IS DISTINCT FROM OLD.active_version_id
           OR NEW.prior_generation IS DISTINCT FROM OLD.active_generation
           OR NEW.prior_epoch IS DISTINCT FROM OLD.active_epoch THEN
            RAISE EXCEPTION 'active transition must select desired and preserve prior version';
        END IF;
    ELSIF TG_OP = 'UPDATE' AND (
        NEW.active_epoch IS DISTINCT FROM OLD.active_epoch
        OR NEW.active_version_id IS DISTINCT FROM OLD.active_version_id
        OR NEW.active_generation IS DISTINCT FROM OLD.active_generation
        OR NEW.prior_epoch IS DISTINCT FROM OLD.prior_epoch
        OR NEW.prior_version_id IS DISTINCT FROM OLD.prior_version_id
        OR NEW.prior_generation IS DISTINCT FROM OLD.prior_generation
    ) THEN
        RAISE EXCEPTION 'captured active/prior policy versions may change only at activation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER policy_activations_transition_guard
    BEFORE UPDATE ON policy_activations
    FOR EACH ROW EXECUTE FUNCTION validate_policy_activation_transition();

CREATE TABLE allowance_checkpoints (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    policy_kind text NOT NULL CHECK (policy_kind IN ('gateway_key_budget', 'organization_origin_budget')),
    policy_id uuid NOT NULL,
    policy_version_id uuid NOT NULL,
    epoch text NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    node_id text NOT NULL CHECK (char_length(node_id) BETWEEN 1 AND 160),
    granted_nanos numeric(38,0) NOT NULL CHECK (granted_nanos >= 0),
    settled_nanos numeric(38,0) NOT NULL CHECK (settled_nanos >= 0),
    returned_nanos numeric(38,0) NOT NULL CHECK (returned_nanos >= 0),
    observed_at timestamptz NOT NULL,
    CHECK (returned_nanos <= granted_nanos),
    PRIMARY KEY (policy_kind, policy_id, epoch, generation, node_id)
);
CREATE INDEX allowance_checkpoints_observed_idx ON allowance_checkpoints(observed_at, policy_id);

CREATE OR REPLACE FUNCTION validate_allowance_checkpoint_identity()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    matches integer;
BEGIN
    IF NEW.policy_kind = 'gateway_key_budget' THEN
        SELECT COUNT(*) INTO matches
        FROM gateway_key_budget_policies policy
        JOIN budget_policy_versions version
          ON version.gateway_key_budget_policy_id = policy.id
        WHERE policy.id = NEW.policy_id
          AND policy.organization_id = NEW.organization_id
          AND version.id = NEW.policy_version_id
          AND version.generation = NEW.generation
          AND version.epoch = NEW.epoch;
    ELSE
        SELECT COUNT(*) INTO matches
        FROM organization_origin_budget_policies policy
        JOIN budget_policy_versions version
          ON version.organization_origin_budget_policy_id = policy.id
        WHERE policy.id = NEW.policy_id
          AND policy.organization_id = NEW.organization_id
          AND version.id = NEW.policy_version_id
          AND version.generation = NEW.generation
          AND version.epoch = NEW.epoch;
    END IF;
    IF matches <> 1 THEN
        RAISE EXCEPTION 'allowance checkpoint policy/version/epoch does not resolve exactly';
    END IF;
    RETURN NEW;
END;
$$;
CREATE CONSTRAINT TRIGGER allowance_checkpoints_typed_identity
    AFTER INSERT OR UPDATE ON allowance_checkpoints
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_allowance_checkpoint_identity();

CREATE TABLE coordinator_recoveries (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    policy_kind text NOT NULL CHECK (policy_kind IN ('gateway_key_budget', 'organization_origin_budget')),
    policy_id uuid NOT NULL,
    policy_version_id uuid NOT NULL,
    epoch text NOT NULL,
    policy_generation bigint NOT NULL CHECK (policy_generation > 0),
    recovery_generation bigint NOT NULL CHECK (recovery_generation > 0),
    authorized_allowance_nanos numeric(38,0) NOT NULL CHECK (authorized_allowance_nanos >= 0),
    cumulative_epoch_allowance_nanos numeric(38,0) NOT NULL CHECK (cumulative_epoch_allowance_nanos >= authorized_allowance_nanos),
    incident_reference text NOT NULL CHECK (char_length(incident_reference) BETWEEN 1 AND 512),
    authorized_by_principal jsonb NOT NULL,
    safe_evidence jsonb NOT NULL CHECK (jsonb_typeof(safe_evidence) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (policy_kind, policy_id, epoch, recovery_generation),
    UNIQUE (policy_kind, policy_id, epoch, incident_reference)
);
CREATE OR REPLACE FUNCTION validate_coordinator_recovery()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    policy_epoch text;
    policy_mode text;
    incident_cap numeric(38,0);
    epoch_cap numeric(38,0);
    expected_generation bigint;
    prior_cumulative numeric(38,0);
BEGIN
    IF NEW.policy_kind = 'gateway_key_budget' THEN
        PERFORM 1 FROM gateway_key_budget_policies
        WHERE id = NEW.policy_id AND organization_id = NEW.organization_id
        FOR UPDATE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'gateway recovery policy is outside organization scope';
        END IF;
        SELECT version.epoch, version.mode, version.recovery_incident_cap_nanos,
               version.recovery_epoch_cap_nanos
          INTO policy_epoch, policy_mode, incident_cap, epoch_cap
        FROM budget_policy_versions version
        WHERE version.gateway_key_budget_policy_id = NEW.policy_id
          AND version.id = NEW.policy_version_id
          AND version.generation = NEW.policy_generation;
    ELSE
        PERFORM 1 FROM organization_origin_budget_policies
        WHERE id = NEW.policy_id AND organization_id = NEW.organization_id
        FOR UPDATE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'origin recovery policy is outside organization scope';
        END IF;
        SELECT version.epoch, version.mode, version.recovery_incident_cap_nanos,
               version.recovery_epoch_cap_nanos
          INTO policy_epoch, policy_mode, incident_cap, epoch_cap
        FROM budget_policy_versions version
        WHERE version.organization_origin_budget_policy_id = NEW.policy_id
          AND version.id = NEW.policy_version_id
          AND version.generation = NEW.policy_generation;
    END IF;
    IF policy_epoch IS NULL OR policy_epoch <> NEW.epoch OR policy_mode <> 'enforce' THEN
        RAISE EXCEPTION 'recovery policy/version/epoch does not resolve to an enforcing version';
    END IF;
    SELECT COALESCE(MAX(recovery_generation), 0) + 1,
           COALESCE(MAX(cumulative_epoch_allowance_nanos), 0)
      INTO expected_generation, prior_cumulative
    FROM coordinator_recoveries
    WHERE policy_kind = NEW.policy_kind
      AND policy_id = NEW.policy_id
      AND epoch = NEW.epoch;
    IF NEW.authorized_allowance_nanos > incident_cap
       OR NEW.recovery_generation <> expected_generation
       OR NEW.cumulative_epoch_allowance_nanos
            <> prior_cumulative + NEW.authorized_allowance_nanos
       OR NEW.cumulative_epoch_allowance_nanos > epoch_cap THEN
        RAISE EXCEPTION 'recovery incident/generation/cumulative allowance exceeds durable authority';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER coordinator_recoveries_authority
    BEFORE INSERT ON coordinator_recoveries
    FOR EACH ROW EXECUTE FUNCTION validate_coordinator_recovery();
CREATE TRIGGER coordinator_recoveries_immutable
    BEFORE UPDATE OR DELETE ON coordinator_recoveries
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();

CREATE TABLE logical_usage_hourly (
    bucket_start timestamptz NOT NULL,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    principal_kind text NOT NULL CHECK (principal_kind IN ('gateway_api_key', 'local_user', 'external_jwt')),
    gateway_api_key_id uuid,
    user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    membership_id uuid,
    route_id uuid NOT NULL REFERENCES model_routes(id) ON DELETE RESTRICT,
    ingress_protocol_family text NOT NULL CHECK (ingress_protocol_family IN (
        'anthropic_messages', 'openai_chat_completions', 'openai_responses', 'google_gemini'
    )),
    outcome_class text NOT NULL CHECK (char_length(outcome_class) BETWEEN 1 AND 64),
    request_count bigint NOT NULL CHECK (request_count >= 0),
    input_units numeric(38,0) NOT NULL CHECK (input_units >= 0),
    output_units numeric(38,0) NOT NULL CHECK (output_units >= 0),
    cached_input_units numeric(38,0) NOT NULL CHECK (cached_input_units >= 0),
    cost_nanos numeric(38,0),
    unknown_cost_count bigint NOT NULL CHECK (unknown_cost_count >= 0),
    duration_millis numeric(38,0) NOT NULL CHECK (duration_millis >= 0),
    CHECK (
        (principal_kind = 'gateway_api_key' AND gateway_api_key_id IS NOT NULL
            AND user_id IS NULL AND membership_id IS NULL)
        OR (principal_kind IN ('local_user', 'external_jwt') AND gateway_api_key_id IS NULL
            AND user_id IS NOT NULL AND membership_id IS NOT NULL)
    ),
    FOREIGN KEY (organization_id, gateway_api_key_id)
        REFERENCES gateway_api_keys(organization_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, membership_id, user_id)
        REFERENCES memberships(organization_id, id, user_id) ON DELETE RESTRICT,
    CONSTRAINT logical_usage_hourly_identity_unique UNIQUE NULLS NOT DISTINCT (
        bucket_start, organization_id, principal_kind, gateway_api_key_id, user_id, membership_id,
        route_id, ingress_protocol_family, outcome_class
    )
);
CREATE INDEX logical_usage_hourly_org_time_idx
    ON logical_usage_hourly(organization_id, bucket_start DESC);

CREATE TABLE attempt_usage_hourly (
    bucket_start timestamptz NOT NULL,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    principal_kind text NOT NULL CHECK (principal_kind IN ('gateway_api_key', 'local_user', 'external_jwt')),
    gateway_api_key_id uuid,
    user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    membership_id uuid,
    route_id uuid NOT NULL REFERENCES model_routes(id) ON DELETE RESTRICT,
    target_id uuid NOT NULL,
    deployment_id uuid NOT NULL REFERENCES model_deployments(id) ON DELETE RESTRICT,
    endpoint_id uuid NOT NULL REFERENCES upstream_endpoints(id) ON DELETE RESTRICT,
    endpoint_config_version bigint NOT NULL CHECK (endpoint_config_version > 0),
    credential_id uuid NOT NULL REFERENCES upstream_credentials(id) ON DELETE RESTRICT,
    credential_secret_version bigint NOT NULL CHECK (credential_secret_version > 0),
    credential_state_identity_version bigint NOT NULL CHECK (credential_state_identity_version > 0),
    origin text NOT NULL CHECK (origin IN ('system_provided', 'organization_byok')),
    pricing_policy_version_id uuid REFERENCES pricing_policy_versions(id) ON DELETE RESTRICT,
    key_budget_policy_id uuid REFERENCES gateway_key_budget_policies(id) ON DELETE RESTRICT,
    key_budget_version_id uuid REFERENCES budget_policy_versions(id) ON DELETE RESTRICT,
    key_budget_generation bigint CHECK (key_budget_generation IS NULL OR key_budget_generation > 0),
    key_budget_epoch text,
    origin_budget_policy_id uuid REFERENCES organization_origin_budget_policies(id) ON DELETE RESTRICT,
    origin_budget_version_id uuid REFERENCES budget_policy_versions(id) ON DELETE RESTRICT,
    origin_budget_generation bigint CHECK (origin_budget_generation IS NULL OR origin_budget_generation > 0),
    origin_budget_epoch text,
    terminal_class text NOT NULL CHECK (terminal_class IN (
        'actual', 'definitely_not_dispatched', 'unknown_or_ambiguous', 'actual_above_estimate'
    )),
    attempt_count bigint NOT NULL CHECK (attempt_count >= 0),
    input_units numeric(38,0) NOT NULL CHECK (input_units >= 0),
    output_units numeric(38,0) NOT NULL CHECK (output_units >= 0),
    cached_input_units numeric(38,0) NOT NULL CHECK (cached_input_units >= 0),
    estimated_cost_nanos numeric(38,0) CHECK (estimated_cost_nanos >= 0),
    unknown_estimate_count bigint NOT NULL CHECK (unknown_estimate_count >= 0),
    actual_cost_nanos numeric(38,0),
    unknown_cost_count bigint NOT NULL CHECK (unknown_cost_count >= 0),
    duration_millis numeric(38,0) NOT NULL CHECK (duration_millis >= 0),
    CHECK (
        (principal_kind = 'gateway_api_key' AND gateway_api_key_id IS NOT NULL
            AND user_id IS NULL AND membership_id IS NULL
            AND key_budget_policy_id IS NOT NULL AND key_budget_version_id IS NOT NULL
            AND key_budget_generation IS NOT NULL AND key_budget_epoch IS NOT NULL
            AND origin_budget_policy_id IS NOT NULL AND origin_budget_version_id IS NOT NULL
            AND origin_budget_generation IS NOT NULL AND origin_budget_epoch IS NOT NULL)
        OR (principal_kind IN ('local_user', 'external_jwt') AND gateway_api_key_id IS NULL
            AND user_id IS NOT NULL AND membership_id IS NOT NULL
            AND key_budget_policy_id IS NULL AND key_budget_version_id IS NULL
            AND key_budget_generation IS NULL AND key_budget_epoch IS NULL
            AND origin_budget_policy_id IS NULL AND origin_budget_version_id IS NULL
            AND origin_budget_generation IS NULL AND origin_budget_epoch IS NULL)
    ),
    FOREIGN KEY (organization_id, gateway_api_key_id)
        REFERENCES gateway_api_keys(organization_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, membership_id, user_id)
        REFERENCES memberships(organization_id, id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, gateway_api_key_id, key_budget_policy_id)
        REFERENCES gateway_key_budget_policies(organization_id, gateway_api_key_id, id)
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, origin_budget_policy_id, origin)
        REFERENCES organization_origin_budget_policies(organization_id, id, origin)
        ON DELETE RESTRICT,
    FOREIGN KEY (credential_id, credential_secret_version)
        REFERENCES upstream_credential_secret_versions(credential_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (
        key_budget_policy_id, key_budget_version_id, key_budget_generation, key_budget_epoch
    ) REFERENCES budget_policy_versions(
        gateway_key_budget_policy_id, id, generation, epoch
    ) ON DELETE RESTRICT,
    FOREIGN KEY (
        origin_budget_policy_id, origin_budget_version_id,
        origin_budget_generation, origin_budget_epoch
    ) REFERENCES budget_policy_versions(
        organization_origin_budget_policy_id, id, generation, epoch
    ) ON DELETE RESTRICT,
    CONSTRAINT attempt_usage_hourly_identity_unique UNIQUE NULLS NOT DISTINCT (
        bucket_start, organization_id, principal_kind, gateway_api_key_id, user_id, membership_id,
        route_id, target_id, deployment_id, endpoint_id, endpoint_config_version,
        credential_id, credential_secret_version, credential_state_identity_version,
        origin, pricing_policy_version_id, key_budget_policy_id, key_budget_version_id,
        key_budget_generation, key_budget_epoch, origin_budget_policy_id,
        origin_budget_version_id, origin_budget_generation, origin_budget_epoch, terminal_class
    )
);
CREATE INDEX attempt_usage_hourly_org_time_idx
    ON attempt_usage_hourly(organization_id, bucket_start DESC);
CREATE INDEX attempt_usage_hourly_target_time_idx
    ON attempt_usage_hourly(target_id, bucket_start DESC);

CREATE OR REPLACE FUNCTION validate_usage_catalog_attribution()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    route_scope text;
    route_organization_id uuid;
    deployment_scope text;
    deployment_organization_id uuid;
    deployment_endpoint_id uuid;
    deployment_credential_id uuid;
    target_route_id uuid;
    target_deployment_id uuid;
BEGIN
    SELECT resource_scope_kind, organization_id
      INTO route_scope, route_organization_id
    FROM model_routes WHERE id = NEW.route_id;
    IF route_scope IS NULL
       OR (route_scope = 'organization' AND route_organization_id <> NEW.organization_id)
       OR (route_scope = 'deployment' AND NOT EXISTS (
            SELECT 1 FROM organization_route_grants grant_row
            WHERE grant_row.organization_id = NEW.organization_id
              AND grant_row.route_id = NEW.route_id
       )) THEN
        RAISE EXCEPTION 'usage route is outside captured organization visibility';
    END IF;
    IF TG_TABLE_NAME IN ('logical_usage_hourly', 'logical_usage_daily') THEN
        RETURN NEW;
    END IF;
    SELECT resource_scope_kind, organization_id, endpoint_id, credential_id
      INTO deployment_scope, deployment_organization_id,
           deployment_endpoint_id, deployment_credential_id
    FROM model_deployments WHERE id = NEW.deployment_id;
    SELECT target.route_id, target.deployment_id
      INTO target_route_id, target_deployment_id
    FROM route_targets target WHERE target.id = NEW.target_id;
    IF target_route_id IS NULL THEN
        SELECT retired.route_id, retired.deployment_id
          INTO target_route_id, target_deployment_id
        FROM retired_route_target_identities retired
        WHERE retired.target_id = NEW.target_id;
    END IF;
    IF target_route_id IS DISTINCT FROM NEW.route_id
       OR target_deployment_id IS DISTINCT FROM NEW.deployment_id
       OR deployment_endpoint_id IS DISTINCT FROM NEW.endpoint_id
       OR deployment_credential_id IS DISTINCT FROM NEW.credential_id
       OR (NEW.origin = 'system_provided' AND deployment_scope <> 'deployment')
       OR (NEW.origin = 'organization_byok' AND (
            deployment_scope <> 'organization'
            OR deployment_organization_id <> NEW.organization_id
       )) THEN
        RAISE EXCEPTION 'attempt usage catalog/origin attribution does not match captured graph';
    END IF;
    RETURN NEW;
END;
$$;
CREATE CONSTRAINT TRIGGER logical_usage_catalog_attribution
    AFTER INSERT OR UPDATE ON logical_usage_hourly
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_usage_catalog_attribution();
CREATE CONSTRAINT TRIGGER attempt_usage_catalog_attribution
    AFTER INSERT OR UPDATE ON attempt_usage_hourly
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_usage_catalog_attribution();

CREATE TABLE logical_usage_daily (LIKE logical_usage_hourly INCLUDING CONSTRAINTS INCLUDING INDEXES);
ALTER TABLE logical_usage_daily RENAME COLUMN bucket_start TO bucket_date;
ALTER TABLE logical_usage_daily
    ADD FOREIGN KEY (organization_id)
        REFERENCES organizations(id) ON DELETE RESTRICT,
    ADD FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE RESTRICT,
    ADD FOREIGN KEY (route_id)
        REFERENCES model_routes(id) ON DELETE RESTRICT,
    ADD FOREIGN KEY (organization_id, gateway_api_key_id)
        REFERENCES gateway_api_keys(organization_id, id) ON DELETE RESTRICT,
    ADD FOREIGN KEY (organization_id, membership_id, user_id)
        REFERENCES memberships(organization_id, id, user_id) ON DELETE RESTRICT;
CREATE CONSTRAINT TRIGGER logical_usage_daily_catalog_attribution
    AFTER INSERT OR UPDATE ON logical_usage_daily
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_usage_catalog_attribution();

CREATE TABLE attempt_usage_daily (LIKE attempt_usage_hourly INCLUDING CONSTRAINTS INCLUDING INDEXES);
ALTER TABLE attempt_usage_daily RENAME COLUMN bucket_start TO bucket_date;
ALTER TABLE attempt_usage_daily
    ADD FOREIGN KEY (organization_id)
        REFERENCES organizations(id) ON DELETE RESTRICT,
    ADD FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE RESTRICT,
    ADD FOREIGN KEY (route_id)
        REFERENCES model_routes(id) ON DELETE RESTRICT,
    ADD FOREIGN KEY (deployment_id)
        REFERENCES model_deployments(id) ON DELETE RESTRICT,
    ADD FOREIGN KEY (endpoint_id)
        REFERENCES upstream_endpoints(id) ON DELETE RESTRICT,
    ADD FOREIGN KEY (credential_id)
        REFERENCES upstream_credentials(id) ON DELETE RESTRICT,
    ADD FOREIGN KEY (pricing_policy_version_id)
        REFERENCES pricing_policy_versions(id) ON DELETE RESTRICT,
    ADD FOREIGN KEY (key_budget_policy_id)
        REFERENCES gateway_key_budget_policies(id) ON DELETE RESTRICT,
    ADD FOREIGN KEY (key_budget_version_id)
        REFERENCES budget_policy_versions(id) ON DELETE RESTRICT,
    ADD FOREIGN KEY (origin_budget_policy_id)
        REFERENCES organization_origin_budget_policies(id) ON DELETE RESTRICT,
    ADD FOREIGN KEY (origin_budget_version_id)
        REFERENCES budget_policy_versions(id) ON DELETE RESTRICT,
    ADD FOREIGN KEY (organization_id, gateway_api_key_id)
        REFERENCES gateway_api_keys(organization_id, id) ON DELETE RESTRICT,
    ADD FOREIGN KEY (organization_id, membership_id, user_id)
        REFERENCES memberships(organization_id, id, user_id) ON DELETE RESTRICT,
    ADD FOREIGN KEY (organization_id, gateway_api_key_id, key_budget_policy_id)
        REFERENCES gateway_key_budget_policies(organization_id, gateway_api_key_id, id)
        ON DELETE RESTRICT,
    ADD FOREIGN KEY (organization_id, origin_budget_policy_id, origin)
        REFERENCES organization_origin_budget_policies(organization_id, id, origin)
        ON DELETE RESTRICT,
    ADD FOREIGN KEY (credential_id, credential_secret_version)
        REFERENCES upstream_credential_secret_versions(credential_id, version) ON DELETE RESTRICT,
    ADD FOREIGN KEY (
        key_budget_policy_id, key_budget_version_id, key_budget_generation, key_budget_epoch
    ) REFERENCES budget_policy_versions(
        gateway_key_budget_policy_id, id, generation, epoch
    ) ON DELETE RESTRICT,
    ADD FOREIGN KEY (
        origin_budget_policy_id, origin_budget_version_id,
        origin_budget_generation, origin_budget_epoch
    ) REFERENCES budget_policy_versions(
        organization_origin_budget_policy_id, id, generation, epoch
    ) ON DELETE RESTRICT;
CREATE CONSTRAINT TRIGGER attempt_usage_daily_catalog_attribution
    AFTER INSERT OR UPDATE ON attempt_usage_daily
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_usage_catalog_attribution();

CREATE TABLE aggregate_flush_receipts (
    id uuid PRIMARY KEY,
    source_epoch uuid NOT NULL,
    batch_sequence bigint NOT NULL CHECK (batch_sequence >= 0),
    fact_family text NOT NULL CHECK (fact_family IN ('logical_hourly', 'attempt_hourly')),
    batch_digest bytea NOT NULL CHECK (octet_length(batch_digest) = 32),
    fact_count integer NOT NULL CHECK (fact_count >= 0),
    flushed_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (source_epoch, batch_sequence, fact_family)
);
CREATE TRIGGER aggregate_flush_receipts_immutable
    BEFORE UPDATE OR DELETE ON aggregate_flush_receipts
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
