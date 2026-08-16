ALTER TABLE coordinator_recoveries
    ADD COLUMN reason text NOT NULL DEFAULT 'legacy recovery authorization'
        CHECK (char_length(reason) BETWEEN 1 AND 2048);
ALTER TABLE coordinator_recoveries ALTER COLUMN reason DROP DEFAULT;

CREATE TABLE coordinator_recovery_installations (
    recovery_id uuid PRIMARY KEY REFERENCES coordinator_recoveries(id) ON DELETE RESTRICT,
    status text NOT NULL CHECK (status IN ('pending', 'installed', 'failed')),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_attempt_at timestamptz,
    installed_at timestamptz,
    safe_error jsonb CHECK (safe_error IS NULL OR jsonb_typeof(safe_error) = 'object'),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (status = 'installed' AND installed_at IS NOT NULL AND safe_error IS NULL)
        OR (status IN ('pending', 'failed') AND installed_at IS NULL)
    )
);
CREATE INDEX coordinator_recovery_installations_pending_idx
    ON coordinator_recovery_installations(status, updated_at, recovery_id)
    WHERE status IN ('pending', 'failed');

CREATE OR REPLACE FUNCTION validate_coordinator_recovery()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    policy_epoch text;
    policy_mode text;
    policy_status text;
    active_version_id uuid;
    incident_cap numeric(38,0);
    epoch_cap numeric(38,0);
    deployment_incident_cap numeric(38,0);
    deployment_epoch_cap numeric(38,0);
    expected_generation bigint;
    prior_cumulative numeric(38,0);
BEGIN
    IF NEW.policy_kind = 'gateway_key_budget' THEN
        SELECT policy.status, policy.active_version_id
          INTO policy_status, active_version_id
        FROM gateway_key_budget_policies policy
        WHERE policy.id = NEW.policy_id AND policy.organization_id = NEW.organization_id
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
        SELECT policy.status, policy.active_version_id
          INTO policy_status, active_version_id
        FROM organization_origin_budget_policies policy
        WHERE policy.id = NEW.policy_id AND policy.organization_id = NEW.organization_id
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
    IF policy_status <> 'active'
       OR active_version_id IS DISTINCT FROM NEW.policy_version_id
       OR policy_epoch IS NULL
       OR policy_epoch <> NEW.epoch
       OR policy_mode <> 'enforce' THEN
        RAISE EXCEPTION 'recovery policy/version/epoch is not the active enforcing version';
    END IF;
    SELECT max_recovery_incident_cap_nanos, max_recovery_epoch_cap_nanos
      INTO deployment_incident_cap, deployment_epoch_cap
    FROM gateway_policy_ceilings WHERE singleton = true;
    IF deployment_incident_cap IS NULL OR deployment_epoch_cap IS NULL THEN
        RAISE EXCEPTION 'gateway policy ceilings are unavailable';
    END IF;
    SELECT COALESCE(MAX(recovery_generation), 0) + 1,
           COALESCE(MAX(cumulative_epoch_allowance_nanos), 0)
      INTO expected_generation, prior_cumulative
    FROM coordinator_recoveries
    WHERE policy_kind = NEW.policy_kind
      AND policy_id = NEW.policy_id
      AND epoch = NEW.epoch;
    IF NEW.authorized_allowance_nanos > LEAST(incident_cap, deployment_incident_cap)
       OR NEW.recovery_generation <> expected_generation
       OR NEW.cumulative_epoch_allowance_nanos
            <> prior_cumulative + NEW.authorized_allowance_nanos
       OR NEW.cumulative_epoch_allowance_nanos > LEAST(epoch_cap, deployment_epoch_cap) THEN
        RAISE EXCEPTION 'recovery incident/generation/cumulative allowance exceeds durable authority';
    END IF;
    RETURN NEW;
END;
$$;
