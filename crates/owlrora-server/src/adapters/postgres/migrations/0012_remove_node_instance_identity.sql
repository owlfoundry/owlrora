-- OwlRora replicas are stateless and do not have durable application identities.
-- Preserve fleet-level allowance evidence while removing the obsolete per-replica key.
ALTER TABLE allowance_checkpoints RENAME TO allowance_checkpoints_with_node_identity;
ALTER INDEX allowance_checkpoints_observed_idx
    RENAME TO allowance_checkpoints_with_node_identity_observed_idx;

CREATE TABLE allowance_checkpoints (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    policy_kind text NOT NULL CHECK (policy_kind IN ('gateway_key_budget', 'organization_origin_budget')),
    policy_id uuid NOT NULL,
    policy_version_id uuid NOT NULL,
    epoch text NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    granted_nanos numeric(38,0) NOT NULL CHECK (granted_nanos >= 0),
    settled_nanos numeric(38,0) NOT NULL CHECK (settled_nanos >= 0),
    returned_nanos numeric(38,0) NOT NULL CHECK (returned_nanos >= 0),
    observed_at timestamptz NOT NULL,
    CHECK (returned_nanos <= granted_nanos),
    PRIMARY KEY (policy_kind, policy_id, epoch, generation)
);

INSERT INTO allowance_checkpoints(
    organization_id,
    policy_kind,
    policy_id,
    policy_version_id,
    epoch,
    generation,
    granted_nanos,
    settled_nanos,
    returned_nanos,
    observed_at
)
SELECT
    organization_id,
    policy_kind,
    policy_id,
    policy_version_id,
    epoch,
    generation,
    SUM(granted_nanos),
    SUM(settled_nanos),
    SUM(returned_nanos),
    MAX(observed_at)
FROM allowance_checkpoints_with_node_identity
GROUP BY
    organization_id,
    policy_kind,
    policy_id,
    policy_version_id,
    epoch,
    generation;

CREATE INDEX allowance_checkpoints_observed_idx
    ON allowance_checkpoints(observed_at, policy_id);
CREATE CONSTRAINT TRIGGER allowance_checkpoints_typed_identity
    AFTER INSERT OR UPDATE ON allowance_checkpoints
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_allowance_checkpoint_identity();

DROP TABLE allowance_checkpoints_with_node_identity;

-- server-v0.0.3 processes read and write node_watermarks. This contract
-- migration intentionally establishes a schema compatibility boundary: stop
-- every older process before applying it, and do not restart an older binary
-- against the migrated database.
DROP TABLE node_watermarks;
