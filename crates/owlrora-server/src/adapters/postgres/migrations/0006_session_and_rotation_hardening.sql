ALTER TABLE management_api_key_secret_versions
ADD COLUMN overlap_started_at timestamptz;

-- Pre-0006 rows did not record the transition into overlap. Preserve their
-- already-persisted deadline without pretending the secret creation time was
-- the rotation time. Starting the compatibility window at the earlier of the
-- migration time and stored deadline lets later policy tightening clamp from
-- upgrade time, while never extending the existing overlap_until authority.
UPDATE management_api_key_secret_versions
SET overlap_started_at = LEAST(CURRENT_TIMESTAMP, overlap_until)
WHERE state = 'overlap';

-- The old schema allowed retired rows to retain a historical overlap_until.
-- Normalize those legal rows before enforcing the new state invariant.
UPDATE management_api_key_secret_versions
SET overlap_started_at = NULL, overlap_until = NULL
WHERE state <> 'overlap';

ALTER TABLE management_api_key_secret_versions
ADD CONSTRAINT management_key_overlap_window_check CHECK (
    (state = 'overlap' AND overlap_started_at IS NOT NULL AND overlap_until IS NOT NULL
        AND overlap_until >= overlap_started_at)
    OR
    (state <> 'overlap' AND overlap_started_at IS NULL AND overlap_until IS NULL)
);

CREATE INDEX system_administrator_grants_time_idx
ON system_administrator_grants(created_at DESC, id DESC);
