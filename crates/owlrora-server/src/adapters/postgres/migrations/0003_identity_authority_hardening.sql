ALTER TABLE web_sessions
ADD COLUMN captured_system_administrator boolean NOT NULL DEFAULT false,
ADD COLUMN captured_organization_capabilities jsonb NOT NULL DEFAULT '{}'::jsonb;

DELETE FROM web_sessions
WHERE authentication_method = 'external_session';

ALTER TABLE web_sessions
ADD CONSTRAINT web_sessions_identity_evidence_check CHECK (
    (
        authentication_method = 'management_api_key_session'
        AND external_issuer_id IS NULL
        AND external_subject IS NULL
    )
    OR
    (
        authentication_method = 'external_session'
        AND management_api_key_id IS NULL
        AND accepted_key_version_id IS NULL
        AND external_issuer_id IS NOT NULL
        AND external_subject IS NOT NULL
    )
),
ADD CONSTRAINT web_sessions_captured_organization_capabilities_object_check CHECK (
    jsonb_typeof(captured_organization_capabilities) = 'object'
);

DELETE FROM oidc_login_states;

ALTER TABLE oidc_login_states
ADD COLUMN issuer_policy_version bigint NOT NULL CHECK (issuer_policy_version > 0),
ADD COLUMN transaction_digest bytea NOT NULL CHECK (octet_length(transaction_digest) = 32);

CREATE OR REPLACE FUNCTION reject_issuer_verifier_material_update()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'issuer verifier material versions are immutable';
END;
$$;

CREATE TRIGGER issuer_verifier_material_versions_immutable
BEFORE UPDATE ON issuer_verifier_material_versions
FOR EACH ROW EXECUTE FUNCTION reject_issuer_verifier_material_update();
