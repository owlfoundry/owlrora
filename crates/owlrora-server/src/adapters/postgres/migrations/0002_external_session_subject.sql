ALTER TABLE web_sessions
ADD COLUMN external_subject text
CHECK (external_subject IS NULL OR char_length(external_subject) BETWEEN 1 AND 512);

CREATE INDEX web_sessions_external_identity_idx
ON web_sessions(external_issuer_id, external_subject)
WHERE status = 'active' AND external_issuer_id IS NOT NULL;
