CREATE INDEX oidc_login_states_cleanup_expires_idx
    ON oidc_login_states(expires_at, id);

CREATE INDEX oidc_login_states_cleanup_consumed_idx
    ON oidc_login_states(consumed_at, id)
    WHERE consumed_at IS NOT NULL;

CREATE INDEX web_sessions_cleanup_expires_idx
    ON web_sessions(expires_at, id);

CREATE INDEX web_sessions_cleanup_revoked_idx
    ON web_sessions(revoked_at, id)
    WHERE revoked_at IS NOT NULL;
