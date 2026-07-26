CREATE TABLE IF NOT EXISTS {{tables.session_admission_leases}} (
    team_id             TEXT NOT NULL,
    principal_agent_id  UUID NOT NULL REFERENCES {{tables.agents}}(agent_id) ON DELETE CASCADE,
    session_id          TEXT NOT NULL,
    session_key_hash    BYTEA NOT NULL,
    generation          BIGINT NOT NULL DEFAULT 1,
    acquired_at         TIMESTAMPTZ NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (team_id, principal_agent_id)
);

CREATE INDEX IF NOT EXISTS idx_session_admission_leases_expiry
    ON {{tables.session_admission_leases}} (expires_at);
