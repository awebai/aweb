-- 018_identity_grant_liveness.sql
-- Ephemeral liveness for resident identity session grants. Durable workspace and
-- task/message attribution stays with the subject identity; grant runtime
-- liveness is keyed by grant_id so revoking/retiring one grant does not clobber
-- the root runtime or another grant.

CREATE TABLE IF NOT EXISTS {{tables.identity_grant_liveness}} (
    grant_id          UUID PRIMARY KEY REFERENCES {{tables.identity_session_grants}}(grant_id) ON DELETE CASCADE,
    team_id           TEXT NOT NULL,
    subject_agent_id  UUID NOT NULL REFERENCES {{tables.agents}}(agent_id) ON DELETE CASCADE,
    workspace_id      UUID REFERENCES {{tables.workspaces}}(workspace_id) ON DELETE SET NULL,
    alias             TEXT NOT NULL,
    session_did_key   TEXT NOT NULL CHECK (session_did_key LIKE 'did:key:z%'),
    last_seen_at      TIMESTAMPTZ NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    CHECK (expires_at >= last_seen_at)
);

CREATE INDEX IF NOT EXISTS idx_identity_grant_liveness_subject
    ON {{tables.identity_grant_liveness}} (team_id, subject_agent_id);

CREATE INDEX IF NOT EXISTS idx_identity_grant_liveness_expiry
    ON {{tables.identity_grant_liveness}} (expires_at);
