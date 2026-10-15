-- 020_agent_status_hosts.sql
-- The one team member whose signed status reports speak for an agent
-- (docs/agent-health.md). At most one host per agent; replacing or clearing
-- the designation is a row upsert or delete.

CREATE TABLE IF NOT EXISTS {{tables.agent_status_hosts}} (
    agent_id           UUID PRIMARY KEY REFERENCES {{tables.agents}}(agent_id) ON DELETE CASCADE,
    team_id            TEXT NOT NULL,
    host_did           TEXT NOT NULL CHECK (host_did LIKE 'did:key:z%'),
    designated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    designated_by_did  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_status_hosts_team_host
    ON {{tables.agent_status_hosts}} (team_id, host_did);
