-- 021_agent_status.sql
-- The latest signed status document per agent (docs/agent-health.md). The row
-- is upserted only with a greater seq and holds no history. reachable,
-- reason_code and fixing_by are copies of signed fields kept for change
-- detection; signed_payload and signature are the authority.

CREATE TABLE IF NOT EXISTS {{tables.agent_status}} (
    agent_id        UUID PRIMARY KEY REFERENCES {{tables.agents}}(agent_id) ON DELETE CASCADE,
    team_id         TEXT NOT NULL,
    publisher_did   TEXT NOT NULL CHECK (publisher_did LIKE 'did:key:z%'),
    seq             BIGINT NOT NULL CHECK (seq > 0),
    reachable       TEXT NOT NULL,
    reason_code     TEXT,
    fixing_by       TEXT,
    observed_at     TIMESTAMPTZ NOT NULL,
    valid_until     TIMESTAMPTZ NOT NULL,
    signed_payload  TEXT NOT NULL,
    signature       TEXT NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_status_team
    ON {{tables.agent_status}} (team_id);
