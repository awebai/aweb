-- Agent lifecycle audit log for rotation, retirement, deregistration

CREATE TABLE IF NOT EXISTS {{tables.agent_log}} (
    log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    project_id UUID NOT NULL,
    operation TEXT NOT NULL,
    old_did TEXT,
    new_did TEXT,
    signed_by TEXT,
    entry_signature TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_log_agent_id
  ON {{tables.agent_log}} (agent_id, created_at);
