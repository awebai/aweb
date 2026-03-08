CREATE TABLE {{tables.control_signals}} (
    signal_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    target_agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    from_agent_id UUID REFERENCES {{tables.agents}}(agent_id),
    signal_type TEXT NOT NULL CHECK (signal_type IN ('pause', 'resume', 'interrupt')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at TIMESTAMPTZ
);

CREATE INDEX idx_control_signals_pending
ON {{tables.control_signals}} (project_id, target_agent_id)
WHERE consumed_at IS NULL;
