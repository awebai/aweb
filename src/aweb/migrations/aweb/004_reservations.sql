-- aweb reservations (generic opaque locks)

CREATE TABLE IF NOT EXISTS {{tables.reservations}} (
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    resource_key TEXT NOT NULL,
    holder_agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    holder_alias TEXT NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (project_id, resource_key)
);

CREATE INDEX IF NOT EXISTS idx_reservations_project_expires
ON {{tables.reservations}} (project_id, expires_at);

