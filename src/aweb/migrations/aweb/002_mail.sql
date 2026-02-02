-- aweb mail (async messages)

CREATE TABLE IF NOT EXISTS {{tables.messages}} (
    message_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    from_agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    to_agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    from_alias TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL,
    priority TEXT NOT NULL DEFAULT 'normal',
    thread_id UUID,
    read_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_messages_inbox
ON {{tables.messages}} (project_id, to_agent_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_messages_unread
ON {{tables.messages}} (project_id, to_agent_id, read_at)
WHERE read_at IS NULL;

