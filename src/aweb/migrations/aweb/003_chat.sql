-- aweb chat (persistent sessions + messages + read receipts)

CREATE TABLE IF NOT EXISTS {{tables.chat_sessions}} (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    participant_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, participant_hash)
);

CREATE TABLE IF NOT EXISTS {{tables.chat_session_participants}} (
    session_id UUID NOT NULL REFERENCES {{tables.chat_sessions}}(session_id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    alias TEXT NOT NULL,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (session_id, agent_id)
);

CREATE TABLE IF NOT EXISTS {{tables.chat_messages}} (
    message_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES {{tables.chat_sessions}}(session_id) ON DELETE CASCADE,
    from_agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    from_alias TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sender_leaving BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_session_created
ON {{tables.chat_messages}} (session_id, created_at ASC);

CREATE TABLE IF NOT EXISTS {{tables.chat_read_receipts}} (
    session_id UUID NOT NULL REFERENCES {{tables.chat_sessions}}(session_id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    last_read_message_id UUID,
    last_read_at TIMESTAMPTZ,
    PRIMARY KEY (session_id, agent_id)
);

