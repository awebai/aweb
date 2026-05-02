-- 002_conversations.sql
-- First-class conversation primitives.  This is an additive schema set:
-- durable conversations, participant-set routing/auth metadata, and an
-- optional mail message link into that conversation graph.

CREATE TABLE IF NOT EXISTS {{tables.conversations}} (
    conversation_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_type TEXT NOT NULL
                      CHECK (conversation_type IN ('mail', 'chat')),
    status            TEXT NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active', 'closed', 'expired')),
    team_id           TEXT REFERENCES {{tables.teams}}(team_id),
    created_by_did    TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at         TIMESTAMPTZ,
    expires_at        TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_conversations_type_status
    ON {{tables.conversations}} (conversation_type, status, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_conversations_expires_at
    ON {{tables.conversations}} (expires_at)
    WHERE expires_at IS NOT NULL AND status = 'active';

CREATE TABLE IF NOT EXISTS {{tables.conversation_participants}} (
    conversation_id UUID NOT NULL
                    REFERENCES {{tables.conversations}}(conversation_id)
                    ON DELETE CASCADE,
    did             TEXT NOT NULL,
    agent_id        UUID REFERENCES {{tables.agents}}(agent_id) ON DELETE SET NULL,
    alias           TEXT NOT NULL DEFAULT '',
    address         TEXT,
    transport_hint  TEXT,
    role            TEXT NOT NULL DEFAULT 'participant'
                    CHECK (role IN ('participant', 'initiator')),
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (conversation_id, did)
);

CREATE INDEX IF NOT EXISTS idx_conversation_participants_did
    ON {{tables.conversation_participants}} (did, conversation_id);

CREATE INDEX IF NOT EXISTS idx_conversation_participants_agent
    ON {{tables.conversation_participants}} (agent_id, conversation_id)
    WHERE agent_id IS NOT NULL;

ALTER TABLE {{tables.messages}}
    ADD COLUMN IF NOT EXISTS conversation_id UUID
        REFERENCES {{tables.conversations}}(conversation_id)
        ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_messages_conversation
    ON {{tables.messages}} (conversation_id, created_at)
    WHERE conversation_id IS NOT NULL;
