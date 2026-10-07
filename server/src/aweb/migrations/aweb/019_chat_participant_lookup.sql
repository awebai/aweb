-- Viewer-first pending-chat lookup. Include departed participants: pending
-- conversation semantics do not filter left_at. These are additive indexes;
-- applying this migration is a separate operator/release action.
CREATE INDEX IF NOT EXISTS idx_chat_participants_did
    ON {{tables.chat_participants}} (did);

CREATE INDEX IF NOT EXISTS idx_chat_participants_agent
    ON {{tables.chat_participants}} (agent_id)
    WHERE agent_id IS NOT NULL;
