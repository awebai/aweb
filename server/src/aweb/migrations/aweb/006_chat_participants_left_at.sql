-- 006_chat_participants_left_at.sql
-- Durable chat membership removal state. This is distinct from
-- chat_messages.sender_leaving, which only means the sender ended its current
-- wait/turn.

ALTER TABLE {{tables.chat_participants}}
    ADD COLUMN IF NOT EXISTS left_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_chat_participants_active
    ON {{tables.chat_participants}} (session_id, did)
    WHERE left_at IS NULL;
