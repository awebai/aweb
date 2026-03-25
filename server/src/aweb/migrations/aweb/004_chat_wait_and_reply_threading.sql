ALTER TABLE {{tables.chat_sessions}}
ADD COLUMN IF NOT EXISTS wait_seconds INTEGER;

ALTER TABLE {{tables.chat_sessions}}
ADD COLUMN IF NOT EXISTS wait_started_at TIMESTAMPTZ;

ALTER TABLE {{tables.chat_sessions}}
ADD COLUMN IF NOT EXISTS wait_started_by_agent_id UUID REFERENCES {{tables.agents}}(agent_id);

ALTER TABLE {{tables.chat_sessions}}
DROP CONSTRAINT IF EXISTS chk_chat_sessions_wait_seconds;

ALTER TABLE {{tables.chat_sessions}}
ADD CONSTRAINT chk_chat_sessions_wait_seconds
CHECK (wait_seconds IS NULL OR wait_seconds >= 1);

ALTER TABLE {{tables.chat_messages}}
ADD COLUMN IF NOT EXISTS reply_to_message_id UUID REFERENCES {{tables.chat_messages}}(message_id);

CREATE INDEX IF NOT EXISTS idx_chat_messages_reply_to
ON {{tables.chat_messages}} (reply_to_message_id)
WHERE reply_to_message_id IS NOT NULL;
