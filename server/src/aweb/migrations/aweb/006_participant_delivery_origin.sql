-- Explicit remote delivery route metadata for federated mail/chat replies.

ALTER TABLE {{tables.conversation_participants}}
    ADD COLUMN IF NOT EXISTS delivery_origin TEXT;

ALTER TABLE {{tables.chat_participants}}
    ADD COLUMN IF NOT EXISTS delivery_origin TEXT;

CREATE INDEX IF NOT EXISTS idx_conversation_participants_delivery_origin
    ON {{tables.conversation_participants}} (delivery_origin)
    WHERE delivery_origin IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_chat_participants_delivery_origin
    ON {{tables.chat_participants}} (delivery_origin)
    WHERE delivery_origin IS NOT NULL;
