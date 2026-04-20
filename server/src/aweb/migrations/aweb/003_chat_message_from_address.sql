ALTER TABLE {{tables.messages}}
    ADD COLUMN IF NOT EXISTS from_address TEXT;

ALTER TABLE {{tables.chat_messages}}
    ADD COLUMN IF NOT EXISTS from_address TEXT;
