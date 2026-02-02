-- Add hang_on column to chat_messages for requesting more time to reply

ALTER TABLE {{tables.chat_messages}}
ADD COLUMN IF NOT EXISTS hang_on BOOLEAN NOT NULL DEFAULT FALSE;
