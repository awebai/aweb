-- No backfill: current rows cannot establish membership at historical acceptance.
ALTER TABLE {{tables.messages}} ADD COLUMN sender_admission JSONB;
ALTER TABLE {{tables.chat_messages}} ADD COLUMN sender_admission JSONB;
