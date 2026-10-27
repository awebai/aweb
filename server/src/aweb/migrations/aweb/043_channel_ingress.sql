ALTER TABLE {{tables.messages}} ADD COLUMN ingress JSONB;
ALTER TABLE {{tables.chat_messages}} ADD COLUMN ingress JSONB;
