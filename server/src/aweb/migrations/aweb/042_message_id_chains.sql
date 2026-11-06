-- Adjacent, optional identity proofs. Original message bytes stay unchanged.
ALTER TABLE {{tables.messages}} ADD COLUMN id_chain JSONB;
ALTER TABLE {{tables.chat_messages}} ADD COLUMN id_chain JSONB;
