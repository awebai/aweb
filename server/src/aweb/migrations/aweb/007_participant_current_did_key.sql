-- Persist remote participant current did:key used by federated continuations.

ALTER TABLE {{tables.conversation_participants}}
    ADD COLUMN IF NOT EXISTS current_did_key TEXT;

ALTER TABLE {{tables.chat_participants}}
    ADD COLUMN IF NOT EXISTS current_did_key TEXT;
