-- DID/signature columns on chat_messages table

ALTER TABLE {{tables.chat_messages}}
  ADD COLUMN IF NOT EXISTS from_did TEXT,
  ADD COLUMN IF NOT EXISTS to_did TEXT,
  ADD COLUMN IF NOT EXISTS signature TEXT,
  ADD COLUMN IF NOT EXISTS signing_key_id TEXT;
