-- DID/signature columns on messages table

ALTER TABLE {{tables.messages}}
  ADD COLUMN IF NOT EXISTS from_did TEXT,
  ADD COLUMN IF NOT EXISTS to_did TEXT,
  ADD COLUMN IF NOT EXISTS signature TEXT,
  ADD COLUMN IF NOT EXISTS signing_key_id TEXT;
