-- Stable identity anchors (did:claw) + stable envelope fields

ALTER TABLE {{tables.agents}}
  ADD COLUMN IF NOT EXISTS stable_id TEXT;

CREATE INDEX IF NOT EXISTS idx_agents_stable_id
  ON {{tables.agents}} (stable_id)
  WHERE deleted_at IS NULL AND stable_id IS NOT NULL;

ALTER TABLE {{tables.messages}}
  ADD COLUMN IF NOT EXISTS from_stable_id TEXT,
  ADD COLUMN IF NOT EXISTS to_stable_id TEXT;

ALTER TABLE {{tables.chat_messages}}
  ADD COLUMN IF NOT EXISTS from_stable_id TEXT,
  ADD COLUMN IF NOT EXISTS to_stable_id TEXT;

