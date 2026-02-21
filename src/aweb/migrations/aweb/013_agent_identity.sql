-- Agent identity columns for DID/signing support

ALTER TABLE {{tables.agents}}
  ADD COLUMN IF NOT EXISTS did TEXT,
  ADD COLUMN IF NOT EXISTS public_key TEXT,
  ADD COLUMN IF NOT EXISTS custody TEXT,
  ADD COLUMN IF NOT EXISTS signing_key_enc BYTEA,
  ADD COLUMN IF NOT EXISTS lifetime TEXT NOT NULL DEFAULT 'persistent',
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active',
  ADD COLUMN IF NOT EXISTS successor_agent_id UUID REFERENCES {{tables.agents}}(agent_id);

ALTER TABLE {{tables.agents}}
  DROP CONSTRAINT IF EXISTS chk_agents_custody,
  ADD CONSTRAINT chk_agents_custody CHECK (custody IN ('self', 'custodial'));

ALTER TABLE {{tables.agents}}
  DROP CONSTRAINT IF EXISTS chk_agents_lifetime,
  ADD CONSTRAINT chk_agents_lifetime CHECK (lifetime IN ('persistent', 'ephemeral'));

ALTER TABLE {{tables.agents}}
  DROP CONSTRAINT IF EXISTS chk_agents_status,
  ADD CONSTRAINT chk_agents_status CHECK (status IN ('active', 'retired', 'deregistered'));

CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_did_unique_active
  ON {{tables.agents}} (project_id, did)
  WHERE deleted_at IS NULL AND did IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_agents_did
  ON {{tables.agents}} (did)
  WHERE deleted_at IS NULL AND did IS NOT NULL;
