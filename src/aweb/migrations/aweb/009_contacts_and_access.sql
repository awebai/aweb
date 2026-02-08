-- Contacts table for project address books + agent access_mode

CREATE TABLE IF NOT EXISTS {{tables.contacts}} (
    contact_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    contact_address TEXT NOT NULL,
    label TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_contacts_project_address
ON {{tables.contacts}} (project_id, contact_address);

ALTER TABLE {{tables.agents}}
ADD COLUMN IF NOT EXISTS access_mode TEXT NOT NULL DEFAULT 'open';

-- CHECK constraint: TEXT column (not enum) for easy future extension.
-- DROP+ADD is idempotent.
ALTER TABLE {{tables.agents}}
DROP CONSTRAINT IF EXISTS chk_agents_access_mode;

ALTER TABLE {{tables.agents}}
ADD CONSTRAINT chk_agents_access_mode
CHECK (access_mode IN ('open', 'contacts_only'));
