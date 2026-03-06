-- Namespace as a first-class core concept.
-- Namespaces are the public address space for agents (namespace_slug/alias).

CREATE TABLE IF NOT EXISTS {{tables.namespaces}} (
    namespace_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_namespaces_slug_unique_active
ON {{tables.namespaces}} (slug)
WHERE deleted_at IS NULL;

-- Add namespace_id to projects.
ALTER TABLE {{tables.projects}}
    ADD COLUMN IF NOT EXISTS namespace_id UUID
    REFERENCES {{tables.namespaces}}(namespace_id);

CREATE INDEX IF NOT EXISTS idx_projects_namespace
ON {{tables.projects}} (namespace_id);

-- Add namespace_id to agents.
ALTER TABLE {{tables.agents}}
    ADD COLUMN IF NOT EXISTS namespace_id UUID
    REFERENCES {{tables.namespaces}}(namespace_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_namespace_alias_unique_active
ON {{tables.agents}} (namespace_id, alias)
WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_agents_namespace
ON {{tables.agents}} (namespace_id);
