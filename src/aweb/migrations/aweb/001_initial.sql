-- aweb initial schema (clean start)

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS {{tables.projects}} (
    project_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- OSS mode: slug unique globally for active projects.
CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_slug_unique_active
ON {{tables.projects}} (slug)
WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS {{tables.agents}} (
    agent_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    alias TEXT NOT NULL,
    human_name TEXT NOT NULL DEFAULT '',
    agent_type TEXT NOT NULL DEFAULT 'agent',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_project_alias_unique_active
ON {{tables.agents}} (project_id, alias)
WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS {{tables.api_keys}} (
    api_key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_prefix_unique
ON {{tables.api_keys}} (key_prefix);

CREATE INDEX IF NOT EXISTS idx_api_keys_project
ON {{tables.api_keys}} (project_id);
