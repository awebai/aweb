CREATE TABLE IF NOT EXISTS {{tables.spawn_invite_tokens}} (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id) ON DELETE CASCADE,
    created_by_agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    alias_hint TEXT,
    access_mode TEXT NOT NULL DEFAULT 'open',
    max_uses INTEGER NOT NULL DEFAULT 1,
    current_uses INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_spawn_invite_access_mode CHECK (access_mode IN ('project_only', 'owner_only', 'contacts_only', 'open')),
    CONSTRAINT chk_spawn_invite_max_uses CHECK (max_uses >= 1),
    CONSTRAINT chk_spawn_invite_current_uses CHECK (current_uses >= 0)
);

CREATE INDEX IF NOT EXISTS idx_spawn_invite_tokens_project
ON {{tables.spawn_invite_tokens}} (project_id);

CREATE INDEX IF NOT EXISTS idx_spawn_invite_tokens_creator
ON {{tables.spawn_invite_tokens}} (created_by_agent_id);

CREATE INDEX IF NOT EXISTS idx_spawn_invite_tokens_prefix
ON {{tables.spawn_invite_tokens}} (token_prefix);
