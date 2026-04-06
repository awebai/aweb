-- 001_initial.sql
-- Clean baseline for the embedded aweb protocol schema.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- Projects
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.projects}} (
    project_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    tenant_id UUID,
    owner_type TEXT,
    owner_ref TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_slug_unique_active_oss
ON {{tables.projects}} (slug)
WHERE tenant_id IS NULL AND deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_tenant_slug_unique_active
ON {{tables.projects}} (tenant_id, slug)
WHERE tenant_id IS NOT NULL AND deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_projects_owner_scope
ON {{tables.projects}} (owner_type, owner_ref, slug)
WHERE deleted_at IS NULL AND owner_ref IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Agents
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.agents}} (
    agent_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    alias TEXT NOT NULL,
    human_name TEXT NOT NULL DEFAULT '',
    agent_type TEXT NOT NULL DEFAULT 'agent',
    access_mode TEXT NOT NULL DEFAULT 'open',
    did TEXT,
    public_key TEXT,
    custody TEXT,
    signing_key_enc BYTEA,
    stable_id TEXT,
    lifetime TEXT NOT NULL DEFAULT 'persistent',
    status TEXT NOT NULL DEFAULT 'active',
    successor_agent_id UUID REFERENCES {{tables.agents}}(agent_id),
    role TEXT,
    program TEXT,
    context JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT chk_agents_alias_no_slash CHECK (POSITION('/' IN alias) = 0),
    CONSTRAINT chk_agents_access_mode CHECK (access_mode IN ('project_only', 'owner_only', 'contacts_only', 'open')),
    CONSTRAINT chk_agents_custody CHECK (custody IN ('self', 'custodial')),
    CONSTRAINT chk_agents_lifetime CHECK (lifetime IN ('persistent', 'ephemeral')),
    CONSTRAINT chk_agents_status CHECK (status IN ('active', 'retired', 'archived', 'deleted'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_project_alias_unique_active
ON {{tables.agents}} (project_id, alias)
WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_did_unique_active
ON {{tables.agents}} (project_id, did)
WHERE deleted_at IS NULL AND did IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_agents_did
ON {{tables.agents}} (did)
WHERE deleted_at IS NULL AND did IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_stable_id
ON {{tables.agents}} (stable_id)
WHERE deleted_at IS NULL AND stable_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- API Keys
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.api_keys}} (
    api_key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    agent_id UUID REFERENCES {{tables.agents}}(agent_id),
    user_id UUID,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_keys_project
ON {{tables.api_keys}} (project_id);

CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash
ON {{tables.api_keys}} (key_hash);

CREATE INDEX IF NOT EXISTS idx_api_keys_agent_id
ON {{tables.api_keys}} (agent_id);

CREATE INDEX IF NOT EXISTS idx_api_keys_user
ON {{tables.api_keys}} (user_id)
WHERE user_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Spawn invite tokens
-- ---------------------------------------------------------------------------

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

-- ---------------------------------------------------------------------------
-- Messages (async mail)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.messages}} (
    message_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    recipient_project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    from_agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    to_agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    from_alias TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL,
    priority TEXT NOT NULL DEFAULT 'normal',
    thread_id UUID,
    read_at TIMESTAMPTZ,
    from_did TEXT,
    to_did TEXT,
    from_stable_id TEXT,
    to_stable_id TEXT,
    signature TEXT,
    signing_key_id TEXT,
    signed_payload TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_messages_inbox
ON {{tables.messages}} (recipient_project_id, to_agent_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_messages_unread
ON {{tables.messages}} (recipient_project_id, to_agent_id, read_at)
WHERE read_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_messages_project_created
ON {{tables.messages}} (project_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- Chat
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.chat_sessions}} (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    participant_hash TEXT NOT NULL,
    wait_seconds INTEGER,
    wait_started_at TIMESTAMPTZ,
    wait_started_by_agent_id UUID REFERENCES {{tables.agents}}(agent_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_chat_sessions_wait_seconds CHECK (wait_seconds IS NULL OR wait_seconds >= 1),
    UNIQUE (participant_hash)
);

CREATE INDEX IF NOT EXISTS idx_chat_sessions_project_created
ON {{tables.chat_sessions}} (project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS {{tables.chat_session_participants}} (
    session_id UUID NOT NULL REFERENCES {{tables.chat_sessions}}(session_id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    alias TEXT NOT NULL,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (session_id, agent_id)
);

CREATE TABLE IF NOT EXISTS {{tables.chat_messages}} (
    message_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES {{tables.chat_sessions}}(session_id) ON DELETE CASCADE,
    from_agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    from_alias TEXT NOT NULL,
    body TEXT NOT NULL,
    reply_to_message_id UUID REFERENCES {{tables.chat_messages}}(message_id),
    sender_leaving BOOLEAN NOT NULL DEFAULT FALSE,
    hang_on BOOLEAN NOT NULL DEFAULT FALSE,
    from_did TEXT,
    to_did TEXT,
    from_stable_id TEXT,
    to_stable_id TEXT,
    signature TEXT,
    signing_key_id TEXT,
    signed_payload TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_session_created
ON {{tables.chat_messages}} (session_id, created_at ASC);

CREATE INDEX IF NOT EXISTS idx_chat_messages_reply_to
ON {{tables.chat_messages}} (reply_to_message_id)
WHERE reply_to_message_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS {{tables.chat_read_receipts}} (
    session_id UUID NOT NULL REFERENCES {{tables.chat_sessions}}(session_id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    last_read_message_id UUID REFERENCES {{tables.chat_messages}}(message_id) ON DELETE SET NULL,
    last_read_at TIMESTAMPTZ,
    PRIMARY KEY (session_id, agent_id)
);

-- ---------------------------------------------------------------------------
-- Contacts
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.contacts}} (
    contact_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    contact_address TEXT NOT NULL,
    label TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_contacts_project_address
ON {{tables.contacts}} (project_id, contact_address);

-- ---------------------------------------------------------------------------
-- Agent audit log
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.agent_log}} (
    log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    project_id UUID NOT NULL,
    operation TEXT NOT NULL,
    old_did TEXT,
    new_did TEXT,
    signed_by TEXT,
    entry_signature TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_log_agent_id
ON {{tables.agent_log}} (agent_id, created_at);

-- ---------------------------------------------------------------------------
-- Rotation announcements
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.rotation_announcements}} (
    announcement_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    project_id UUID NOT NULL,
    old_did TEXT NOT NULL,
    new_did TEXT NOT NULL,
    rotation_timestamp TEXT NOT NULL,
    old_key_signature TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rotation_announcements_agent
ON {{tables.rotation_announcements}} (agent_id, created_at DESC);

CREATE TABLE IF NOT EXISTS {{tables.rotation_peer_acks}} (
    announcement_id UUID NOT NULL REFERENCES {{tables.rotation_announcements}}(announcement_id),
    peer_agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    notified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ,
    PRIMARY KEY (announcement_id, peer_agent_id)
);

-- ---------------------------------------------------------------------------
-- Control signals
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.control_signals}} (
    signal_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    target_agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    from_agent_id UUID REFERENCES {{tables.agents}}(agent_id),
    signal_type TEXT NOT NULL CHECK (signal_type IN ('pause', 'resume', 'interrupt')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_control_signals_pending
ON {{tables.control_signals}} (project_id, target_agent_id)
WHERE consumed_at IS NULL;
