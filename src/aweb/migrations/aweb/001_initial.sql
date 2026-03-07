-- Consolidated aweb schema — all tables, indexes, and constraints.
-- Replaces migrations 001–022 from the pre-reset era (tag: pre-schema-reset).
-- Includes beadhub integration additions: policies, agent profile fields.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- Namespaces
-- ---------------------------------------------------------------------------

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

-- ---------------------------------------------------------------------------
-- Projects
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.projects}} (
    project_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    tenant_id UUID,
    namespace_id UUID REFERENCES {{tables.namespaces}}(namespace_id),
    active_policy_id UUID,  -- FK added after policies table is created
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- OSS: one project per slug (no tenant)
CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_slug_unique_active_oss
ON {{tables.projects}} (slug)
WHERE tenant_id IS NULL AND deleted_at IS NULL;

-- Cloud: one project per slug per tenant
CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_tenant_slug_unique_active
ON {{tables.projects}} (tenant_id, slug)
WHERE tenant_id IS NOT NULL AND deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_projects_namespace
ON {{tables.projects}} (namespace_id);

-- ---------------------------------------------------------------------------
-- Agents
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.agents}} (
    agent_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    namespace_id UUID REFERENCES {{tables.namespaces}}(namespace_id),
    alias TEXT NOT NULL,
    human_name TEXT NOT NULL DEFAULT '',
    agent_type TEXT NOT NULL DEFAULT 'agent',
    access_mode TEXT NOT NULL DEFAULT 'open',
    -- Cryptographic identity
    did TEXT,
    public_key TEXT,
    custody TEXT,
    signing_key_enc BYTEA,
    stable_id TEXT,
    -- Lifecycle
    lifetime TEXT NOT NULL DEFAULT 'persistent',
    status TEXT NOT NULL DEFAULT 'active',
    successor_agent_id UUID REFERENCES {{tables.agents}}(agent_id),
    -- Profile (beadhub integration)
    role TEXT,
    program TEXT,
    context JSONB,
    --
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    --
    CONSTRAINT chk_agents_alias_no_slash CHECK (POSITION('/' IN alias) = 0),
    CONSTRAINT chk_agents_access_mode CHECK (access_mode IN ('open', 'contacts_only')),
    CONSTRAINT chk_agents_custody CHECK (custody IN ('self', 'custodial')),
    CONSTRAINT chk_agents_lifetime CHECK (lifetime IN ('persistent', 'ephemeral')),
    CONSTRAINT chk_agents_status CHECK (status IN ('active', 'retired', 'deregistered'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_project_alias_unique_active
ON {{tables.agents}} (project_id, alias)
WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_namespace_alias_unique_active
ON {{tables.agents}} (namespace_id, alias)
WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_did_unique_active
ON {{tables.agents}} (project_id, did)
WHERE deleted_at IS NULL AND did IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_agents_did
ON {{tables.agents}} (did)
WHERE deleted_at IS NULL AND did IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_agents_stable_id
ON {{tables.agents}} (stable_id)
WHERE deleted_at IS NULL AND stable_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_agents_namespace
ON {{tables.agents}} (namespace_id);

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
-- Messages (async mail)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.messages}} (
    message_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    from_agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    to_agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    from_alias TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL,
    priority TEXT NOT NULL DEFAULT 'normal',
    thread_id UUID,
    read_at TIMESTAMPTZ,
    -- Identity fields
    from_did TEXT,
    to_did TEXT,
    from_stable_id TEXT,
    to_stable_id TEXT,
    signature TEXT,
    signing_key_id TEXT,
    --
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_messages_inbox
ON {{tables.messages}} (project_id, to_agent_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_messages_unread
ON {{tables.messages}} (project_id, to_agent_id, read_at)
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
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, participant_hash)
);

CREATE INDEX IF NOT EXISTS idx_chat_sessions_project_created
ON {{tables.chat_sessions}} (project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS {{tables.chat_session_participants}} (
    session_id UUID NOT NULL REFERENCES {{tables.chat_sessions}}(session_id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
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
    sender_leaving BOOLEAN NOT NULL DEFAULT FALSE,
    hang_on BOOLEAN NOT NULL DEFAULT FALSE,
    -- Identity fields
    from_did TEXT,
    to_did TEXT,
    from_stable_id TEXT,
    to_stable_id TEXT,
    signature TEXT,
    signing_key_id TEXT,
    --
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_session_created
ON {{tables.chat_messages}} (session_id, created_at ASC);

CREATE TABLE IF NOT EXISTS {{tables.chat_read_receipts}} (
    session_id UUID NOT NULL REFERENCES {{tables.chat_sessions}}(session_id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    last_read_message_id UUID,
    last_read_at TIMESTAMPTZ,
    PRIMARY KEY (session_id, agent_id)
);

-- ---------------------------------------------------------------------------
-- Reservations (resource locks)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.reservations}} (
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    resource_key TEXT NOT NULL,
    holder_agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    holder_alias TEXT NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (project_id, resource_key)
);

CREATE INDEX IF NOT EXISTS idx_reservations_project_expires
ON {{tables.reservations}} (project_id, expires_at);

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
-- Tasks
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.task_counters}} (
    project_id UUID PRIMARY KEY REFERENCES {{tables.projects}}(project_id),
    next_number INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS {{tables.tasks}} (
    task_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    task_number INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    priority INTEGER NOT NULL DEFAULT 2,
    task_type TEXT NOT NULL DEFAULT 'task',
    assignee_agent_id UUID REFERENCES {{tables.agents}}(agent_id),
    created_by_agent_id UUID REFERENCES {{tables.agents}}(agent_id),
    closed_by_agent_id UUID REFERENCES {{tables.agents}}(agent_id),
    labels TEXT[] NOT NULL DEFAULT '{}',
    parent_task_id UUID REFERENCES {{tables.tasks}}(task_id),
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at TIMESTAMPTZ,
    --
    UNIQUE (project_id, task_number),
    CONSTRAINT chk_tasks_status CHECK (status IN ('open', 'in_progress', 'closed')),
    CONSTRAINT chk_tasks_priority CHECK (priority >= 0 AND priority <= 4),
    CONSTRAINT chk_tasks_type CHECK (task_type IN ('task', 'bug', 'feature'))
);

CREATE INDEX IF NOT EXISTS idx_tasks_project_status
ON {{tables.tasks}} (project_id, status)
WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_tasks_project_assignee
ON {{tables.tasks}} (project_id, assignee_agent_id)
WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_tasks_parent
ON {{tables.tasks}} (parent_task_id)
WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS {{tables.task_dependencies}} (
    task_id UUID NOT NULL REFERENCES {{tables.tasks}}(task_id) ON DELETE CASCADE,
    depends_on_task_id UUID NOT NULL REFERENCES {{tables.tasks}}(task_id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (task_id, depends_on_task_id),
    CONSTRAINT chk_task_dep_no_self CHECK (task_id != depends_on_task_id)
);

CREATE TABLE IF NOT EXISTS {{tables.task_comments}} (
    comment_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id UUID NOT NULL REFERENCES {{tables.tasks}}(task_id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_task_comments_task
ON {{tables.task_comments}} (task_id, created_at);

-- ---------------------------------------------------------------------------
-- Policies (versioned project governance)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.policies}} (
    policy_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    version INTEGER NOT NULL,
    content JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_project_version
ON {{tables.policies}} (project_id, version);

-- Now that policies table exists, add the FK from projects.
ALTER TABLE {{tables.projects}}
    ADD CONSTRAINT fk_projects_active_policy
    FOREIGN KEY (active_policy_id)
    REFERENCES {{tables.policies}}(policy_id);
