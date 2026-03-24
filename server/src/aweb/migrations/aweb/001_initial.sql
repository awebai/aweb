-- 001_initial.sql
-- Description: Clean baseline for the embedded aweb protocol schema.
-- Fresh installs should derive the full embedded core schema from this file alone.
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
    -- Optional profile fields consumed by coordination layers
    role TEXT,
    program TEXT,
    context JSONB,
    --
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    --
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
    -- Identity fields
    from_did TEXT,
    to_did TEXT,
    from_stable_id TEXT,
    to_stable_id TEXT,
    signature TEXT,
    signing_key_id TEXT,
    signed_payload TEXT,
    --
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
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
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
    sender_leaving BOOLEAN NOT NULL DEFAULT FALSE,
    hang_on BOOLEAN NOT NULL DEFAULT FALSE,
    -- Identity fields
    from_did TEXT,
    to_did TEXT,
    from_stable_id TEXT,
    to_stable_id TEXT,
    signature TEXT,
    signing_key_id TEXT,
    signed_payload TEXT,
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

CREATE TABLE IF NOT EXISTS {{tables.task_root_counters}} (
    project_id UUID PRIMARY KEY REFERENCES {{tables.projects}}(project_id),
    next_number INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS {{tables.tasks}} (
    task_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    task_number INTEGER NOT NULL,
    root_task_seq INTEGER NOT NULL,
    task_ref_suffix TEXT NOT NULL,
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
    UNIQUE (project_id, task_ref_suffix),
    CONSTRAINT chk_tasks_status CHECK (status IN ('open', 'in_progress', 'closed')),
    CONSTRAINT chk_tasks_priority CHECK (priority >= 0 AND priority <= 4),
    CONSTRAINT chk_tasks_type CHECK (task_type IN ('task', 'bug', 'feature', 'epic', 'chore'))
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
CREATE TABLE {{tables.control_signals}} (
    signal_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    target_agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    from_agent_id UUID REFERENCES {{tables.agents}}(agent_id),
    signal_type TEXT NOT NULL CHECK (signal_type IN ('pause', 'resume', 'interrupt')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at TIMESTAMPTZ
);

CREATE INDEX idx_control_signals_pending
ON {{tables.control_signals}} (project_id, target_agent_id)
WHERE consumed_at IS NULL;
ALTER TABLE {{tables.chat_read_receipts}}
    ADD CONSTRAINT fk_chat_read_receipts_last_read_message
    FOREIGN KEY (last_read_message_id)
    REFERENCES {{tables.chat_messages}}(message_id)
    ON DELETE SET NULL;
CREATE TABLE IF NOT EXISTS {{tables.did_aw_mappings}} (
    did_aw TEXT PRIMARY KEY,
    current_did_key TEXT NOT NULL,
    server_url TEXT NOT NULL,
    address TEXT NOT NULL,
    handle TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS {{tables.did_aw_log}} (
    did_aw TEXT NOT NULL REFERENCES {{tables.did_aw_mappings}}(did_aw) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    operation TEXT NOT NULL,
    previous_did_key TEXT,
    new_did_key TEXT NOT NULL,
    prev_entry_hash TEXT,
    entry_hash TEXT NOT NULL,
    state_hash TEXT NOT NULL,
    authorized_by TEXT NOT NULL,
    signature TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (did_aw, seq)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_did_aw_log_entry_hash
ON {{tables.did_aw_log}} (entry_hash);

CREATE INDEX IF NOT EXISTS idx_did_aw_log_head
ON {{tables.did_aw_log}} (did_aw, seq DESC);
SELECT 1;
CREATE TABLE IF NOT EXISTS {{tables.dns_namespaces}} (
    namespace_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain TEXT NOT NULL,
    controller_did TEXT NOT NULL,
    verification_status TEXT NOT NULL DEFAULT 'unverified',
    last_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT chk_dns_namespaces_status CHECK (
        verification_status IN ('verified', 'unverified', 'revoked')
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_namespaces_domain_unique_active
ON {{tables.dns_namespaces}} (domain)
WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_dns_namespaces_controller_did
ON {{tables.dns_namespaces}} (controller_did)
WHERE deleted_at IS NULL;
CREATE TABLE IF NOT EXISTS {{tables.public_addresses}} (
    address_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace_id UUID NOT NULL REFERENCES {{tables.dns_namespaces}}(namespace_id),
    name TEXT NOT NULL,
    did_aw TEXT NOT NULL,
    current_did_key TEXT NOT NULL,
    reachability TEXT NOT NULL DEFAULT 'private',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT chk_public_addresses_name_not_empty CHECK (name <> ''),
    CONSTRAINT chk_public_addresses_name_no_slash CHECK (POSITION('/' IN name) = 0),
    CONSTRAINT chk_public_addresses_name_no_dot CHECK (POSITION('.' IN name) = 0),
    CONSTRAINT chk_public_addresses_name_no_tilde CHECK (POSITION('~' IN name) = 0),
    CONSTRAINT chk_public_addresses_did_aw_prefix CHECK (did_aw LIKE 'did:aw:%'),
    CONSTRAINT chk_public_addresses_reachability
        CHECK (reachability IN ('private', 'org_visible', 'contacts_only', 'public'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_public_addresses_namespace_name_active
ON {{tables.public_addresses}} (namespace_id, name)
WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_public_addresses_did_aw_active
ON {{tables.public_addresses}} (did_aw)
WHERE deleted_at IS NULL;
DROP TABLE IF EXISTS {{tables.task_comments}};
DROP TABLE IF EXISTS {{tables.task_dependencies}};
DROP TABLE IF EXISTS {{tables.tasks}};
DROP TABLE IF EXISTS {{tables.task_root_counters}};
DROP TABLE IF EXISTS {{tables.task_counters}};
DROP TABLE IF EXISTS {{tables.reservations}};
ALTER TABLE {{tables.projects}}
    DROP CONSTRAINT IF EXISTS fk_projects_active_policy;

ALTER TABLE {{tables.projects}}
    DROP COLUMN IF EXISTS active_policy_id;

DROP TABLE IF EXISTS {{tables.policies}};
ALTER TABLE {{tables.dns_namespaces}}
    ALTER COLUMN controller_did DROP NOT NULL;

ALTER TABLE {{tables.dns_namespaces}}
    ADD COLUMN namespace_type TEXT NOT NULL DEFAULT 'dns_verified';

ALTER TABLE {{tables.dns_namespaces}}
    ADD COLUMN scope_id UUID REFERENCES {{tables.projects}}(project_id);

ALTER TABLE {{tables.dns_namespaces}}
    ADD CONSTRAINT chk_dns_namespaces_type
        CHECK (namespace_type IN ('dns_verified', 'managed'));

ALTER TABLE {{tables.dns_namespaces}}
    ADD CONSTRAINT chk_dns_namespaces_type_fields
        CHECK (
            (namespace_type = 'managed' AND scope_id IS NOT NULL AND controller_did IS NULL)
            OR
            (namespace_type = 'dns_verified' AND controller_did IS NOT NULL)
        );

CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_namespaces_scope_unique_active
ON {{tables.dns_namespaces}} (scope_id)
WHERE deleted_at IS NULL AND namespace_type = 'managed';
DROP INDEX IF EXISTS {{schema}}.idx_public_addresses_did_aw_active;
ALTER TABLE {{tables.messages}}
ADD COLUMN IF NOT EXISTS signed_payload TEXT;

ALTER TABLE {{tables.chat_messages}}
ADD COLUMN IF NOT EXISTS signed_payload TEXT;
