-- 001_initial.sql
-- Consolidated aweb schema: teams, agents, and all coordination tables.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- Teams
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.teams}} (
    team_address    TEXT PRIMARY KEY,
    namespace       TEXT NOT NULL,
    team_name       TEXT NOT NULL,
    team_did_key    TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- Agents
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.agents}} (
    agent_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL REFERENCES {{tables.teams}}(team_address),
    did_key         TEXT NOT NULL,
    did_aw          TEXT,
    address         TEXT,
    alias           TEXT NOT NULL,
    lifetime        TEXT NOT NULL DEFAULT 'ephemeral'
                    CHECK (lifetime IN ('permanent', 'ephemeral')),
    human_name      TEXT NOT NULL DEFAULT '',
    agent_type      TEXT NOT NULL DEFAULT 'agent',
    role            TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'retired', 'deleted')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,

    UNIQUE (team_address, alias)
);

CREATE INDEX IF NOT EXISTS idx_agents_did_key
    ON {{tables.agents}} (did_key) WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_agents_did_aw
    ON {{tables.agents}} (did_aw) WHERE did_aw IS NOT NULL AND deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- Messages (async mail)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.messages}} (
    message_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL REFERENCES {{tables.teams}}(team_address),
    from_agent_id   UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    to_agent_id     UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    from_alias      TEXT NOT NULL,
    to_alias        TEXT NOT NULL,
    subject         TEXT NOT NULL DEFAULT '',
    body            TEXT NOT NULL,
    priority        TEXT NOT NULL DEFAULT 'normal',
    from_did        TEXT,
    signature       TEXT,
    signed_payload  TEXT,
    read_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_messages_inbox
    ON {{tables.messages}} (team_address, to_agent_id, created_at)
    WHERE read_at IS NULL;

-- ---------------------------------------------------------------------------
-- Chat
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.chat_sessions}} (
    session_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL REFERENCES {{tables.teams}}(team_address),
    created_by      TEXT NOT NULL,
    wait_seconds    INTEGER,
    wait_started_at TIMESTAMPTZ,
    wait_started_by UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS {{tables.chat_participants}} (
    session_id      UUID NOT NULL REFERENCES {{tables.chat_sessions}}(session_id),
    agent_id        UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    alias           TEXT NOT NULL,
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (session_id, agent_id)
);

CREATE TABLE IF NOT EXISTS {{tables.chat_messages}} (
    message_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL REFERENCES {{tables.chat_sessions}}(session_id),
    from_agent_id   UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    from_alias      TEXT NOT NULL,
    body            TEXT NOT NULL,
    reply_to        UUID,
    sender_leaving  BOOLEAN NOT NULL DEFAULT FALSE,
    hang_on         BOOLEAN NOT NULL DEFAULT FALSE,
    from_did        TEXT,
    signature       TEXT,
    signed_payload  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_session
    ON {{tables.chat_messages}} (session_id, created_at);

CREATE TABLE IF NOT EXISTS {{tables.chat_read_receipts}} (
    session_id      UUID NOT NULL REFERENCES {{tables.chat_sessions}}(session_id),
    agent_id        UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    last_read_message_id UUID REFERENCES {{tables.chat_messages}}(message_id),
    last_read_at    TIMESTAMPTZ,
    PRIMARY KEY (session_id, agent_id)
);

-- ---------------------------------------------------------------------------
-- Contacts
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.contacts}} (
    contact_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL REFERENCES {{tables.teams}}(team_address),
    contact_address TEXT NOT NULL,
    label           TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (team_address, contact_address)
);

-- ---------------------------------------------------------------------------
-- Control signals
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.control_signals}} (
    signal_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL REFERENCES {{tables.teams}}(team_address),
    target_agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    from_agent_id   UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    signal_type     TEXT NOT NULL
                    CHECK (signal_type IN ('pause', 'resume', 'interrupt')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_control_signals_pending
    ON {{tables.control_signals}} (team_address, target_agent_id, created_at)
    WHERE consumed_at IS NULL;

-- ---------------------------------------------------------------------------
-- Repos
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.repos}} (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL,
    origin_url      TEXT NOT NULL,
    canonical_origin TEXT NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,

    UNIQUE (team_address, canonical_origin)
);

-- ---------------------------------------------------------------------------
-- Workspaces
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.workspaces}} (
    workspace_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL,
    agent_id        UUID NOT NULL,
    repo_id         UUID REFERENCES {{tables.repos}}(id),
    alias           TEXT NOT NULL,
    human_name      TEXT NOT NULL DEFAULT '',
    role            TEXT,
    hostname        TEXT,
    workspace_path  TEXT,
    workspace_type  TEXT NOT NULL DEFAULT 'manual',
    focus_task_ref  TEXT,
    focus_updated_at TIMESTAMPTZ,
    last_seen_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ,
    deleted_at      TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_workspaces_active_alias
    ON {{tables.workspaces}} (team_address, alias)
    WHERE deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- Tasks
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.tasks}} (
    task_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL,
    task_number     INTEGER NOT NULL,
    root_task_seq   INTEGER,
    task_ref_suffix TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    notes           TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'in_progress', 'closed')),
    priority        INTEGER NOT NULL DEFAULT 2
                    CHECK (priority BETWEEN 0 AND 4),
    task_type       TEXT NOT NULL DEFAULT 'task'
                    CHECK (task_type IN ('task', 'bug', 'feature', 'epic', 'chore')),
    assignee_alias  TEXT,
    created_by_alias TEXT,
    closed_by_alias TEXT,
    labels          TEXT[] NOT NULL DEFAULT '{}',
    parent_task_id  UUID REFERENCES {{tables.tasks}}(task_id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ,
    closed_at       TIMESTAMPTZ,
    deleted_at      TIMESTAMPTZ,

    UNIQUE (team_address, task_number),
    UNIQUE (team_address, task_ref_suffix)
);

CREATE TABLE IF NOT EXISTS {{tables.task_comments}} (
    comment_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id         UUID NOT NULL REFERENCES {{tables.tasks}}(task_id),
    team_address    TEXT NOT NULL,
    author_alias    TEXT NOT NULL,
    body            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS {{tables.task_dependencies}} (
    task_id         UUID NOT NULL REFERENCES {{tables.tasks}}(task_id),
    depends_on_id   UUID NOT NULL REFERENCES {{tables.tasks}}(task_id),
    team_address    TEXT NOT NULL,
    PRIMARY KEY (task_id, depends_on_id)
);

CREATE TABLE IF NOT EXISTS {{tables.task_counters}} (
    team_address    TEXT PRIMARY KEY,
    next_number     INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS {{tables.task_root_counters}} (
    team_address    TEXT PRIMARY KEY,
    next_number     INTEGER NOT NULL DEFAULT 1
);

-- ---------------------------------------------------------------------------
-- Task claims
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.task_claims}} (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL,
    workspace_id    UUID NOT NULL,
    alias           TEXT NOT NULL,
    human_name      TEXT NOT NULL DEFAULT '',
    task_ref        TEXT NOT NULL,
    apex_task_ref   TEXT,
    claimed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (team_address, task_ref, workspace_id)
);

-- ---------------------------------------------------------------------------
-- Reservations (resource locks)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.reservations}} (
    team_address    TEXT NOT NULL,
    resource_key    TEXT NOT NULL,
    holder_alias    TEXT NOT NULL,
    holder_agent_id UUID NOT NULL,
    acquired_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    metadata_json   JSONB,

    PRIMARY KEY (team_address, resource_key)
);

-- ---------------------------------------------------------------------------
-- Roles (versioned per team)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.project_roles}} (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    bundle_json     JSONB NOT NULL DEFAULT '[]',
    is_active       BOOLEAN NOT NULL DEFAULT FALSE,
    created_by_alias TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ,

    UNIQUE (team_address, version)
);

-- ---------------------------------------------------------------------------
-- Instructions (versioned per team)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.project_instructions}} (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    document_json   JSONB NOT NULL DEFAULT '{}',
    is_active       BOOLEAN NOT NULL DEFAULT FALSE,
    created_by_alias TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ,

    UNIQUE (team_address, version)
);

-- ---------------------------------------------------------------------------
-- Audit log
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.audit_log}} (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL,
    alias           TEXT,
    event_type      TEXT NOT NULL,
    resource        TEXT,
    details         JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
