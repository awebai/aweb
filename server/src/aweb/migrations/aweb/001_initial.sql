-- 001_initial.sql
-- Consolidated canonical aweb baseline.
--
-- This is the single-file baseline produced by aapm.6: it declares the
-- final clean schema directly (no historical ADD COLUMN / DROP COLUMN /
-- DROP CONSTRAINT replay). aapm rebuild path resets schema_migrations
-- checksums, so the chain that produced this state (the old 001..011)
-- does not need to be replayed against fresh databases.
--
-- Final-schema equivalence to the prior 001..011 chain is verified via
-- pg_dump --schema-only diff on two fresh databases (one with the old
-- chain applied, one with this file applied); see aweb-aapm6 packet for
-- evidence.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- Teams
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.teams}} (
    team_id         TEXT PRIMARY KEY,
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
    team_id         TEXT NOT NULL REFERENCES {{tables.teams}}(team_id),
    did_key         TEXT NOT NULL,
    did_aw          TEXT,
    address         TEXT,
    alias           TEXT NOT NULL,
    human_name      TEXT NOT NULL DEFAULT '',
    agent_type      TEXT NOT NULL DEFAULT 'agent',
    role            TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'retired', 'archived', 'deleted')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,
    inbound_mode    TEXT
                    CONSTRAINT agents_inbound_mode_valid
                    CHECK (inbound_mode IS NULL OR inbound_mode IN
                        ('open', 'contacts_only')),
    identity_scope  TEXT NOT NULL DEFAULT 'local'
                    CONSTRAINT agents_identity_scope_valid
                    CHECK (identity_scope IN ('global', 'local'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_active_alias
    ON {{tables.agents}} (team_id, alias)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_active_did_key
    ON {{tables.agents}} (team_id, did_key)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_agents_did_aw
    ON {{tables.agents}} (did_aw) WHERE did_aw IS NOT NULL AND deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- Conversations — declared before messages/chat tables so messages can
-- FK the conversation_id column directly.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.conversations}} (
    conversation_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_type TEXT NOT NULL
                      CHECK (conversation_type IN ('mail', 'chat')),
    status            TEXT NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active', 'closed', 'expired')),
    team_id           TEXT REFERENCES {{tables.teams}}(team_id),
    created_by_did    TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at         TIMESTAMPTZ,
    expires_at        TIMESTAMPTZ,
    CONSTRAINT conversations_created_by_did_not_blank
        CHECK (BTRIM(created_by_did) <> '')
);

CREATE INDEX IF NOT EXISTS idx_conversations_type_status
    ON {{tables.conversations}} (conversation_type, status, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_conversations_expires_at
    ON {{tables.conversations}} (expires_at)
    WHERE expires_at IS NOT NULL AND status = 'active';

CREATE OR REPLACE FUNCTION aweb.set_conversation_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.updated_at IS NOT DISTINCT FROM OLD.updated_at THEN
        NEW.updated_at = NOW();
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_conversations_updated_at
    BEFORE UPDATE ON {{tables.conversations}}
    FOR EACH ROW
    EXECUTE FUNCTION aweb.set_conversation_updated_at();

CREATE TABLE IF NOT EXISTS {{tables.conversation_participants}} (
    conversation_id UUID NOT NULL
                    REFERENCES {{tables.conversations}}(conversation_id)
                    ON DELETE CASCADE,
    did             TEXT NOT NULL,
    agent_id        UUID REFERENCES {{tables.agents}}(agent_id) ON DELETE SET NULL,
    alias           TEXT NOT NULL,
    address         TEXT,
    transport_hint  TEXT,
    role            TEXT NOT NULL DEFAULT 'participant'
                    CHECK (role IN ('participant', 'initiator')),
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivery_origin TEXT,
    current_did_key TEXT,
    PRIMARY KEY (conversation_id, did),
    CONSTRAINT conversation_participants_alias_not_blank
        CHECK (BTRIM(alias) <> ''),
    CONSTRAINT conversation_participants_reachable
        CHECK (
            NULLIF(BTRIM(COALESCE(address, '')), '') IS NOT NULL
            OR NULLIF(BTRIM(COALESCE(transport_hint, '')), '') IS NOT NULL
        )
);

CREATE INDEX IF NOT EXISTS idx_conversation_participants_did
    ON {{tables.conversation_participants}} (did, conversation_id);

CREATE INDEX IF NOT EXISTS idx_conversation_participants_agent
    ON {{tables.conversation_participants}} (agent_id, conversation_id)
    WHERE agent_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_conversation_participants_delivery_origin
    ON {{tables.conversation_participants}} (delivery_origin)
    WHERE delivery_origin IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Messages (async mail) — conversation_id column declared inline.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.messages}} (
    message_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_did        TEXT NOT NULL,
    to_did          TEXT NOT NULL,
    from_alias      TEXT NOT NULL DEFAULT '',
    from_address    TEXT,
    to_alias        TEXT NOT NULL DEFAULT '',
    subject         TEXT NOT NULL DEFAULT '',
    body            TEXT NOT NULL,
    priority        TEXT NOT NULL DEFAULT 'normal',
    team_id         TEXT REFERENCES {{tables.teams}}(team_id),
    from_agent_id   UUID REFERENCES {{tables.agents}}(agent_id),
    to_agent_id     UUID REFERENCES {{tables.agents}}(agent_id),
    signature       TEXT,
    signed_payload  TEXT,
    read_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    conversation_id UUID REFERENCES {{tables.conversations}}(conversation_id)
                    ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_inbox
    ON {{tables.messages}} (to_did, created_at)
    WHERE read_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_messages_conversation
    ON {{tables.messages}} (conversation_id, created_at)
    WHERE conversation_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Chat
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.chat_sessions}} (
    session_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         TEXT REFERENCES {{tables.teams}}(team_id),
    created_by      TEXT NOT NULL,
    wait_seconds    INTEGER,
    wait_started_at TIMESTAMPTZ,
    wait_started_by UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS {{tables.chat_participants}} (
    session_id      UUID NOT NULL REFERENCES {{tables.chat_sessions}}(session_id),
    did             TEXT NOT NULL,
    agent_id        UUID REFERENCES {{tables.agents}}(agent_id),
    alias           TEXT NOT NULL,
    address         TEXT,
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivery_origin TEXT,
    current_did_key TEXT,
    PRIMARY KEY (session_id, did)
);

CREATE INDEX IF NOT EXISTS idx_chat_participants_delivery_origin
    ON {{tables.chat_participants}} (delivery_origin)
    WHERE delivery_origin IS NOT NULL;

CREATE TABLE IF NOT EXISTS {{tables.chat_messages}} (
    message_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL REFERENCES {{tables.chat_sessions}}(session_id),
    from_agent_id   UUID REFERENCES {{tables.agents}}(agent_id),
    from_did        TEXT NOT NULL,
    from_alias      TEXT NOT NULL,
    from_address    TEXT,
    body            TEXT NOT NULL,
    reply_to        UUID,
    sender_leaving  BOOLEAN NOT NULL DEFAULT FALSE,
    hang_on         BOOLEAN NOT NULL DEFAULT FALSE,
    signature       TEXT,
    signed_payload  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_session
    ON {{tables.chat_messages}} (session_id, created_at);

CREATE TABLE IF NOT EXISTS {{tables.chat_read_receipts}} (
    session_id      UUID NOT NULL REFERENCES {{tables.chat_sessions}}(session_id),
    did             TEXT NOT NULL,
    agent_id        UUID REFERENCES {{tables.agents}}(agent_id),
    last_read_message_id UUID REFERENCES {{tables.chat_messages}}(message_id),
    last_read_at    TIMESTAMPTZ,
    PRIMARY KEY (session_id, did)
);

-- ---------------------------------------------------------------------------
-- Contacts — final shape with handle support and pending state.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.contacts}} (
    contact_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_did         TEXT NOT NULL,
    contact_address   TEXT,
    label             TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reference_type    TEXT NOT NULL DEFAULT 'identity',
    status            TEXT NOT NULL DEFAULT 'active',
    handle_namespace  TEXT,
    target_agent_name TEXT,

    UNIQUE (owner_did, contact_address),
    CONSTRAINT contacts_reference_type_valid
        CHECK (reference_type IN ('identity', 'handle')),
    CONSTRAINT contacts_status_valid
        CHECK (status IN ('pending', 'active')),
    CONSTRAINT contacts_reference_shape_valid
        CHECK (
            (
                reference_type = 'identity'
                AND contact_address IS NOT NULL
                AND handle_namespace IS NULL
                AND target_agent_name IS NULL
            )
            OR (
                reference_type = 'handle'
                AND contact_address IS NULL
                AND handle_namespace IS NOT NULL
            )
        )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_contacts_owner_handle_target
    ON {{tables.contacts}} (owner_did, handle_namespace, COALESCE(target_agent_name, ''))
    WHERE reference_type = 'handle';

-- ---------------------------------------------------------------------------
-- Control signals
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.control_signals}} (
    signal_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         TEXT NOT NULL REFERENCES {{tables.teams}}(team_id),
    target_agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    from_agent_id   UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    signal_type     TEXT NOT NULL
                    CHECK (signal_type IN ('pause', 'resume', 'interrupt')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_control_signals_pending
    ON {{tables.control_signals}} (team_id, target_agent_id, created_at)
    WHERE consumed_at IS NULL;

-- ---------------------------------------------------------------------------
-- Repos
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.repos}} (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         TEXT NOT NULL,
    origin_url      TEXT NOT NULL,
    canonical_origin TEXT NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,

    UNIQUE (team_id, canonical_origin)
);

-- ---------------------------------------------------------------------------
-- Workspaces
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.workspaces}} (
    workspace_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         TEXT NOT NULL,
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
    ON {{tables.workspaces}} (team_id, alias)
    WHERE deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- Tasks
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.tasks}} (
    task_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         TEXT NOT NULL,
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

    UNIQUE (team_id, task_number),
    UNIQUE (team_id, task_ref_suffix)
);

CREATE TABLE IF NOT EXISTS {{tables.task_comments}} (
    comment_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id         UUID NOT NULL REFERENCES {{tables.tasks}}(task_id),
    team_id         TEXT NOT NULL,
    author_alias    TEXT NOT NULL,
    body            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS {{tables.task_dependencies}} (
    task_id         UUID NOT NULL REFERENCES {{tables.tasks}}(task_id),
    depends_on_id   UUID NOT NULL REFERENCES {{tables.tasks}}(task_id),
    team_id         TEXT NOT NULL,
    PRIMARY KEY (task_id, depends_on_id)
);

CREATE TABLE IF NOT EXISTS {{tables.task_counters}} (
    team_id         TEXT PRIMARY KEY,
    next_number     INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS {{tables.task_root_counters}} (
    team_id         TEXT PRIMARY KEY,
    next_number     INTEGER NOT NULL DEFAULT 1
);

-- ---------------------------------------------------------------------------
-- Task claims
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.task_claims}} (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         TEXT NOT NULL,
    workspace_id    UUID NOT NULL,
    alias           TEXT NOT NULL,
    human_name      TEXT NOT NULL DEFAULT '',
    task_ref        TEXT NOT NULL,
    apex_task_ref   TEXT,
    claimed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (team_id, task_ref, workspace_id)
);

-- ---------------------------------------------------------------------------
-- Reservations (resource locks)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.reservations}} (
    team_id         TEXT NOT NULL,
    resource_key    TEXT NOT NULL,
    holder_alias    TEXT NOT NULL,
    holder_agent_id UUID NOT NULL,
    acquired_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    metadata_json   JSONB,

    PRIMARY KEY (team_id, resource_key)
);

-- ---------------------------------------------------------------------------
-- Roles (versioned per team)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.team_roles}} (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         TEXT NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    bundle_json     JSONB NOT NULL DEFAULT '[]',
    is_active       BOOLEAN NOT NULL DEFAULT FALSE,
    created_by_alias TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ,

    UNIQUE (team_id, version)
);

-- ---------------------------------------------------------------------------
-- Instructions (versioned per team)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.team_instructions}} (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         TEXT NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    document_json   JSONB NOT NULL DEFAULT '{}',
    is_active       BOOLEAN NOT NULL DEFAULT FALSE,
    created_by_alias TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ,

    UNIQUE (team_id, version)
);

-- ---------------------------------------------------------------------------
-- Audit log
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.audit_log}} (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         TEXT NOT NULL,
    alias           TEXT,
    event_type      TEXT NOT NULL,
    resource        TEXT,
    details         JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- Federated message deliveries (idempotency keys for inbound federation)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.federated_message_deliveries}} (
    message_type    TEXT NOT NULL
                    CHECK (message_type IN ('mail', 'chat')),
    sender_did_aw   TEXT NOT NULL,
    target_did_aw   TEXT NOT NULL,
    message_id      UUID NOT NULL,
    conversation_id UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (message_type, sender_did_aw, target_did_aw, message_id)
);
