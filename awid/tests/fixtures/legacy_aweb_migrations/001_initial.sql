-- 001_initial.sql
-- Frozen legacy aweb source schema for awid migrate tests.
--
-- This fixture intentionally preserves the pre-consolidation identity tables
-- so awid can keep testing migration-from-aweb behavior after aweb's live
-- schema removes them from its current baseline.
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

-- ---------------------------------------------------------------------------
-- DID:aw resolution
-- ---------------------------------------------------------------------------

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

-- ---------------------------------------------------------------------------
-- DNS namespaces and public addresses
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.dns_namespaces}} (
    namespace_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain TEXT NOT NULL,
    controller_did TEXT,
    verification_status TEXT NOT NULL DEFAULT 'unverified',
    last_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    namespace_type TEXT NOT NULL DEFAULT 'dns_verified',
    scope_id UUID REFERENCES {{tables.projects}}(project_id),
    CONSTRAINT chk_dns_namespaces_status CHECK (
        verification_status IN ('verified', 'unverified', 'revoked')
    ),
    CONSTRAINT chk_dns_namespaces_type CHECK (
        namespace_type IN ('dns_verified', 'managed')
    ),
    CONSTRAINT chk_dns_namespaces_type_fields CHECK (
        (namespace_type = 'managed' AND scope_id IS NOT NULL AND controller_did IS NULL)
        OR
        (namespace_type = 'dns_verified' AND controller_did IS NOT NULL)
    )
);

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

-- ---------------------------------------------------------------------------
-- Replacement announcements
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.replacement_announcements}} (
    announcement_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    old_agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    new_agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    namespace_id UUID NOT NULL REFERENCES {{tables.dns_namespaces}}(namespace_id),
    address_name TEXT NOT NULL,
    old_did TEXT NOT NULL,
    new_did TEXT NOT NULL,
    controller_did TEXT NOT NULL,
    replacement_timestamp TEXT NOT NULL,
    controller_signature TEXT NOT NULL,
    authorized_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
