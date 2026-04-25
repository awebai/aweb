-- 001_registry.sql
-- Identity resolution tables for the awid registry:
-- DID mappings, audit log, DNS namespaces, public addresses,
-- replacement announcements, teams, and team certificates.

-- DID:aw resolution
CREATE TABLE IF NOT EXISTS {{tables.did_aw_mappings}} (
    did_aw          TEXT PRIMARY KEY,
    current_did_key TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS {{tables.did_aw_log}} (
    did_aw          TEXT NOT NULL REFERENCES {{tables.did_aw_mappings}}(did_aw) ON DELETE CASCADE,
    seq             INTEGER NOT NULL,
    operation       TEXT NOT NULL,
    previous_did_key TEXT,
    new_did_key     TEXT NOT NULL,
    prev_entry_hash TEXT,
    entry_hash      TEXT NOT NULL,
    state_hash      TEXT NOT NULL,
    authorized_by   TEXT NOT NULL,
    signature       TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (did_aw, seq)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_did_aw_log_entry_hash
    ON {{tables.did_aw_log}} (entry_hash);

CREATE INDEX IF NOT EXISTS idx_did_aw_log_head
    ON {{tables.did_aw_log}} (did_aw, seq DESC);

-- DNS namespaces
CREATE TABLE IF NOT EXISTS {{tables.dns_namespaces}} (
    namespace_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain          TEXT NOT NULL,
    controller_did  TEXT,
    verification_status TEXT NOT NULL DEFAULT 'unverified',
    last_verified_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,
    scope_id        UUID,
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

-- Public addresses
CREATE TABLE IF NOT EXISTS {{tables.public_addresses}} (
    address_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace_id    UUID NOT NULL REFERENCES {{tables.dns_namespaces}}(namespace_id),
    name            TEXT NOT NULL,
    did_aw          TEXT NOT NULL REFERENCES {{tables.did_aw_mappings}}(did_aw),
    reachability    TEXT NOT NULL DEFAULT 'nobody',
    visible_to_team_id TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,
    CONSTRAINT chk_public_addresses_name_not_empty CHECK (name <> ''),
    CONSTRAINT chk_public_addresses_name_no_slash CHECK (POSITION('/' IN name) = 0),
    CONSTRAINT chk_public_addresses_name_no_dot CHECK (POSITION('.' IN name) = 0),
    CONSTRAINT chk_public_addresses_name_no_tilde CHECK (POSITION('~' IN name) = 0),
    CONSTRAINT chk_public_addresses_did_aw_prefix CHECK (did_aw LIKE 'did:aw:%'),
    CONSTRAINT chk_public_addresses_reachability
        CHECK (reachability IN ('nobody', 'org_only', 'team_members_only', 'public')),
    CONSTRAINT chk_public_addresses_visible_to_team_id
        CHECK (
            (reachability = 'team_members_only' AND visible_to_team_id IS NOT NULL)
            OR (reachability != 'team_members_only' AND visible_to_team_id IS NULL)
        )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_public_addresses_namespace_name_active
    ON {{tables.public_addresses}} (namespace_id, name)
    WHERE deleted_at IS NULL;

-- Replacement announcements
CREATE TABLE IF NOT EXISTS {{tables.replacement_announcements}} (
    announcement_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    namespace_id    UUID NOT NULL REFERENCES {{tables.dns_namespaces}}(namespace_id),
    address_name    TEXT NOT NULL,
    old_did         TEXT NOT NULL,
    new_did         TEXT NOT NULL,
    controller_did  TEXT NOT NULL,
    replacement_timestamp TEXT NOT NULL,
    controller_signature TEXT NOT NULL,
    authorized_by   TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_replacement_announcements_address_new_did
    ON {{tables.replacement_announcements}} (namespace_id, address_name, new_did);

-- Teams
CREATE TABLE IF NOT EXISTS {{tables.teams}} (
    team_uuid       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain          TEXT NOT NULL,
    name            TEXT NOT NULL
                    CONSTRAINT chk_teams_name CHECK (name ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'),
    display_name    TEXT NOT NULL DEFAULT '',
    team_did_key    TEXT NOT NULL,
    visibility      TEXT NOT NULL DEFAULT 'private'
                    CHECK (visibility IN ('public', 'private')),
    created_by      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_teams_domain_name_active
    ON {{tables.teams}} (domain, name)
    WHERE deleted_at IS NULL;

-- Team certificates
CREATE TABLE IF NOT EXISTS {{tables.team_certificates}} (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_uuid       UUID NOT NULL REFERENCES {{tables.teams}}(team_uuid),
    certificate_id  TEXT NOT NULL,
    member_did_key  TEXT NOT NULL,
    member_did_aw   TEXT,
    member_address  TEXT,
    alias           TEXT NOT NULL,
    lifetime        TEXT NOT NULL DEFAULT 'persistent'
                    CHECK (lifetime IN ('persistent', 'ephemeral')),
    certificate     TEXT,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ,

    UNIQUE (team_uuid, certificate_id)
);

CREATE INDEX IF NOT EXISTS idx_team_certificates_active
    ON {{tables.team_certificates}} (team_uuid, member_did_key)
    WHERE revoked_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_team_certificates_alias_active
    ON {{tables.team_certificates}} (team_uuid, alias)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_team_certificates_revoked
    ON {{tables.team_certificates}} (team_uuid, revoked_at)
    WHERE revoked_at IS NOT NULL;
