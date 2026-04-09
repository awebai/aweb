-- 002_teams.sql
-- Teams and team certificate registration for the awid registry.

CREATE TABLE IF NOT EXISTS {{tables.teams}} (
    team_uuid       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain          TEXT NOT NULL,
    name            TEXT NOT NULL
                    CONSTRAINT chk_teams_name CHECK (name ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'),
    display_name    TEXT NOT NULL DEFAULT '',
    team_did_key    TEXT NOT NULL,
    created_by      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_teams_domain_name_active
    ON {{tables.teams}} (domain, name)
    WHERE deleted_at IS NULL;

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
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ,

    UNIQUE (team_uuid, certificate_id)
);

-- Active certificates: lookup by team + member key
CREATE INDEX IF NOT EXISTS idx_team_certificates_active
    ON {{tables.team_certificates}} (team_uuid, member_did_key)
    WHERE revoked_at IS NULL;

-- Team-member references are keyed by active (team, alias).
CREATE UNIQUE INDEX IF NOT EXISTS idx_team_certificates_alias_active
    ON {{tables.team_certificates}} (team_uuid, alias)
    WHERE revoked_at IS NULL;

-- Revoked certificates: lookup for revocation list queries
CREATE INDEX IF NOT EXISTS idx_team_certificates_revoked
    ON {{tables.team_certificates}} (team_uuid, revoked_at)
    WHERE revoked_at IS NOT NULL;
