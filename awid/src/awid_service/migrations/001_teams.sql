-- 001_teams.sql
-- Teams and team certificate registration for the awid registry.

CREATE TABLE IF NOT EXISTS {{tables.teams}} (
    team_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain          TEXT NOT NULL,
    name            TEXT NOT NULL,
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
    team_id         UUID NOT NULL REFERENCES {{tables.teams}}(team_id),
    certificate_id  TEXT NOT NULL,
    member_did_key  TEXT NOT NULL,
    member_did_aw   TEXT,
    member_address  TEXT,
    alias           TEXT NOT NULL,
    lifetime        TEXT NOT NULL DEFAULT 'permanent'
                    CHECK (lifetime IN ('permanent', 'ephemeral')),
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ,

    UNIQUE (team_id, certificate_id)
);

-- Active certificates: lookup by team + member key
CREATE INDEX IF NOT EXISTS idx_team_certificates_active
    ON {{tables.team_certificates}} (team_id, member_did_key)
    WHERE revoked_at IS NULL;

-- Revoked certificates: lookup for revocation list queries
CREATE INDEX IF NOT EXISTS idx_team_certificates_revoked
    ON {{tables.team_certificates}} (team_id, revoked_at)
    WHERE revoked_at IS NOT NULL;
