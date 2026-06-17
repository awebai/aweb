-- 008_app_registry_grants.sql
-- Core app registry entries and per-team app grants.

CREATE TABLE IF NOT EXISTS {{tables.app_registry_apps}} (
    app_id     TEXT PRIMARY KEY,
    origin     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (app_id, origin),
    CONSTRAINT app_registry_apps_app_id_not_blank
        CHECK (BTRIM(app_id) <> ''),
    CONSTRAINT app_registry_apps_origin_not_blank
        CHECK (BTRIM(origin) <> '')
);

CREATE TABLE IF NOT EXISTS {{tables.app_registry_entries}} (
    app_id           TEXT NOT NULL,
    origin           TEXT NOT NULL,
    digest           TEXT NOT NULL,
    app_version      TEXT NOT NULL,
    manifest_version INTEGER NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (app_id, origin, digest),
    FOREIGN KEY (app_id, origin)
        REFERENCES {{tables.app_registry_apps}}(app_id, origin),
    CONSTRAINT app_registry_entries_app_id_not_blank
        CHECK (BTRIM(app_id) <> ''),
    CONSTRAINT app_registry_entries_origin_not_blank
        CHECK (BTRIM(origin) <> ''),
    CONSTRAINT app_registry_entries_digest_sha256
        CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT app_registry_entries_app_version_not_blank
        CHECK (BTRIM(app_version) <> ''),
    CONSTRAINT app_registry_entries_manifest_version_positive
        CHECK (manifest_version > 0)
);

CREATE INDEX IF NOT EXISTS idx_app_registry_entries_origin_digest
    ON {{tables.app_registry_entries}} (origin, digest);

CREATE TABLE IF NOT EXISTS {{tables.team_app_installs}} (
    team_id              TEXT NOT NULL REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    app_id               TEXT NOT NULL,
    origin               TEXT NOT NULL,
    digest               TEXT NOT NULL,
    granted_scopes       TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    installed_by_agent_id UUID REFERENCES {{tables.agents}}(agent_id) ON DELETE SET NULL,
    installed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (team_id, app_id),
    FOREIGN KEY (app_id, origin, digest)
        REFERENCES {{tables.app_registry_entries}}(app_id, origin, digest),
    CONSTRAINT team_app_installs_app_id_not_blank
        CHECK (BTRIM(app_id) <> ''),
    CONSTRAINT team_app_installs_origin_not_blank
        CHECK (BTRIM(origin) <> ''),
    CONSTRAINT team_app_installs_digest_sha256
        CHECK (digest ~ '^sha256:[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS idx_team_app_installs_team
    ON {{tables.team_app_installs}} (team_id, app_id);

CREATE INDEX IF NOT EXISTS idx_team_app_installs_origin_digest
    ON {{tables.team_app_installs}} (origin, digest);
