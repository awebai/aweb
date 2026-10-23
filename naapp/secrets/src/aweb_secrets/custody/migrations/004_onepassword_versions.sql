-- Immutable reference candidates and retained opaque audit handles. No item
-- value or service-account token is copied here. A candidate can precede its
-- secret record in an inert first-create draft, so no FK to secrets is used.
CREATE TABLE IF NOT EXISTS {{tables.onepassword_versions}} (
    installation_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    secret_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    credential_version INTEGER NOT NULL CHECK (credential_version > 0),
    version_ref TEXT NOT NULL CHECK (version_ref ~ '^sv_[0-9a-f]{32}$'),
    binding JSONB,
    destroyed_at TIMESTAMPTZ,
    item_updated_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK ((binding IS NOT NULL AND destroyed_at IS NULL)
        OR (binding IS NULL AND destroyed_at IS NOT NULL)),
    PRIMARY KEY (installation_id, team_id, secret_id, version),
    UNIQUE (installation_id, team_id, version_ref),
    FOREIGN KEY (installation_id, team_id, secret_id)
        REFERENCES {{tables.custody_secrets}} (installation_id, team_id, secret_id)
);
