-- 027_team_app_keys.sql
-- An installed app's registered keys and the purposes each may sign, as rows
-- of the installing team. A key is active only for that team's currently
-- installed digest and only for a purpose it declares; revocation is one-way.
-- Rows come only from the manifest bytes that hash to the pinned digest.

CREATE TABLE IF NOT EXISTS {{tables.team_app_keys}} (
    team_id    TEXT NOT NULL REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    app_id     TEXT NOT NULL,
    origin     TEXT NOT NULL,
    digest     TEXT NOT NULL,
    key_id     TEXT NOT NULL,
    did_key    TEXT NOT NULL,
    purposes   TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (team_id, app_id, origin, digest, key_id),
    FOREIGN KEY (app_id, origin, digest)
        REFERENCES {{tables.app_registry_entries}}(app_id, origin, digest),
    CONSTRAINT team_app_keys_key_id_not_blank
        CHECK (BTRIM(key_id) <> ''),
    CONSTRAINT team_app_keys_did_key_not_blank
        CHECK (BTRIM(did_key) <> '')
);

CREATE INDEX IF NOT EXISTS idx_team_app_keys_key_id
    ON {{tables.team_app_keys}} (team_id, app_id, key_id);
