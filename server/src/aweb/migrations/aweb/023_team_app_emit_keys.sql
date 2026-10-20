-- 023_team_app_emit_keys.sql
-- App emit keys belong to the team whose install registered them. A key is
-- active only for that team's currently installed digest, a registered key id
-- keeps its did_key, and revocation is one-way.
--
-- Rows of app_registry_emit_keys are not copied: they record no installing
-- team, so attributing them to every team that pins the digest could activate
-- a key another team supplied. Each team registers its keys again by
-- installing the app.

CREATE TABLE IF NOT EXISTS {{tables.team_app_emit_keys}} (
    team_id    TEXT NOT NULL REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    app_id     TEXT NOT NULL,
    origin     TEXT NOT NULL,
    digest     TEXT NOT NULL,
    key_id     TEXT NOT NULL,
    did_key    TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (team_id, app_id, origin, digest, key_id),
    FOREIGN KEY (app_id, origin, digest)
        REFERENCES {{tables.app_registry_entries}}(app_id, origin, digest),
    CONSTRAINT team_app_emit_keys_key_id_not_blank
        CHECK (BTRIM(key_id) <> ''),
    CONSTRAINT team_app_emit_keys_did_key_not_blank
        CHECK (BTRIM(did_key) <> '')
);

CREATE INDEX IF NOT EXISTS idx_team_app_emit_keys_key_id
    ON {{tables.team_app_emit_keys}} (team_id, app_id, key_id);
