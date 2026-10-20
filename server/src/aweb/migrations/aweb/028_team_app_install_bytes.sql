-- 028_team_app_install_bytes.sql
-- Whether a team's install registered its keys and declarations from the exact
-- manifest bytes that hash to its pinned digest. Operators read it to measure
-- when every client sends the bytes, before installs are required to.

ALTER TABLE {{tables.team_app_installs}}
    ADD COLUMN IF NOT EXISTS registered_from_manifest_bytes BOOLEAN NOT NULL DEFAULT FALSE;
