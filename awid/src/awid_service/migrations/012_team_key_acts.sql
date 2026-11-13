-- 012_team_key_acts.sql
-- The namespace controller's rotate_team_key acts, kept exactly as signed
-- (the signed bytes, the signer and the signature), so a relying server can
-- check a team key against the controller DNS names instead of the registry.

CREATE TABLE IF NOT EXISTS {{tables.team_key_acts}} (
    act_id         BIGSERIAL PRIMARY KEY,
    team_uuid      UUID NOT NULL REFERENCES {{tables.teams}}(team_uuid) ON DELETE CASCADE,
    team_did_key   TEXT NOT NULL,
    signer_did_key TEXT NOT NULL,
    signed_payload TEXT NOT NULL,
    signature      TEXT NOT NULL,
    recorded_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS team_key_acts_team_latest
    ON {{tables.team_key_acts}} (team_uuid, act_id DESC);
