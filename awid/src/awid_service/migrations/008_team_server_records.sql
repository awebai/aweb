-- 008_team_server_records.sql
-- aweb.team-server/1: the current team-key-signed binding of a team to its
-- coordination server. The canonical record bytes and signature are kept as
-- signed, so any reader can verify them against the team's current key.

CREATE TABLE IF NOT EXISTS {{tables.team_server_records}} (
    team_uuid    UUID PRIMARY KEY REFERENCES {{tables.teams}}(team_uuid) ON DELETE CASCADE,
    record_json  TEXT NOT NULL,
    signature    TEXT NOT NULL,
    team_did_key TEXT NOT NULL,
    server_url   TEXT NOT NULL,
    issued_at    TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
