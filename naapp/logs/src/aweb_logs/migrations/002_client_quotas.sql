-- Per-member usage of client-class ingest, one row per member and minute, so
-- one member cannot flood the team's chain (audit-substrate.md §B2).
CREATE TABLE IF NOT EXISTS {{tables.client_ingest_usage}} (
    team_id      TEXT NOT NULL,
    member       TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    events       INTEGER NOT NULL CHECK (events >= 0),
    bytes        BIGINT NOT NULL CHECK (bytes >= 0),
    PRIMARY KEY (team_id, member, window_start)
);
