-- Human-role holdings (human-role-holders.md, Reading a holding). A holding is
-- a principal's role assignment in the team together with this record of it
-- in one installation: its B3 scope and the exact certificate retained for it.
-- The record outlives the assignment as history and grants nothing alone; the
-- holding exists while both are present. certificate is NULL only for a
-- holding retained before certificates were.
CREATE TABLE IF NOT EXISTS {{tables.role_holdings}} (
    b3_scope        TEXT PRIMARY KEY,
    installation_id TEXT NOT NULL,
    team_id         TEXT NOT NULL,
    role            TEXT NOT NULL,
    principal_did   TEXT NOT NULL,
    certificate     BYTEA,
    UNIQUE (installation_id, team_id, role, principal_did),
    CHECK (principal_did LIKE 'did:aw:_%')
);

CREATE INDEX IF NOT EXISTS idx_role_holdings_assignment
    ON {{tables.role_holdings}} (team_id, role, principal_did);

-- A holding's version is its assignment's time: the wall clock at the write,
-- so ending and holding again in one transaction gives a new version.
ALTER TABLE {{tables.role_assignments}} ALTER COLUMN assigned_at SET DEFAULT clock_timestamp();
