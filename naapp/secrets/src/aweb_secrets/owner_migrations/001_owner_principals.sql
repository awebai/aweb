-- The principal behind each owner scope. An owner scope's name is a hash of
-- the installation and the principal (decision 40), so the directory reads
-- the principal back here to check that it still holds secrets.owner.

CREATE TABLE IF NOT EXISTS {{tables.owner_principals}} (
    scope            TEXT PRIMARY KEY,
    installation_id  TEXT NOT NULL,
    team_id          TEXT NOT NULL,
    principal_did    TEXT NOT NULL,
    UNIQUE (installation_id, team_id, principal_did)
);
