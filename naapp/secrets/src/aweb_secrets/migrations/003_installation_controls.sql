-- Local kill switch, separate from the team server's installation grant:
-- refreshing that authority must never re-enable a contained installation.
CREATE TABLE IF NOT EXISTS {{tables.containment_installations}} (
    installation_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    disabled_at TIMESTAMPTZ,
    PRIMARY KEY (installation_id, team_id)
);
