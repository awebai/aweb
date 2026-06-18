-- Library scaffold schema: only the team/agent identity tables the AWID
-- team-certificate auth path observes. Library's domain tables (profile packs,
-- profiles, versions, bindings, materializations, proposals) arrive in a later
-- migration with the model task.

CREATE TABLE IF NOT EXISTS {{tables.teams}} (
    team_id TEXT PRIMARY KEY,
    team_did_key TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS {{tables.agents}} (
    team_id TEXT NOT NULL REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    did_key TEXT NOT NULL,
    did_aw TEXT,
    address TEXT,
    alias TEXT NOT NULL,
    latest_certificate_id TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (team_id, did_key, alias)
);

CREATE INDEX IF NOT EXISTS idx_library_agents_team_alias
    ON {{tables.agents}}(team_id, alias);
