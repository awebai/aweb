-- Teams and member identities a naapp has authenticated (record_observed_principal).
-- IF NOT EXISTS: an app whose own initial migration created these identical tables keeps them.
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
