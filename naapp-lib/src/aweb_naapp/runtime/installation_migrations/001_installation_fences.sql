CREATE TABLE {{tables.installation_fences}} (
    app_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    installation_id TEXT,
    generation BIGINT CHECK (generation > 0),
    state TEXT NOT NULL DEFAULT 'inactive' CHECK (state IN ('active', 'inactive')),
    fresh_until TIMESTAMPTZ,
    PRIMARY KEY (app_id, team_id),
    CHECK (state <> 'active' OR (installation_id IS NOT NULL AND generation IS NOT NULL))
);

-- Reinstall creates a different ID. Never accept an observed retired ID again.
CREATE TABLE {{tables.retired_installation_fences}} (
    app_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    PRIMARY KEY (app_id, team_id, installation_id)
);
