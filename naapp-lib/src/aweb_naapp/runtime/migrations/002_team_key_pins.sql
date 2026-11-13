-- The team key this app holds for each team it has authenticated, and the
-- signing time of the namespace-controller act that set it (NULL for a key
-- pinned on first sight). Only such an act moves a pin (awid.team_key_acts).
CREATE TABLE IF NOT EXISTS {{tables.team_key_pins}} (
    team_id TEXT PRIMARY KEY,
    team_did_key TEXT NOT NULL,
    team_key_act_at TIMESTAMPTZ,
    pinned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
