-- The signing time of the namespace-controller act that set the pinned
-- team key; NULL for a key pinned at admission. A later act must be newer.
ALTER TABLE {{tables.teams}} ADD COLUMN IF NOT EXISTS team_key_act_at TIMESTAMPTZ;
