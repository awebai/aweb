-- The team key under which this server last accepted each member's
-- certificate. A member is refused wherever it is looked up when this is not
-- the team's current key, the key the server admitted (teams.team_did_key).
ALTER TABLE {{tables.agents}} ADD COLUMN IF NOT EXISTS accepted_team_did_key TEXT;

-- Members recorded before the key was: they were accepted under the key the
-- server holds for their team.
UPDATE {{tables.agents}} AS a
SET accepted_team_did_key = t.team_did_key
FROM {{tables.teams}} AS t
WHERE t.team_id = a.team_id
  AND a.certificate_id IS NOT NULL
  AND a.accepted_team_did_key IS NULL;
