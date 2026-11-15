-- The team key under which this server last accepted each member. A member is
-- a member only while this is the team's current key, the key the server
-- admitted (teams.team_did_key); changing the key removes every member until
-- each is accepted under the new one.
ALTER TABLE {{tables.agents}} ADD COLUMN IF NOT EXISTS accepted_team_did_key TEXT;

-- Every member recorded before the key was, with or without a certificate,
-- was accepted under the key the server holds for its team.
UPDATE {{tables.agents}} AS a
SET accepted_team_did_key = t.team_did_key
FROM {{tables.teams}} AS t
WHERE t.team_id = a.team_id
  AND a.accepted_team_did_key IS NULL;

-- A member row written without the key is accepted under the key the server
-- holds for its team at that moment. Certificate admission writes the key it
-- verified under explicitly.
CREATE OR REPLACE FUNCTION aweb.member_accepted_team_key_default()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.accepted_team_did_key IS NULL THEN
        SELECT team_did_key INTO NEW.accepted_team_did_key
        FROM {{tables.teams}}
        WHERE team_id = NEW.team_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_member_accepted_team_key_default ON {{tables.agents}};
CREATE TRIGGER trg_member_accepted_team_key_default
    BEFORE INSERT ON {{tables.agents}}
    FOR EACH ROW
    EXECUTE FUNCTION aweb.member_accepted_team_key_default();
