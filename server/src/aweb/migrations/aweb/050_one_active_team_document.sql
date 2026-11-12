-- 050_one_active_team_document.sql
-- A team has at most one active version of its roles and of its instructions,
-- whoever writes the row. Teams that already have more are counted and the
-- migration stops: which version stays active is a decision about their data,
-- not one a migration makes.

DO $$
DECLARE
    teams INTEGER;
BEGIN
    SELECT COUNT(*) INTO teams FROM (
        SELECT team_id FROM {{tables.team_roles}} WHERE is_active GROUP BY team_id HAVING COUNT(*) > 1
    ) violating;
    IF teams > 0 THEN
        RAISE EXCEPTION '% teams have more than one active row in team_roles', teams;
    END IF;

    SELECT COUNT(*) INTO teams FROM (
        SELECT team_id FROM {{tables.team_instructions}} WHERE is_active GROUP BY team_id HAVING COUNT(*) > 1
    ) violating;
    IF teams > 0 THEN
        RAISE EXCEPTION '% teams have more than one active row in team_instructions', teams;
    END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS team_roles_one_active
    ON {{tables.team_roles}} (team_id)
    WHERE is_active;

CREATE UNIQUE INDEX IF NOT EXISTS team_instructions_one_active
    ON {{tables.team_instructions}} (team_id)
    WHERE is_active;
