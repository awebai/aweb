-- An installation id is not team authority. Keep only unambiguous retained
-- attribution; missing or conflicting attribution requires an explicit decision.
CREATE TEMP TABLE legacy_installation_team_candidates (
    installation_id TEXT NOT NULL, team_id TEXT NOT NULL
) ON COMMIT DROP;
DO $$
DECLARE
    target_schema TEXT;
    source_table TEXT;
BEGIN
    SELECT n.nspname INTO target_schema
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.oid = '{{tables.config_revisions}}'::regclass;
    FOREACH source_table IN ARRAY ARRAY[
        'secrets', 'grants', 'intents', 'owner_principals', 'role_holdings',
        'installation_fences', 'retired_installation_fences'
    ] LOOP
        IF to_regclass(format('%I.%I', target_schema, source_table)) IS NOT NULL THEN
            EXECUTE format(
                'INSERT INTO pg_temp.legacy_installation_team_candidates '
                'SELECT installation_id, team_id FROM %I.%I '
                'WHERE installation_id IS NOT NULL AND team_id IS NOT NULL',
                target_schema, source_table
            );
        END IF;
    END LOOP;
END $$;
CREATE TEMP TABLE legacy_installation_teams ON COMMIT DROP AS
SELECT installation_id, MIN(team_id) AS team_id
FROM legacy_installation_team_candidates
GROUP BY installation_id HAVING COUNT(DISTINCT team_id) = 1;

ALTER TABLE {{tables.config_revisions}} ADD COLUMN team_id TEXT;
UPDATE {{tables.config_revisions}} t SET team_id = m.team_id
FROM legacy_installation_teams m WHERE m.installation_id = t.installation_id;
DO $$
DECLARE missing_count BIGINT;
BEGIN
    SELECT COUNT(DISTINCT installation_id) INTO missing_count
    FROM {{tables.config_revisions}} WHERE team_id IS NULL;
    IF missing_count > 0 THEN
        RAISE EXCEPTION 'config_revisions: % installation(s) have missing or ambiguous team attribution', missing_count;
    END IF;
END $$;
ALTER TABLE {{tables.config_revisions}} ALTER COLUMN team_id SET NOT NULL;
ALTER TABLE {{tables.config_revisions}} DROP CONSTRAINT config_revisions_pkey;
ALTER TABLE {{tables.config_revisions}} ADD PRIMARY KEY (installation_id, team_id);
