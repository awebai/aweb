\set ON_ERROR_STOP on
\if :{?secrets_schema}
\else
\set secrets_schema public
\endif
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '30s';
SELECT 1 / COUNT(*)::integer AS selected_schema_exists
FROM pg_namespace WHERE nspname = :'secrets_schema';
WITH source_sql AS (
  SELECT COALESCE(string_agg(format(
    'SELECT installation_id, team_id FROM %I.%I WHERE installation_id IS NOT NULL AND team_id IS NOT NULL',
    n.nspname, c.relname), ' UNION ALL ' ORDER BY c.relname),
    'SELECT NULL::text AS installation_id, NULL::text AS team_id WHERE false') AS query
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = :'secrets_schema' AND c.relname IN (
    'secrets', 'grants', 'intents', 'owner_principals', 'role_holdings',
    'installation_fences', 'retired_installation_fences'
  )
), target_sql AS (
  SELECT COALESCE(string_agg(format(
    'SELECT DISTINCT %L::text AS target_table, installation_id FROM %I.%I',
    c.relname, n.nspname, c.relname), ' UNION ALL ' ORDER BY c.relname),
    'SELECT NULL::text AS target_table, NULL::text AS installation_id WHERE false') AS query
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = :'secrets_schema' AND c.relname IN (
    'policies', 'grant_templates', 'change_set_settings', 'config_revisions'
  )
)
SELECT format($count$
WITH candidates AS (%s), targets AS (%s), evidence AS (
  SELECT installation_id, COUNT(DISTINCT team_id) AS teams
  FROM candidates GROUP BY installation_id
), classified AS (
  SELECT t.target_table, t.installation_id, COALESCE(e.teams, 0) AS teams
  FROM targets t LEFT JOIN evidence e USING (installation_id)
), target_names(target_table) AS (
  VALUES ('policies'), ('grant_templates'), ('change_set_settings'), ('config_revisions')
)
SELECT n.target_table,
       COUNT(c.installation_id) FILTER (WHERE c.teams = 0) AS zero_teams,
       COUNT(c.installation_id) FILTER (WHERE c.teams > 1) AS multiple_teams,
       COUNT(c.installation_id) FILTER (WHERE c.teams = 1) AS one_team
FROM target_names n LEFT JOIN classified c USING (target_table)
GROUP BY n.target_table ORDER BY n.target_table;
$count$, source_sql.query, target_sql.query) FROM source_sql CROSS JOIN target_sql
\gexec
COMMIT;
