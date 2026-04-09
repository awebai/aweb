ALTER TABLE IF EXISTS {{tables.project_roles}} RENAME TO team_roles;
ALTER TABLE IF EXISTS {{tables.project_instructions}} RENAME TO team_instructions;
