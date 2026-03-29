-- 002_project_roles_rename.sql
-- Rename legacy policy schema objects to canonical project_roles names.

DO $$
DECLARE
    schema_name text := trim(both '"' from '{{schema}}');
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = schema_name
          AND table_name = 'project_policies'
    ) THEN
        EXECUTE format(
            'ALTER TABLE %I.%I RENAME TO %I',
            schema_name,
            'project_policies',
            'project_roles'
        );
    END IF;
END
$$;

DO $$
DECLARE
    schema_name text := trim(both '"' from '{{schema}}');
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = schema_name
          AND table_name = 'projects'
          AND column_name = 'active_policy_id'
    ) THEN
        EXECUTE format(
            'ALTER TABLE %I.%I RENAME COLUMN %I TO %I',
            schema_name,
            'projects',
            'active_policy_id',
            'active_project_roles_id'
        );
    END IF;
END
$$;

DO $$
DECLARE
    schema_name text := trim(both '"' from '{{schema}}');
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = schema_name
          AND table_name = 'project_roles'
          AND column_name = 'policy_id'
    ) THEN
        EXECUTE format(
            'ALTER TABLE %I.%I RENAME COLUMN %I TO %I',
            schema_name,
            'project_roles',
            'policy_id',
            'project_roles_id'
        );
    END IF;
END
$$;

DO $$
DECLARE
    schema_name text := trim(both '"' from '{{schema}}');
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.table_constraints
        WHERE table_schema = schema_name
          AND table_name = 'projects'
          AND constraint_name = 'fk_projects_active_policy'
    ) THEN
        EXECUTE format(
            'ALTER TABLE %I.%I RENAME CONSTRAINT %I TO %I',
            schema_name,
            'projects',
            'fk_projects_active_policy',
            'fk_projects_active_project_roles'
        );
    END IF;
END
$$;
