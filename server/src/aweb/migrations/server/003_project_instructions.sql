-- 003_project_instructions.sql
-- Add project-wide shared instructions as a first-class coordination resource.

ALTER TABLE {{tables.projects}}
    ADD COLUMN IF NOT EXISTS active_project_instructions_id UUID;

CREATE TABLE IF NOT EXISTS {{tables.project_instructions}} (
    project_instructions_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(id) ON DELETE CASCADE,
    version INT NOT NULL,
    document_json JSONB NOT NULL,
    created_by_workspace_id UUID REFERENCES {{tables.workspaces}}(workspace_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT project_instructions_version_unique UNIQUE (project_id, version)
);

DO $$
DECLARE
    schema_name text := trim(both '"' from '{{schema}}');
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.table_constraints
        WHERE table_schema = schema_name
          AND table_name = 'projects'
          AND constraint_name = 'fk_projects_active_project_instructions'
    ) THEN
        EXECUTE format(
            'ALTER TABLE %I.%I ADD CONSTRAINT %I FOREIGN KEY (%I) REFERENCES %I.%I(%I) ON DELETE SET NULL',
            schema_name,
            'projects',
            'fk_projects_active_project_instructions',
            'active_project_instructions_id',
            schema_name,
            'project_instructions',
            'project_instructions_id'
        );
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_project_instructions_project_version
    ON {{tables.project_instructions}}(project_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_project_instructions_created_by
    ON {{tables.project_instructions}}(created_by_workspace_id)
    WHERE created_by_workspace_id IS NOT NULL;

CREATE OR REPLACE FUNCTION {{schema}}.project_instructions_update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS project_instructions_update_timestamp ON {{tables.project_instructions}};
CREATE TRIGGER project_instructions_update_timestamp
    BEFORE UPDATE ON {{tables.project_instructions}}
    FOR EACH ROW
    EXECUTE FUNCTION {{schema}}.project_instructions_update_timestamp();
