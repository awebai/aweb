-- 001_initial.sql
-- Description: Clean baseline for the aweb coordination server schema.
-- Fresh installs should derive the full server schema from this file alone.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS {{tables.projects}} (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Partition key for multi-tenant SaaS (NULL for single-tenant standalone mode)
    tenant_id UUID,
    slug TEXT NOT NULL,
    name TEXT,
    -- Active policy pointer (FK added after project_policies exists)
    active_policy_id UUID,
    visibility TEXT NOT NULL DEFAULT 'private'
        CHECK (visibility IN ('private', 'public')),
    owner_type TEXT,
    owner_ref TEXT,
    owner_user_id UUID,
    owner_org_id UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    -- Soft-delete support: NULL means active
    deleted_at TIMESTAMPTZ,
    CONSTRAINT chk_projects_owner_fields CHECK (
        (
            owner_type IS NULL
            AND owner_ref IS NULL
            AND owner_user_id IS NULL
            AND owner_org_id IS NULL
        )
        OR
        (
            owner_type = 'user'
            AND (owner_ref IS NOT NULL OR owner_user_id IS NOT NULL)
            AND owner_org_id IS NULL
        )
        OR
        (
            owner_type = 'organization'
            AND (owner_ref IS NOT NULL OR owner_org_id IS NOT NULL)
            AND owner_user_id IS NULL
        )
    )
);

-- Slugs unique within tenant (or globally if no tenant), for non-deleted projects.
CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_slug_no_tenant
    ON {{tables.projects}}(slug) WHERE tenant_id IS NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_slug_with_tenant
    ON {{tables.projects}}(tenant_id, slug) WHERE tenant_id IS NOT NULL AND deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_projects_active ON {{tables.projects}}(id) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS {{tables.repos}} (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- CASCADE: repos are deleted when their project is deleted (repos without projects are invalid)
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(id) ON DELETE CASCADE,
    origin_url TEXT NOT NULL,
    canonical_origin TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    -- Soft-delete support: NULL means active, timestamp means deleted
    -- Unique constraint retained for ON CONFLICT support in ensure_repo.
    -- When a soft-deleted repo is re-registered, ensure_repo clears deleted_at.
    deleted_at TIMESTAMPTZ,
    CONSTRAINT unique_repo_per_project UNIQUE (project_id, canonical_origin)
);

CREATE INDEX IF NOT EXISTS idx_repos_project ON {{tables.repos}}(project_id);
CREATE INDEX IF NOT EXISTS idx_repos_active ON {{tables.repos}}(project_id)
    WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS {{tables.workspaces}} (
    workspace_id UUID PRIMARY KEY,
    -- CASCADE: workspaces are deleted when their project is deleted
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(id) ON DELETE CASCADE,
    -- SET NULL: when repo is hard-deleted (e.g., project deletion cascade), preserve workspace for audit
    -- When repo is soft-deleted via API, workspaces are soft-deleted manually in application code
    repo_id UUID REFERENCES {{tables.repos}}(id) ON DELETE SET NULL,
    alias TEXT NOT NULL,
    human_name TEXT NOT NULL DEFAULT '',
    role TEXT,
    current_branch TEXT,
    focus_task_ref TEXT,
    focus_updated_at TIMESTAMPTZ,
    -- Physical location: for detecting "gone" workspaces (directory no longer exists)
    -- Only checked for workspaces on the current hostname to avoid cross-machine false positives
    hostname TEXT,
    workspace_path TEXT,
    timezone TEXT,
    -- Workspace classification
    workspace_type TEXT NOT NULL DEFAULT 'agent',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    -- Soft-delete support: NULL means active, timestamp means deleted
    deleted_at TIMESTAMPTZ,
    -- Track when workspace was last seen (updated on coordination activity)
    last_seen_at TIMESTAMPTZ,
    CONSTRAINT chk_workspace_repo CHECK (
        deleted_at IS NOT NULL OR
        (
            (workspace_type = 'agent' AND repo_id IS NOT NULL) OR
            (
                workspace_type IN (
                    'dashboard_browser',
                    'hosted_mcp',
                    'local_dir',
                    'service_process',
                    'manual'
                )
                AND repo_id IS NULL
            )
        )
    ),
    CONSTRAINT chk_workspace_role_length CHECK (role IS NULL OR length(role) <= 50)
);

-- Partial unique index: aliases unique within project for non-deleted workspaces only
CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_active_alias
    ON {{tables.workspaces}}(project_id, alias)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_workspaces_alias ON {{tables.workspaces}}(alias);
CREATE INDEX IF NOT EXISTS idx_workspaces_project ON {{tables.workspaces}}(project_id);
CREATE INDEX IF NOT EXISTS idx_workspaces_repo ON {{tables.workspaces}}(repo_id);
CREATE INDEX IF NOT EXISTS idx_workspaces_active ON {{tables.workspaces}}(project_id)
    WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_workspaces_hostname ON {{tables.workspaces}}(hostname)
    WHERE hostname IS NOT NULL AND deleted_at IS NULL;
-- Trigger to update updated_at and enforce immutability
CREATE OR REPLACE FUNCTION {{schema}}.update_workspace_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    -- Enforce immutability of key fields
    IF NEW.project_id IS DISTINCT FROM OLD.project_id THEN
        RAISE EXCEPTION 'project_id is immutable';
    END IF;
    -- repo_id may be assigned once when a local/manual workspace is upgraded into
    -- a repo-backed workspace, but cannot change between two non-NULL repos.
    IF OLD.repo_id IS NOT NULL
       AND NEW.repo_id IS DISTINCT FROM OLD.repo_id
       AND NEW.repo_id IS NOT NULL THEN
        RAISE EXCEPTION 'repo_id is immutable once set';
    END IF;
    IF NEW.alias IS DISTINCT FROM OLD.alias THEN
        RAISE EXCEPTION 'alias is immutable';
    END IF;

    -- Auto-soft-delete when repo_id becomes NULL (repo was hard-deleted)
    IF OLD.repo_id IS NOT NULL
       AND NEW.repo_id IS NULL
       AND NEW.deleted_at IS NULL
       AND NEW.workspace_type = 'agent' THEN
        NEW.deleted_at = NOW();
    END IF;

    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS workspace_updated_at ON {{tables.workspaces}};
CREATE TRIGGER workspace_updated_at
    BEFORE UPDATE ON {{tables.workspaces}}
    FOR EACH ROW
    EXECUTE FUNCTION {{schema}}.update_workspace_timestamp();

CREATE TABLE IF NOT EXISTS {{tables.task_claims}} (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- CASCADE: claims deleted when project is deleted
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(id) ON DELETE CASCADE,
    -- CASCADE: claims deleted when workspace is deleted
    workspace_id UUID NOT NULL REFERENCES {{tables.workspaces}}(workspace_id) ON DELETE CASCADE,
    alias TEXT NOT NULL,
    human_name TEXT NOT NULL,
    task_ref TEXT NOT NULL,
    -- Apex reference for fast team status listings
    apex_task_ref TEXT,
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Multiple workspaces can claim the same task (coordinated work with --:jump-in)
    UNIQUE(project_id, task_ref, workspace_id)
);

CREATE INDEX IF NOT EXISTS idx_task_claims_workspace
    ON {{tables.task_claims}}(workspace_id, claimed_at DESC);
CREATE INDEX IF NOT EXISTS idx_task_claims_project ON {{tables.task_claims}}(project_id);

-- ---------------------------------------------------------------------------
-- Reservations (resource locks)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS {{tables.reservations}} (
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(id) ON DELETE CASCADE,
    resource_key TEXT NOT NULL,
    holder_agent_id UUID NOT NULL REFERENCES {{tables.workspaces}}(workspace_id) ON DELETE CASCADE,
    holder_alias TEXT NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (project_id, resource_key)
);

CREATE INDEX IF NOT EXISTS idx_reservations_project_expires
    ON {{tables.reservations}}(project_id, expires_at);

CREATE TABLE IF NOT EXISTS {{tables.audit_log}} (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(id) ON DELETE CASCADE,
    workspace_id UUID REFERENCES {{tables.workspaces}}(workspace_id) ON DELETE SET NULL,
    agent_id UUID,
    event_type TEXT NOT NULL,
    alias TEXT,
    member_email TEXT,
    resource TEXT,
    details JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_created ON {{tables.audit_log}}(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_alias ON {{tables.audit_log}}(alias);
CREATE INDEX IF NOT EXISTS idx_audit_log_project ON {{tables.audit_log}}(project_id);

CREATE TABLE IF NOT EXISTS {{tables.project_policies}} (
    policy_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(id) ON DELETE CASCADE,
    version INT NOT NULL,
    bundle_json JSONB NOT NULL,
    created_by_workspace_id UUID REFERENCES {{tables.workspaces}}(workspace_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT project_policies_version_unique UNIQUE (project_id, version)
);

-- Add FK after project_policies to avoid circular dependency during create
ALTER TABLE {{tables.projects}}
    ADD CONSTRAINT fk_projects_active_policy
    FOREIGN KEY (active_policy_id)
    REFERENCES {{tables.project_policies}}(policy_id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_project_policies_project_version
    ON {{tables.project_policies}}(project_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_project_policies_created_by
    ON {{tables.project_policies}}(created_by_workspace_id)
    WHERE created_by_workspace_id IS NOT NULL;

CREATE OR REPLACE FUNCTION {{schema}}.project_policies_update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS project_policies_update_timestamp ON {{tables.project_policies}};
CREATE TRIGGER project_policies_update_timestamp
    BEFORE UPDATE ON {{tables.project_policies}}
    FOR EACH ROW
    EXECUTE FUNCTION {{schema}}.project_policies_update_timestamp();

CREATE INDEX IF NOT EXISTS idx_audit_log_agent_id ON {{tables.audit_log}}(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_projects_owner_scope
    ON {{tables.projects}}(owner_type, owner_ref, slug)
    WHERE owner_ref IS NOT NULL AND deleted_at IS NULL;
CREATE TABLE IF NOT EXISTS {{tables.task_counters}} (
    project_id UUID PRIMARY KEY REFERENCES {{tables.projects}}(id) ON DELETE CASCADE,
    next_number INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS {{tables.task_root_counters}} (
    project_id UUID PRIMARY KEY REFERENCES {{tables.projects}}(id) ON DELETE CASCADE,
    next_number INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS {{tables.tasks}} (
    task_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(id) ON DELETE CASCADE,
    task_number INTEGER NOT NULL,
    root_task_seq INTEGER NOT NULL,
    task_ref_suffix TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    priority INTEGER NOT NULL DEFAULT 2,
    task_type TEXT NOT NULL DEFAULT 'task',
    assignee_agent_id UUID,
    created_by_agent_id UUID,
    closed_by_agent_id UUID,
    labels TEXT[] NOT NULL DEFAULT '{}',
    parent_task_id UUID REFERENCES {{tables.tasks}}(task_id) ON DELETE SET NULL,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at TIMESTAMPTZ,
    UNIQUE (project_id, task_number),
    UNIQUE (project_id, task_ref_suffix),
    CONSTRAINT chk_tasks_status CHECK (status IN ('open', 'in_progress', 'closed')),
    CONSTRAINT chk_tasks_priority CHECK (priority >= 0 AND priority <= 4),
    CONSTRAINT chk_tasks_type CHECK (task_type IN ('task', 'bug', 'feature', 'epic', 'chore'))
);

CREATE INDEX IF NOT EXISTS idx_tasks_project_status
ON {{tables.tasks}} (project_id, status)
WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_tasks_project_assignee
ON {{tables.tasks}} (project_id, assignee_agent_id)
WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_tasks_parent
ON {{tables.tasks}} (parent_task_id)
WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS {{tables.task_dependencies}} (
    task_id UUID NOT NULL REFERENCES {{tables.tasks}}(task_id) ON DELETE CASCADE,
    depends_on_task_id UUID NOT NULL REFERENCES {{tables.tasks}}(task_id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (task_id, depends_on_task_id),
    CONSTRAINT chk_task_dep_no_self CHECK (task_id != depends_on_task_id)
);

CREATE TABLE IF NOT EXISTS {{tables.task_comments}} (
    comment_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id UUID NOT NULL REFERENCES {{tables.tasks}}(task_id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_task_comments_task
ON {{tables.task_comments}} (task_id, created_at);
ALTER TABLE server.projects
DROP COLUMN IF EXISTS scope_id;
