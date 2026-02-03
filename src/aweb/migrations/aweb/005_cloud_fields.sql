-- Cloud-aware optional fields (clean start)

-- Projects may be partitioned by an external tenant in Cloud.
ALTER TABLE {{tables.projects}}
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Adjust slug uniqueness:
-- - OSS: tenant_id is NULL → slug must be globally unique among active projects
-- - Cloud: tenant_id is set → slug must be unique per tenant among active projects
DROP INDEX IF EXISTS idx_projects_slug_unique_active;

CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_slug_unique_active_oss
ON {{tables.projects}} (slug)
WHERE tenant_id IS NULL AND deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_tenant_slug_unique_active
ON {{tables.projects}} (tenant_id, slug)
WHERE tenant_id IS NOT NULL AND deleted_at IS NULL;

-- API keys may be associated with a user (Cloud) for ownership and permissions.
ALTER TABLE {{tables.api_keys}}
    ADD COLUMN IF NOT EXISTS user_id UUID;

CREATE INDEX IF NOT EXISTS idx_api_keys_user
ON {{tables.api_keys}} (user_id)
WHERE user_id IS NOT NULL;
