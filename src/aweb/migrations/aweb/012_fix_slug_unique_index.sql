-- Fix: migration 005 failed to drop the original slug uniqueness index
-- because it used a bare name instead of schema-qualified.
-- The old index enforces global slug uniqueness even when tenant_id is set,
-- preventing multi-tenant deployments from having same-slug projects.

DROP INDEX IF EXISTS {{schema}}.idx_projects_slug_unique_active;
