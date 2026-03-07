-- Backfill namespace_id for existing projects and agents created before
-- migration 021. Derives namespace slugs from project slugs using the same
-- normalization as Python's _namespace_slug_from_project_slug:
--   lowercase → replace non-alnum-hyphen with hyphens → collapse consecutive
--   hyphens → strip edge hyphens → default to 'default' → truncate to 64.

-- Step 1: Create namespace rows for each distinct normalized slug.
INSERT INTO {{tables.namespaces}} (slug)
SELECT DISTINCT
    CASE
        WHEN trim(BOTH '-' FROM regexp_replace(regexp_replace(lower(slug), '[^a-z0-9-]', '-', 'g'), '-+', '-', 'g')) = ''
        THEN 'default'
        ELSE rtrim(left(trim(BOTH '-' FROM regexp_replace(regexp_replace(lower(slug), '[^a-z0-9-]', '-', 'g'), '-+', '-', 'g')), 64), '-')
    END
FROM {{tables.projects}}
WHERE namespace_id IS NULL AND deleted_at IS NULL
ON CONFLICT (slug) WHERE deleted_at IS NULL DO NOTHING;

-- Step 2: Link projects to their namespace.
WITH normalized AS (
    SELECT project_id,
           CASE
               WHEN trim(BOTH '-' FROM regexp_replace(regexp_replace(lower(slug), '[^a-z0-9-]', '-', 'g'), '-+', '-', 'g')) = ''
               THEN 'default'
               ELSE rtrim(left(trim(BOTH '-' FROM regexp_replace(regexp_replace(lower(slug), '[^a-z0-9-]', '-', 'g'), '-+', '-', 'g')), 64), '-')
           END AS ns_slug
    FROM {{tables.projects}}
    WHERE namespace_id IS NULL AND deleted_at IS NULL
)
UPDATE {{tables.projects}} p
SET namespace_id = n.namespace_id
FROM normalized nm
JOIN {{tables.namespaces}} n ON n.slug = nm.ns_slug AND n.deleted_at IS NULL
WHERE p.project_id = nm.project_id;

-- Step 3: Propagate namespace_id to agents from their project.
UPDATE {{tables.agents}} a
SET namespace_id = p.namespace_id
FROM {{tables.projects}} p
WHERE a.project_id = p.project_id
  AND a.namespace_id IS NULL
  AND p.namespace_id IS NOT NULL;
