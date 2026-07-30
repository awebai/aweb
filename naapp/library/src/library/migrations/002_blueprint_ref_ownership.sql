-- Public blueprint refs are globally exclusive: first publisher owns the ref.
-- The aweb.* prefix is additionally reserved to the first first-party publisher
-- and remains reserved even if individual blueprints are deleted.

CREATE TABLE IF NOT EXISTS {{tables.blueprint_ref_owners}} (
    blueprint_ref TEXT PRIMARY KEY,
    owner_team TEXT NOT NULL,
    reserved_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS {{tables.blueprint_ref_prefix_owners}} (
    ref_prefix TEXT PRIMARY KEY,
    owner_team TEXT NOT NULL,
    reserved_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO {{tables.blueprint_ref_owners}} (blueprint_ref, owner_team, reserved_at)
SELECT DISTINCT ON (blueprint_ref) blueprint_ref, owner_team, created_at
FROM {{tables.blueprints}}
ORDER BY blueprint_ref, created_at ASC
ON CONFLICT (blueprint_ref) DO NOTHING;

INSERT INTO {{tables.blueprint_ref_prefix_owners}} (ref_prefix, owner_team, reserved_at)
SELECT 'aweb.', owner_team, created_at
FROM {{tables.blueprints}}
WHERE blueprint_ref LIKE 'aweb.%'
ORDER BY created_at ASC
LIMIT 1
ON CONFLICT (ref_prefix) DO NOTHING;
