-- 010_agent_identity_scope.sql
-- Replace legacy persistent/ephemeral lifetime storage with global/local
-- identity scope. Stale API/certificate inputs are normalized at service
-- boundaries before writing agents.identity_scope.

ALTER TABLE {{tables.agents}}
    ADD COLUMN identity_scope TEXT;

UPDATE {{tables.agents}}
SET identity_scope = CASE lifetime
    WHEN 'persistent' THEN 'global'
    WHEN 'ephemeral' THEN 'local'
    ELSE 'local'
END
WHERE identity_scope IS NULL;

ALTER TABLE {{tables.agents}}
    ALTER COLUMN identity_scope SET DEFAULT 'local',
    ALTER COLUMN identity_scope SET NOT NULL,
    ADD CONSTRAINT agents_identity_scope_valid
        CHECK (identity_scope IN ('global', 'local'));

ALTER TABLE {{tables.agents}}
    DROP COLUMN lifetime;
