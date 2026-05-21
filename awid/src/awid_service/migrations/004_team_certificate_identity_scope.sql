-- 004_team_certificate_identity_scope.sql
-- Team certificates now store canonical global/local identity_scope. Stale
-- lifetime values are accepted only at API/certificate compatibility boundaries.

ALTER TABLE {{tables.team_certificates}}
    ADD COLUMN identity_scope TEXT;

UPDATE {{tables.team_certificates}}
SET identity_scope = CASE lifetime
    WHEN 'persistent' THEN 'global'
    WHEN 'ephemeral' THEN 'local'
    ELSE 'local'
END
WHERE identity_scope IS NULL;

ALTER TABLE {{tables.team_certificates}}
    ALTER COLUMN identity_scope SET DEFAULT 'global',
    ALTER COLUMN identity_scope SET NOT NULL,
    ADD CONSTRAINT team_certificates_identity_scope_valid
        CHECK (identity_scope IN ('global', 'local'));

ALTER TABLE {{tables.team_certificates}}
    DROP COLUMN lifetime;
