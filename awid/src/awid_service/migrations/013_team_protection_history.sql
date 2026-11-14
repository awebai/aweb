-- Keep canonical protection history independently of namespace/team UUIDs.
-- Explicit operator transitions preserve this row, increment generation and
-- drain/invalidate every consumer; a database restore is not a safe rollback.
ALTER TABLE {{tables.team_protection}}
    ADD COLUMN history_id UUID NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN mode TEXT NOT NULL DEFAULT 'protected'
        CHECK (mode IN ('legacy', 'protected')),
    ADD CONSTRAINT team_protection_safe_generation
        CHECK (generation <= 9007199254740991);
