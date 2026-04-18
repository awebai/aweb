ALTER TABLE {{tables.agents}}
    DROP CONSTRAINT IF EXISTS agents_status_check;

ALTER TABLE {{tables.agents}}
    ADD CONSTRAINT agents_status_check
    CHECK (status IN ('active', 'retired', 'archived', 'deleted'));
