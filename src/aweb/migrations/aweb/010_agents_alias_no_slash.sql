-- Enforce that plain agent aliases cannot contain '/'.
-- '/' is reserved for network addresses like "org/alias" and may appear in other tables
-- (e.g. chat session participants) but not in the canonical agents table.

DO $$
BEGIN
    ALTER TABLE {{tables.agents}}
        ADD CONSTRAINT chk_agents_alias_no_slash
        CHECK (POSITION('/' IN alias) = 0);
EXCEPTION
    WHEN duplicate_object THEN
        -- Migration may be applied concurrently or re-run in dev; keep it idempotent.
        NULL;
END $$;
