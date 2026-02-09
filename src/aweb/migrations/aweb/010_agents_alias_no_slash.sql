-- Enforce that plain agent aliases cannot contain '/'.
-- '/' is reserved for network addresses like "org/alias" and may appear in other tables
-- (e.g. chat session participants) but not in the canonical agents table.

ALTER TABLE {{tables.agents}}
ADD CONSTRAINT IF NOT EXISTS chk_agents_alias_no_slash
CHECK (POSITION('/' IN alias) = 0);

