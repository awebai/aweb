-- Keep the explicitly approved policy with each resource so export/deletion
-- remain available if an operator removes the current write configuration.
ALTER TABLE {{tables.pages}} ADD COLUMN retention_policy JSONB;
