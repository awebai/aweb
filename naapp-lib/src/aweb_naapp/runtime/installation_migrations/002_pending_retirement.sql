-- Pending/unknown replacement observations advance the high-water mark but
-- cannot retire authority. Retain the last active ID until active replacement
-- or confirmed uninstall executes its retirement hook in the same transaction.
ALTER TABLE {{tables.installation_fences}} ADD COLUMN active_installation_id TEXT;
UPDATE {{tables.installation_fences}} SET active_installation_id = installation_id
WHERE state = 'active';
