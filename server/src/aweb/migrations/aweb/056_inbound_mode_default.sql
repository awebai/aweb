-- Native admission uses 'open' when no policy has been chosen. Give old rows
-- the same value without changing any explicitly selected policy.
UPDATE {{tables.agents}} SET inbound_mode = 'open' WHERE inbound_mode IS NULL;

ALTER TABLE {{tables.agents}}
    ALTER COLUMN inbound_mode SET DEFAULT 'open',
    ALTER COLUMN inbound_mode SET NOT NULL;
