-- The old policy migration left team, org and nobody rows without a mode.
-- The original choices cannot be recovered. Keep non-contacts refused for
-- those rows and preserve every explicitly selected policy.
UPDATE {{tables.agents}} SET inbound_mode = 'contacts_only' WHERE inbound_mode IS NULL;

ALTER TABLE {{tables.agents}}
    ALTER COLUMN inbound_mode DROP DEFAULT,
    ALTER COLUMN inbound_mode SET NOT NULL;
