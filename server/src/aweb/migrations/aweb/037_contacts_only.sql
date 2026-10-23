-- aweb-ackf, Juan via Athena 30851a46: introduce strict contacts-only delivery.
-- Preserve the effective policy of historical rows before reusing this value.
UPDATE {{tables.agents}}
SET inbound_mode = 'team_and_contacts'
WHERE inbound_mode = 'contacts_only';

ALTER TABLE {{tables.agents}} DROP CONSTRAINT agents_inbound_mode_valid;
ALTER TABLE {{tables.agents}} ADD CONSTRAINT agents_inbound_mode_valid
    CHECK (inbound_mode IS NULL OR inbound_mode IN ('open', 'team_and_contacts', 'contacts_only'));
