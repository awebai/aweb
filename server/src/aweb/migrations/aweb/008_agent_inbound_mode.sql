-- 008_agent_inbound_mode.sql
-- Add narrow inbound delivery mode without changing legacy messaging_policy.

ALTER TABLE {{tables.agents}}
    ADD COLUMN inbound_mode TEXT;

ALTER TABLE {{tables.agents}}
    ADD CONSTRAINT agents_inbound_mode_valid
    CHECK (inbound_mode IS NULL OR inbound_mode IN ('open', 'contacts_only'));

UPDATE {{tables.agents}}
SET inbound_mode = 'open'
WHERE inbound_mode IS NULL
  AND messaging_policy = 'everyone';

UPDATE {{tables.agents}}
SET inbound_mode = 'contacts_only'
WHERE inbound_mode IS NULL
  AND messaging_policy = 'contacts';
