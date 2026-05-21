-- 011_contacts_or_teammates_inbound_mode.sql
-- Add explicit global inbound mode: contacts or verified same-team members.

ALTER TABLE {{tables.agents}}
    DROP CONSTRAINT IF EXISTS agents_inbound_mode_valid;

ALTER TABLE {{tables.agents}}
    ADD CONSTRAINT agents_inbound_mode_valid
    CHECK (inbound_mode IS NULL OR inbound_mode IN ('open', 'contacts_or_teammates', 'contacts_only'));
