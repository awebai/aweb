-- 002_team_and_contacts_inbound_mode.sql
--
-- aapq: team reachability is part of team membership for global agents.
-- Replace the stale exact-contacts-only restricted state with the truthful
-- canonical value: team_and_contacts.

UPDATE {{tables.agents}}
SET inbound_mode = 'team_and_contacts'
WHERE inbound_mode = 'contacts_only';

ALTER TABLE {{tables.agents}}
    DROP CONSTRAINT IF EXISTS agents_inbound_mode_valid;

ALTER TABLE {{tables.agents}}
    ADD CONSTRAINT agents_inbound_mode_valid
    CHECK (inbound_mode IS NULL OR inbound_mode IN ('open', 'team_and_contacts'));
