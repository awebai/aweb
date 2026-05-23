-- 001_post_initial_team_and_contacts_inbound_mode_transition.sql
--
-- Forward repair for aweb 1.25.2 migration 002. The released 002 updates
-- contacts_only rows to team_and_contacts before replacing the baseline CHECK,
-- which fails on databases that actually contain contacts_only rows. This
-- pre-002 migration widens only the old baseline constraint so 002 can perform
-- the data rewrite and then install the final open/team_and_contacts CHECK.
--
-- This file is intentionally safe if discovered after 002 has already applied:
-- when the current constraint no longer mentions contacts_only, it does
-- nothing and preserves the final 002 constraint.

DO $$
DECLARE
    constraint_def TEXT;
BEGIN
    SELECT pg_get_constraintdef(c.oid)
    INTO constraint_def
    FROM pg_constraint c
    WHERE c.conname = 'agents_inbound_mode_valid'
      AND c.conrelid = '{{tables.agents}}'::regclass;

    IF constraint_def IS NOT NULL
       AND constraint_def LIKE '%contacts_only%'
       AND constraint_def NOT LIKE '%team_and_contacts%'
    THEN
        ALTER TABLE {{tables.agents}}
            DROP CONSTRAINT agents_inbound_mode_valid;
        ALTER TABLE {{tables.agents}}
            ADD CONSTRAINT agents_inbound_mode_valid
            CHECK (inbound_mode IS NULL OR inbound_mode IN ('open', 'contacts_only', 'team_and_contacts'));
    END IF;
END $$;
