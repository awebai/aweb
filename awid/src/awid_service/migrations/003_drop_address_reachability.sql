-- 003_drop_address_reachability.sql
-- Remove legacy address visibility columns; addresses are global aliases and
-- delivery authority lives on address routes via namespace delivery origin.

ALTER TABLE {{tables.public_addresses}}
    DROP COLUMN IF EXISTS visible_to_team_id,
    DROP COLUMN IF EXISTS reachability;
