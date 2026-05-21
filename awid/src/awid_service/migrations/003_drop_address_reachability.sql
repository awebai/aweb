-- 003_drop_address_reachability.sql
-- Remove legacy address visibility columns; addresses are global aliases and
-- delivery authority lives on address routes via namespace delivery origin.
--
-- Fail closed on active non-neutral legacy rows. Dropping these columns would
-- otherwise silently turn hidden/limited address rows into normal addressed
-- global aliases. Operators must explicitly normalize or retire those rows
-- before this migration may remove the old metadata.

DO $$
DECLARE
    legacy_count INTEGER;
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_attribute
        WHERE attrelid = '{{tables.public_addresses}}'::regclass
          AND attname = 'reachability'
          AND NOT attisdropped
    ) AND EXISTS (
        SELECT 1
        FROM pg_attribute
        WHERE attrelid = '{{tables.public_addresses}}'::regclass
          AND attname = 'visible_to_team_id'
          AND NOT attisdropped
    ) THEN
        SELECT COUNT(*)
        INTO legacy_count
        FROM {{tables.public_addresses}}
        WHERE deleted_at IS NULL
          AND (reachability <> 'public' OR visible_to_team_id IS NOT NULL);

        IF legacy_count > 0 THEN
            RAISE EXCEPTION 'Refusing to drop legacy address reachability columns: % active non-neutral rows require explicit operator disposition', legacy_count;
        END IF;
    END IF;
END $$;

ALTER TABLE {{tables.public_addresses}}
    DROP COLUMN IF EXISTS visible_to_team_id,
    DROP COLUMN IF EXISTS reachability;
