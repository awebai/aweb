-- 002_drop_embedded_identity_tables.sql
--
-- Drops the embedded identity registry tables from the `aweb` schema.
--
-- This migration is intentionally activation-gated:
--   SET aweb.drop_embedded_identity_tables = 'on';
--
-- Rationale:
-- - the standalone awid service still uses these tables in its own schema
-- - the OSS repo still carries embedded/local-mode test coverage
-- - cloud can opt in to the drop without forcing the same change everywhere

DO $$
BEGIN
    IF '{{schema}}' <> 'aweb' THEN
        RAISE NOTICE 'Skipping embedded identity table drop for schema %', '{{schema}}';
        RETURN;
    END IF;

    IF COALESCE(current_setting('aweb.drop_embedded_identity_tables', true), 'off') <> 'on' THEN
        RAISE NOTICE
            'Skipping embedded identity table drop for schema %; set aweb.drop_embedded_identity_tables=on to activate',
            '{{schema}}';
        RETURN;
    END IF;

    DROP TABLE IF EXISTS {{tables.replacement_announcements}};
    DROP TABLE IF EXISTS {{tables.public_addresses}};
    DROP TABLE IF EXISTS {{tables.dns_namespaces}};
    DROP TABLE IF EXISTS {{tables.did_aw_log}};
    DROP TABLE IF EXISTS {{tables.did_aw_mappings}};
END $$;
