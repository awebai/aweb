-- Retire the candidate-only signer's data. Stop the old signer before upgrade.
-- Its schema was configurable and need not be the active application's schema.
-- Only a pgdbm ledger for this package's retired module establishes ownership;
-- unrelated tables with the same names are left alone. No CASCADE is used.
DO $$
DECLARE
    legacy_schema text;
    owns_signer boolean;
    owns_passkeys boolean;
BEGIN
    FOR legacy_schema IN
        SELECT table_schema FROM information_schema.columns
        WHERE table_name = 'schema_migrations' AND column_name = 'module_name'
          AND has_schema_privilege(table_schema, 'USAGE')
    LOOP
        EXECUTE format(
            'SELECT EXISTS (SELECT 1 FROM %I.schema_migrations WHERE module_name = $1)',
            legacy_schema
        ) INTO owns_signer USING 'aweb_naapp_protected_signer';
        IF owns_signer THEN
            EXECUTE format('DROP TABLE IF EXISTS %I.%I', legacy_schema, 'protected_signer_notice_reservations');
            EXECUTE format('DROP TABLE IF EXISTS %I.%I', legacy_schema, 'protected_signer_operations');
        END IF;
        -- Passkeys were also installed in the signer's configurable schema.
        -- Restore the ordinary application shape wherever this module ran.
        EXECUTE format(
            'SELECT EXISTS (SELECT 1 FROM %I.schema_migrations WHERE module_name = $1)',
            legacy_schema
        ) INTO owns_passkeys USING 'aweb_naapp_passkeys';
        IF owns_passkeys AND EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = legacy_schema AND table_name = 'passkey_proofs'
              AND column_name = 'authority_context'
        ) THEN
            EXECUTE format(
                'DELETE FROM %I.passkey_proofs WHERE authority_context IS NOT NULL',
                legacy_schema
            );
            EXECUTE format(
                'ALTER TABLE %I.passkey_proofs '
                'DROP CONSTRAINT IF EXISTS passkey_proof_context_shape, '
                'DROP COLUMN IF EXISTS authority_context, '
                'ALTER COLUMN app_id SET NOT NULL, '
                'ALTER COLUMN team_id SET NOT NULL, '
                'ALTER COLUMN installation_id SET NOT NULL', legacy_schema
            );
        END IF;
    END LOOP;
END
$$;
