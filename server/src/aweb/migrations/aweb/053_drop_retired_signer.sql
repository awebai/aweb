-- Retire the candidate-only signer's data. Stop the old signer before upgrade.
-- Its schema was configurable and need not be the active application's schema.
-- Only a pgdbm ledger for this package's retired module establishes ownership;
-- unrelated tables with the same names are left alone. No CASCADE is used.
DO $$
DECLARE
    legacy_schema text;
    owns_signer boolean;
BEGIN
    FOR legacy_schema IN
        SELECT table_schema FROM information_schema.columns
        WHERE table_name = 'schema_migrations' AND column_name = 'module_name'
          AND has_schema_privilege(table_schema, 'USAGE')
    LOOP
        EXECUTE format(
            'SELECT EXISTS (SELECT 1 FROM %I.schema_migrations WHERE module_name = $1)',
            legacy_schema
        ) INTO owns_signer USING 'aweb_independent_protected_signer';
        IF owns_signer THEN
            EXECUTE format('DROP TABLE IF EXISTS %I.%I', legacy_schema, 'protected_requester_bindings');
            EXECUTE format('DROP TABLE IF EXISTS %I.%I', legacy_schema, 'protected_authorizer_bindings');
            EXECUTE format('DROP TABLE IF EXISTS %I.%I', legacy_schema, 'protected_local_audit');
            EXECUTE format('DROP TABLE IF EXISTS %I.%I', legacy_schema, 'protected_operator_bootstraps');
            EXECUTE format('DROP TABLE IF EXISTS %I.%I', legacy_schema, 'protected_admission_policies');
            EXECUTE format('DROP TABLE IF EXISTS %I.%I', legacy_schema, 'protected_root_admissions');
            EXECUTE format('DROP TABLE IF EXISTS %I.%I', legacy_schema, 'protected_root_endorsements');
        END IF;
    END LOOP;
END
$$;
