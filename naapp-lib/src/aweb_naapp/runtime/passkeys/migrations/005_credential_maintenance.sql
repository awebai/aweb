-- An in-effect approver adds a passkey, or replaces one it selects, approved
-- by a passkey it already holds. The new credential registers first under a
-- credential_registration challenge; a credential_change challenge then binds
-- that exact credential and operation for the asserting passkey.
DO $$
DECLARE
    constraint_name TEXT;
BEGIN
    FOR constraint_name IN
        SELECT conname FROM pg_constraint
        WHERE conrelid = '{{tables.passkey_challenges}}'::regclass AND contype = 'c'
          AND pg_get_constraintdef(oid) LIKE '%''login''%'
    LOOP
        EXECUTE format('ALTER TABLE {{tables.passkey_challenges}} DROP CONSTRAINT %I', constraint_name);
    END LOOP;
    FOR constraint_name IN
        SELECT conname FROM pg_constraint
        WHERE conrelid = '{{tables.passkey_assertions}}'::regclass AND contype = 'c'
          AND pg_get_constraintdef(oid) LIKE '%''login''%'
    LOOP
        EXECUTE format('ALTER TABLE {{tables.passkey_assertions}} DROP CONSTRAINT %I', constraint_name);
    END LOOP;
END $$;

ALTER TABLE {{tables.passkey_challenges}} ADD CONSTRAINT passkey_challenges_purpose CHECK (
    purpose IN (
        'enrolment', 'approve', 'reject', 'view', 'contact_change', 'login',
        'credential_registration', 'credential_change'
    )
);
ALTER TABLE {{tables.passkey_assertions}} ADD CONSTRAINT passkey_assertions_purpose CHECK (
    purpose IN ('approve', 'reject', 'view', 'contact_change', 'login', 'credential_change')
);

-- The verified registration's counter, kept with the change challenge that
-- carries the registration until the change takes effect.
ALTER TABLE {{tables.passkey_challenges}} ADD COLUMN registered_sign_count BIGINT;

-- A credential added by a credential change names the assertion that
-- approved it, the challenge that assertion answered and, for a replace, the
-- credential it retired. Credentials registered any other way leave these NULL.
-- added_in and revoked_in are the top-level transactions that wrote the row
-- and revoked it (txid_current(), which a savepoint does not change), so a
-- record made in the same transaction can bind to exactly this write.
ALTER TABLE {{tables.passkey_credentials}}
    ADD COLUMN added_in BIGINT DEFAULT txid_current(),
    ADD COLUMN revoked_in BIGINT,
    ADD COLUMN added_by_evidence TEXT,
    ADD COLUMN added_by_challenge BYTEA UNIQUE,
    ADD COLUMN replaced_credential_id BYTEA,
    ADD CHECK ((added_by_evidence IS NULL) = (added_by_challenge IS NULL)),
    ADD CHECK (replaced_credential_id IS NULL OR added_by_challenge IS NOT NULL);
