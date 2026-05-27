-- 006_identity_encryption_key_custody.sql
-- Sender-visible custody signal for identity-authorized E2E encryption keys.

ALTER TABLE {{tables.identity_encryption_keys}}
    ADD COLUMN IF NOT EXISTS assertion_custody TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_identity_encryption_keys_assertion_custody'
    ) THEN
        ALTER TABLE {{tables.identity_encryption_keys}}
            ADD CONSTRAINT chk_identity_encryption_keys_assertion_custody
            CHECK (
                assertion_custody IS NULL
                OR assertion_custody IN ('self', 'hosted_custodial')
            );
    END IF;
END $$;
