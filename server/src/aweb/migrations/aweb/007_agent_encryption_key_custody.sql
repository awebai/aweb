-- 007_agent_encryption_key_custody.sql
-- Sender-visible custody signal for service-local E2E encryption keys.

ALTER TABLE {{tables.agent_encryption_keys}}
    ADD COLUMN IF NOT EXISTS assertion_custody TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'agent_encryption_keys_assertion_custody_valid'
    ) THEN
        ALTER TABLE {{tables.agent_encryption_keys}}
            ADD CONSTRAINT agent_encryption_keys_assertion_custody_valid
            CHECK (
                assertion_custody IS NULL
                OR assertion_custody IN ('self', 'hosted_custodial')
            );
    END IF;
END $$;
