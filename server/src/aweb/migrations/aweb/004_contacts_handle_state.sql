-- 004_contacts_handle_state.sql
-- Add handle-level contacts and pending contact state without changing 001.

ALTER TABLE {{tables.contacts}}
    ADD COLUMN reference_type TEXT NOT NULL DEFAULT 'identity',
    ADD COLUMN status TEXT NOT NULL DEFAULT 'active',
    ADD COLUMN handle_namespace TEXT,
    ADD COLUMN target_agent_name TEXT;

ALTER TABLE {{tables.contacts}}
    ALTER COLUMN contact_address DROP NOT NULL;

ALTER TABLE {{tables.contacts}}
    ADD CONSTRAINT contacts_reference_type_valid
    CHECK (reference_type IN ('identity', 'handle'));

ALTER TABLE {{tables.contacts}}
    ADD CONSTRAINT contacts_status_valid
    CHECK (status IN ('pending', 'active'));

ALTER TABLE {{tables.contacts}}
    ADD CONSTRAINT contacts_reference_shape_valid
    CHECK (
        (
            reference_type = 'identity'
            AND contact_address IS NOT NULL
            AND handle_namespace IS NULL
            AND target_agent_name IS NULL
        )
        OR (
            reference_type = 'handle'
            AND contact_address IS NULL
            AND handle_namespace IS NOT NULL
        )
    );

CREATE UNIQUE INDEX IF NOT EXISTS idx_contacts_owner_handle_target
    ON {{tables.contacts}} (owner_did, handle_namespace, COALESCE(target_agent_name, ''))
    WHERE reference_type = 'handle';
