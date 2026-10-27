-- A role an owner act revokes keeps the act's signed artifact as its authority,
-- as an owner-act designation does; the commitment is the act's SHA-256.
ALTER TABLE {{tables.credential_narrowing_authority}}
    ADD COLUMN signing BYTEA,
    ADD COLUMN signature TEXT;

DO $$
DECLARE existing_constraint TEXT;
BEGIN
    FOR existing_constraint IN
        SELECT conname FROM pg_constraint
        WHERE conrelid='{{tables.credential_narrowing_authority}}'::regclass AND contype='c'
    LOOP
        EXECUTE format(
            'ALTER TABLE {{tables.credential_narrowing_authority}} DROP CONSTRAINT %I',
            existing_constraint
        );
    END LOOP;
END;
$$;

ALTER TABLE {{tables.credential_narrowing_authority}}
    ADD CONSTRAINT credential_narrowing_generation CHECK (generation > 0),
    ADD CONSTRAINT credential_narrowing_authority_kind
        CHECK (authority IN ('team_cert', 'passkey_session', 'owner_act')),
    ADD CONSTRAINT credential_narrowing_passkey_session_proof
        CHECK ((authority = 'passkey_session') = (retained_proof IS NOT NULL)),
    ADD CONSTRAINT credential_narrowing_owner_act_artifact
        CHECK ((authority = 'owner_act') = (signing IS NOT NULL AND signature IS NOT NULL)),
    ADD CONSTRAINT credential_narrowing_commitment
        CHECK ((authority = 'team_cert') = (commitment IS NULL));
