-- Owner-session preparation retains provenance separately from the approved
-- public request and from the exact-act approval that can authorize an effect.
ALTER TABLE {{tables.protected_signer_operations}}
    ADD COLUMN initiator_subject TEXT,
    ADD COLUMN initiator_scope TEXT,
    ADD COLUMN initiation_selection BYTEA,
    ADD CONSTRAINT protected_owner_initiation_complete CHECK (
        (initiator_subject IS NULL AND initiator_scope IS NULL AND initiation_selection IS NULL)
        OR (initiator_subject IS NOT NULL AND initiator_scope IS NOT NULL AND initiation_selection IS NOT NULL)
    );
