-- Associate B2 callbacks with the SAME ordered S12 slot. The callback precedes
-- S12's slot insertion, so this binding is checked at the outer commit.
CREATE UNIQUE INDEX idx_run_slot_audit_binding ON {{tables.run_slot_approvals}}
    (installation_id,team_id,run_id,ordinal,approval_id,approval_ref,policy_ref);
CREATE TABLE {{tables.run_approval_audits}} (
    approval_id TEXT PRIMARY KEY,
    dispatch_id UUID NOT NULL REFERENCES {{tables.run_contexts}} (dispatch_id),
    installation_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    request_ref TEXT NOT NULL UNIQUE,
    request_sha256 TEXT NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    policy_ref TEXT NOT NULL,
    FOREIGN KEY (installation_id,team_id,run_id,ordinal,approval_id,request_ref,policy_ref)
        REFERENCES {{tables.run_slot_approvals}}
            (installation_id,team_id,run_id,ordinal,approval_id,approval_ref,policy_ref)
        DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE {{tables.run_approval_audit_proofs}} (
    approval_id TEXT PRIMARY KEY REFERENCES {{tables.run_approval_audits}} (approval_id),
    evidence_ref TEXT NOT NULL,
    scope TEXT NOT NULL,
    subject TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('approve','reject')),
    commitment TEXT NOT NULL CHECK (commitment ~ '^[0-9a-f]{64}$')
);
CREATE TRIGGER run_approval_audits_immutable BEFORE UPDATE OR DELETE ON {{tables.run_approval_audits}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
CREATE TRIGGER run_approval_audit_proofs_immutable BEFORE UPDATE OR DELETE ON {{tables.run_approval_audit_proofs}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();

-- The existing value-free activity reader/writer serves BOTH kinds of secret
-- use. Replace its broker-context FK with the sole S3 dispatch FK. Historical
-- broker IDs remain the same and every new run still has one S3 UUID.
DO $$
DECLARE existing_constraint TEXT;
BEGIN
    FOR existing_constraint IN
        SELECT conname FROM pg_constraint
        WHERE conrelid='{{tables.broker_use_events}}'::regclass
          AND confrelid='{{tables.broker_audit_contexts}}'::regclass
          AND contype='f'
    LOOP
        EXECUTE format('ALTER TABLE {{tables.broker_use_events}} DROP CONSTRAINT %I', existing_constraint);
    END LOOP;
END;
$$;
ALTER TABLE {{tables.broker_use_events}} ADD CONSTRAINT secrets_use_events_dispatch_fk
    FOREIGN KEY (dispatch_id) REFERENCES {{tables.dispatches}} (dispatch_id)
    DEFERRABLE INITIALLY DEFERRED;
