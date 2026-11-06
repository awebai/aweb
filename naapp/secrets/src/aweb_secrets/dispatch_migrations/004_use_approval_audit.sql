-- Audit association only; B2 and S3 remain the sole authority/state machines.
CREATE TABLE {{tables.use_approval_audits}} (
    approval_id TEXT PRIMARY KEY,
    dispatch_id UUID NOT NULL REFERENCES {{tables.broker_audit_contexts}} (dispatch_id),
    request_ref TEXT NOT NULL UNIQUE,
    request_sha256 TEXT NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$')
);
CREATE TABLE {{tables.use_approval_audit_proofs}} (
    approval_id TEXT PRIMARY KEY REFERENCES {{tables.use_approval_audits}} (approval_id),
    evidence_ref TEXT NOT NULL,
    scope TEXT NOT NULL,
    subject TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('approve','reject')),
    commitment TEXT NOT NULL CHECK (commitment ~ '^[0-9a-f]{64}$')
);
CREATE TRIGGER use_approval_audits_immutable BEFORE UPDATE OR DELETE ON {{tables.use_approval_audits}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
CREATE TRIGGER use_approval_audit_proofs_immutable BEFORE UPDATE OR DELETE ON {{tables.use_approval_audit_proofs}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
