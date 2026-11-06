-- Immutable B2 control association and local ceremony audit. S3 alone owns
-- the original dispatch's outcome; no control event is a hook or settlement.
CREATE TABLE {{tables.reconciliation_controls}} (
    control_id UUID PRIMARY KEY,
    approval_id TEXT NOT NULL UNIQUE REFERENCES {{tables.approvals}} (approval_id),
    app_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    install_generation BIGINT NOT NULL CHECK (install_generation >= 1),
    reconcile_ref TEXT NOT NULL,
    dispatch_id UUID NOT NULL REFERENCES {{tables.dispatches}} (dispatch_id),
    outcome TEXT NOT NULL CHECK (outcome IN ('completed','failed','unknown-closed')),
    request_ref TEXT NOT NULL UNIQUE,
    request_sha256 TEXT NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    policy_ref TEXT NOT NULL,
    policy_version BIGINT NOT NULL,
    owner_scope TEXT NOT NULL,
    owner_subject TEXT NOT NULL,
    owner_principal TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX reconciliation_controls_original ON {{tables.reconciliation_controls}}
    (installation_id,team_id,reconcile_ref);
CREATE TABLE {{tables.reconciliation_control_events}} (
    event_id UUID PRIMARY KEY,
    approval_id TEXT NOT NULL REFERENCES {{tables.reconciliation_controls}} (approval_id),
    kind TEXT NOT NULL CHECK (kind IN
        ('approval_requested','approval_decided','approval_revoked','dispatch_admitted','dispatch_outcome')),
    actor TEXT NOT NULL,
    subject TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    details JSONB NOT NULL
);
CREATE TABLE {{tables.reconciliation_control_proofs}} (
    approval_id TEXT PRIMARY KEY REFERENCES {{tables.reconciliation_controls}} (approval_id),
    evidence_ref TEXT NOT NULL,
    scope TEXT NOT NULL,
    subject TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('approve','reject')),
    commitment TEXT NOT NULL CHECK (commitment ~ '^[0-9a-f]{64}$')
);
CREATE TRIGGER reconciliation_controls_immutable BEFORE UPDATE OR DELETE ON {{tables.reconciliation_controls}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
CREATE TRIGGER reconciliation_control_events_immutable BEFORE UPDATE OR DELETE ON {{tables.reconciliation_control_events}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
CREATE TRIGGER reconciliation_control_proofs_immutable BEFORE UPDATE OR DELETE ON {{tables.reconciliation_control_proofs}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
