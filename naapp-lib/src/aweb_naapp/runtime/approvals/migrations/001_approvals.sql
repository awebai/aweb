-- Approval requests are frozen at mint: canonical bytes and their digest never change.
CREATE TABLE IF NOT EXISTS {{tables.approval_requests}} (
    request_ref TEXT PRIMARY KEY,
    request_sha256 TEXT NOT NULL,
    canonical BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE OR REPLACE FUNCTION {{schema}}.aweb_naapp_refuse_request_update() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'approval requests are immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER approval_requests_immutable
    BEFORE UPDATE ON {{tables.approval_requests}}
    FOR EACH ROW EXECUTE FUNCTION {{schema}}.aweb_naapp_refuse_request_update();

CREATE TABLE IF NOT EXISTS {{tables.approvals}} (
    approval_id TEXT PRIMARY KEY,
    request_ref TEXT NOT NULL UNIQUE REFERENCES {{tables.approval_requests}}(request_ref),
    request_sha256 TEXT NOT NULL,
    policy_ref TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    requested_by TEXT NOT NULL,
    approver_subject TEXT NOT NULL,
    approver_subject_type TEXT NOT NULL,
    authenticator TEXT CHECK (authenticator IN ('member_session', 'passkey')),
    auth_evidence_ref TEXT,
    presentation_kind TEXT NOT NULL CHECK (presentation_kind IN ('link', 'task')),
    presentation_ref TEXT,
    task_answer_ref TEXT,
    state TEXT NOT NULL
        CHECK (state IN ('pending', 'approved', 'rejected', 'consumed', 'revoked')),
    delivery_status TEXT NOT NULL CHECK (delivery_status IN ('not_required', 'pending', 'delivered', 'failed')),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    decided_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    consumed_operation_id TEXT,
    consumed_at TIMESTAMPTZ,
    dispatch_outcome TEXT CHECK (dispatch_outcome IN (
        'dispatching', 'completed', 'not_sent', 'outcome_unknown',
        'reconciled_completed', 'reconciled_failed', 'reconciled_unknown')),
    response_status TEXT,
    outcome_at TIMESTAMPTZ,
    CHECK (task_answer_ref IS NULL OR presentation_kind = 'task'),
    CHECK ((state = 'consumed') = (consumed_operation_id IS NOT NULL)),
    CHECK ((state = 'consumed') = (dispatch_outcome IS NOT NULL))
);

-- A dispatch still in flight or of unknown outcome blocks new admission for the same request.
CREATE INDEX IF NOT EXISTS idx_approvals_unreconciled
    ON {{tables.approvals}}(request_sha256)
    WHERE dispatch_outcome IN ('dispatching', 'outcome_unknown');

CREATE TABLE IF NOT EXISTS {{tables.approval_links}} (
    link_id TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL UNIQUE REFERENCES {{tables.approvals}}(approval_id),
    request_sha256 TEXT NOT NULL,
    verifier_sha256 TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    used_at TIMESTAMPTZ
);

