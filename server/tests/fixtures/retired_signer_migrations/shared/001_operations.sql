CREATE TABLE {{tables.protected_signer_operations}} (
    operation_id TEXT PRIMARY KEY,
    handoff_id TEXT NOT NULL UNIQUE,
    requester TEXT NOT NULL,
    intent BYTEA NOT NULL,
    request BYTEA NOT NULL,
    digest TEXT NOT NULL,
    approval_id TEXT NOT NULL UNIQUE,
    candidate_links JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    result JSONB,
    evidence_ref TEXT,
    committed_at TIMESTAMPTZ
);
