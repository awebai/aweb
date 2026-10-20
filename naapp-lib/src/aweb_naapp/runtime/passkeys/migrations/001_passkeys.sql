-- Owner-designated app-local approvers. One current approver per scope; a
-- re-designation supersedes the previous one.
CREATE TABLE IF NOT EXISTS {{tables.passkey_approvers}} (
    subject TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    contact TEXT NOT NULL,
    designated_by TEXT NOT NULL,
    designated_at TIMESTAMPTZ NOT NULL,
    superseded_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_passkey_approvers_current
    ON {{tables.passkey_approvers}}(scope) WHERE superseded_at IS NULL;

-- Enrolment links, sent only to the approver's registered contact; verifier hash only.
CREATE TABLE IF NOT EXISTS {{tables.passkey_enrolments}} (
    enrolment_id TEXT PRIMARY KEY,
    subject TEXT NOT NULL REFERENCES {{tables.passkey_approvers}}(subject),
    verifier_sha256 TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS {{tables.passkey_credentials}} (
    credential_id BYTEA PRIMARY KEY,
    subject TEXT NOT NULL REFERENCES {{tables.passkey_approvers}}(subject),
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

-- Server-held challenge state. An enrolment challenge binds its enrolment; an
-- assertion challenge binds the approval, decision and nonce it was derived from.
CREATE TABLE IF NOT EXISTS {{tables.passkey_challenges}} (
    challenge BYTEA PRIMARY KEY,
    purpose TEXT NOT NULL CHECK (purpose IN ('enrolment', 'assertion')),
    subject TEXT NOT NULL REFERENCES {{tables.passkey_approvers}}(subject),
    enrolment_id TEXT REFERENCES {{tables.passkey_enrolments}}(enrolment_id),
    approval_id TEXT,
    decision TEXT CHECK (decision IN ('approve', 'reject')),
    nonce BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    CHECK ((purpose = 'enrolment') = (enrolment_id IS NOT NULL)),
    CHECK ((purpose = 'assertion') = (approval_id IS NOT NULL AND decision IS NOT NULL))
);

-- Restricted evidence behind an approval's auth_evidence_ref.
CREATE TABLE IF NOT EXISTS {{tables.passkey_assertions}} (
    evidence_ref TEXT PRIMARY KEY,
    subject TEXT NOT NULL REFERENCES {{tables.passkey_approvers}}(subject),
    credential_id BYTEA NOT NULL REFERENCES {{tables.passkey_credentials}}(credential_id),
    approval_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('approve', 'reject')),
    request_sha256 TEXT NOT NULL,
    policy_ref TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    sign_count BIGINT NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL
);
