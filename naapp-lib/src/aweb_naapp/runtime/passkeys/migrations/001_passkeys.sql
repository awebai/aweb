-- Owner-designated app-local approvers. One designation per scope is live
-- (superseded_at IS NULL); a recovery's new approver takes effect only at
-- effective_at, after the cooling-off. A contact change waits for
-- pending_contact_at.
CREATE TABLE IF NOT EXISTS {{tables.passkey_approvers}} (
    subject TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    contact TEXT NOT NULL,
    designated_by TEXT NOT NULL,
    designated_at TIMESTAMPTZ NOT NULL,
    effective_at TIMESTAMPTZ NOT NULL,
    superseded_at TIMESTAMPTZ,
    pending_contact TEXT,
    pending_contact_at TIMESTAMPTZ,
    CHECK ((pending_contact IS NULL) = (pending_contact_at IS NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_passkey_approvers_current
    ON {{tables.passkey_approvers}}(scope) WHERE superseded_at IS NULL;

-- Each verified owner act authorises one designation only.
CREATE TABLE IF NOT EXISTS {{tables.passkey_owner_acts}} (
    act_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    signer TEXT NOT NULL,
    scope TEXT NOT NULL,
    subject TEXT NOT NULL REFERENCES {{tables.passkey_approvers}}(subject),
    used_at TIMESTAMPTZ NOT NULL
);

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
-- approval challenge binds the approval, purpose, task answer and nonce it was
-- derived from; a contact-change challenge binds the new contact's digest; a
-- login challenge binds the scope and subject it was issued for.
CREATE TABLE IF NOT EXISTS {{tables.passkey_challenges}} (
    challenge BYTEA PRIMARY KEY,
    issued_seq BIGSERIAL NOT NULL,
    purpose TEXT NOT NULL
        CHECK (purpose IN ('enrolment', 'approve', 'reject', 'view', 'contact_change', 'login')),
    subject TEXT NOT NULL REFERENCES {{tables.passkey_approvers}}(subject),
    enrolment_id TEXT REFERENCES {{tables.passkey_enrolments}}(enrolment_id),
    approval_id TEXT,
    task_answer_ref TEXT,
    contact_sha256 TEXT,
    nonce BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    CHECK ((purpose = 'enrolment') = (enrolment_id IS NOT NULL)),
    CHECK ((purpose IN ('approve', 'reject', 'view')) = (approval_id IS NOT NULL)),
    CHECK ((purpose = 'contact_change') = (contact_sha256 IS NOT NULL))
);

-- Issuance removes expired challenges and keeps a bounded number outstanding
-- per subject and purpose, so unauthenticated requests cannot grow the table.
CREATE INDEX IF NOT EXISTS idx_passkey_challenges_expiry
    ON {{tables.passkey_challenges}}(expires_at);
CREATE INDEX IF NOT EXISTS idx_passkey_challenges_outstanding
    ON {{tables.passkey_challenges}}(subject, purpose, issued_seq) WHERE used_at IS NULL;

-- Restricted evidence behind an approval's auth_evidence_ref, and behind each
-- other passkey-authenticated act.
CREATE TABLE IF NOT EXISTS {{tables.passkey_assertions}} (
    evidence_ref TEXT PRIMARY KEY,
    subject TEXT NOT NULL REFERENCES {{tables.passkey_approvers}}(subject),
    credential_id BYTEA NOT NULL REFERENCES {{tables.passkey_credentials}}(credential_id),
    purpose TEXT NOT NULL
        CHECK (purpose IN ('approve', 'reject', 'view', 'contact_change', 'login')),
    approval_id TEXT,
    request_sha256 TEXT,
    policy_ref TEXT,
    policy_version INTEGER,
    task_answer_ref TEXT,
    sign_count BIGINT NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL
);
