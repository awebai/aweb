-- Restricted historical authorization. Never an authority registry or outbox.
-- Completion retains the original signed artifact after nonce retention ends.
CREATE TABLE {{tables.credential_authorizations}} (
    subject TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    app_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    role TEXT NOT NULL,
    contact_sha256 TEXT NOT NULL,
    effective_at TIMESTAMPTZ NOT NULL,
    authority TEXT NOT NULL CHECK (authority IN ('owner_act', 'passkey_session')),
    commitment TEXT NOT NULL,
    approval_id TEXT,
    signing BYTEA,
    signature TEXT,
    retained_proof JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    CHECK ((authority = 'owner_act') = (signing IS NOT NULL AND signature IS NOT NULL)),
    CHECK ((authority = 'passkey_session') = (retained_proof IS NOT NULL))
);

CREATE TABLE {{tables.credential_completion_links}} (
    enrolment_id TEXT PRIMARY KEY,
    subject TEXT NOT NULL REFERENCES {{tables.credential_authorizations}}(subject),
    verifier_sha256 TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    credential_ref TEXT UNIQUE,
    credential_id BYTEA UNIQUE,
    CHECK ((completed_at IS NOT NULL) = (credential_ref IS NOT NULL AND credential_id IS NOT NULL))
);

-- Login/reissue and B2 change ceremonies remain attributable local events.
-- Tokens, challenges and proof bodies never occur in the shared AuditEvent.
CREATE TABLE {{tables.credential_audit_events}} (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind TEXT NOT NULL,
    actor TEXT NOT NULL,
    subject TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    approval_id TEXT,
    details JSONB NOT NULL
);
