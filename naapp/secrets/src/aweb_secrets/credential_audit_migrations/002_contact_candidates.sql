-- One pending candidate, the original scheduling authority and both actual
-- state transitions. Random public refs never derive from private contacts.
CREATE TABLE {{tables.credential_contact_candidates}} (
    proof_id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    scope TEXT NOT NULL,
    app_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    role TEXT NOT NULL,
    contact_sha256 TEXT NOT NULL,
    effective_at TIMESTAMPTZ NOT NULL,
    verifier_sha256 TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    resource_ref TEXT NOT NULL UNIQUE,
    scheduled_ref TEXT NOT NULL UNIQUE,
    proven_ref TEXT UNIQUE,
    approval_id TEXT NOT NULL,
    commitment TEXT NOT NULL,
    retained_proof JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    CHECK ((completed_at IS NOT NULL) = (proven_ref IS NOT NULL)),
    CHECK (proven_ref IS NULL OR proven_ref <> scheduled_ref)
);
