-- Each credential a holding's own current credential approved adding (Q1
-- human-credential.add, or the new key of human-credential.replace): its
-- opaque receipt reference, and the retained proof and commitment of that
-- approval. One key has one reference, one approval adds one key. Kept with
-- the rest of the credential governance record; it has no read route.
CREATE TABLE {{tables.credential_added_keys}} (
    credential_id BYTEA PRIMARY KEY,
    subject TEXT NOT NULL,
    scope TEXT NOT NULL,
    app_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    generation BIGINT NOT NULL,
    credential_ref TEXT NOT NULL UNIQUE,
    evidence_ref TEXT NOT NULL UNIQUE,
    commitment TEXT NOT NULL,
    retained_proof JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
