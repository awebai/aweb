-- 016_identity_session_grants.sql
-- Scoped, expiring, revocable session grants derived from a durable identity.
-- A worker holding the grant's session keypair may act AS the subject for
-- mail/chat only. Minting and revocation require ordinary team-certificate
-- auth; grant-authenticated requests can never mint or revoke grants.

CREATE TABLE IF NOT EXISTS {{tables.identity_session_grants}} (
    grant_id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id                  TEXT NOT NULL,
    subject_agent_id         UUID NOT NULL REFERENCES {{tables.agents}}(agent_id) ON DELETE CASCADE,
    subject_did_aw           TEXT
                             CHECK (subject_did_aw IS NULL OR subject_did_aw LIKE 'did:aw:%'),
    grant_did_key            TEXT NOT NULL
                             CHECK (grant_did_key LIKE 'did:key:z%'),
    scopes                   TEXT[] NOT NULL
                             CHECK (cardinality(scopes) > 0),
    label                    TEXT,
    issued_by_certificate_id TEXT,
    issued_at                TIMESTAMPTZ NOT NULL,
    expires_at               TIMESTAMPTZ NOT NULL,
    revoked_at               TIMESTAMPTZ,
    CHECK (expires_at > issued_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_session_grants_active_did_key
    ON {{tables.identity_session_grants}} (grant_did_key)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_identity_session_grants_expiry
    ON {{tables.identity_session_grants}} (expires_at);

CREATE INDEX IF NOT EXISTS idx_identity_session_grants_subject
    ON {{tables.identity_session_grants}} (team_id, subject_agent_id);
