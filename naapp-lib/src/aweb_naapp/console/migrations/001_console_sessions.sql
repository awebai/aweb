-- Console sessions for an app-origin human page, opened after a passkey
-- login. Only hashes of the session and CSRF tokens are stored.

CREATE TABLE IF NOT EXISTS {{tables.console_sessions}} (
    token_sha256  BYTEA PRIMARY KEY,
    csrf_sha256   BYTEA NOT NULL,
    subject       TEXT NOT NULL,
    scope         TEXT NOT NULL,
    evidence_ref  TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL,
    closed_at     TIMESTAMPTZ
);
