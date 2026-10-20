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

-- Login attempts per client in its current fixed window, which starts at the
-- client's first attempt. The client key is what the deployment says
-- identifies a client: the peer address, or a configured trusted proxy header.
CREATE TABLE IF NOT EXISTS {{tables.console_login_attempts}} (
    client_key    TEXT PRIMARY KEY,
    window_start  TIMESTAMPTZ NOT NULL,
    attempts      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_console_login_attempts_window
    ON {{tables.console_login_attempts}} (window_start);

-- Login request volume per scope, in buckets of the limiter's window,
-- throttled requests included.
CREATE TABLE IF NOT EXISTS {{tables.console_login_volume}} (
    scope         TEXT NOT NULL,
    window_start  TIMESTAMPTZ NOT NULL,
    requests      INTEGER NOT NULL,
    throttled     INTEGER NOT NULL,
    PRIMARY KEY (scope, window_start)
);
