-- Anonymous handoff references confer no authority. Ceremony completion and
-- result release are distinct, with an absolute ten-minute lifetime.
CREATE TABLE IF NOT EXISTS {{tables.console_handoffs}} (
    handoff_id UUID PRIMARY KEY,
    purpose TEXT NOT NULL CHECK (purpose IN ('credential', 'session')),
    client_key TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    verifier_sha256 BYTEA NOT NULL,
    public_scope JSONB NOT NULL,
    client_hostname TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    browser_sha256 BYTEA,
    csrf_sha256 BYTEA,
    challenge TEXT,
    credential JSONB,
    code_sha256 BYTEA,
    completed_at TIMESTAMPTZ,
    released_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS console_handoffs_expiry ON {{tables.console_handoffs}} (expires_at);
