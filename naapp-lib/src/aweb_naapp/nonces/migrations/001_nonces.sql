CREATE TABLE IF NOT EXISTS {{tables.scoped_nonces}} (
    scope TEXT NOT NULL,
    nonce TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (scope, nonce)
);
CREATE INDEX IF NOT EXISTS idx_scoped_nonces_expiry
    ON {{tables.scoped_nonces}} (expires_at);
