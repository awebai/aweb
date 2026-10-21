-- Capability links (docs/page-links.md §1-§3).
--
-- capability_links: one row per minted link. `record` is the immutable record
-- the creator minted, without its verifier; only the secret's verifier is
-- stored, never the secret. `revoked_at` and `used_at` are its lifecycle.
--
-- link_sessions: a holder's short-lived, key-bound sessions. The CSRF token is
-- stored only as its SHA-256.
--
-- link_nonces: every accepted (session, nonce) pair, kept until the later of
-- the session's expiry and the request's time plus the clock window, so a
-- signed request is never accepted twice. The primary key is the uniqueness
-- every worker shares.

CREATE TABLE IF NOT EXISTS {{tables.capability_links}} (
    link_id          TEXT PRIMARY KEY,
    verifier_sha256  TEXT NOT NULL UNIQUE,
    team_id          TEXT NOT NULL,
    installation_id  TEXT NOT NULL,
    page_id          TEXT NOT NULL,
    record           JSONB NOT NULL,
    created_by       TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL,
    expires_at       TIMESTAMPTZ NOT NULL,
    one_use          BOOLEAN NOT NULL,
    revoked_at       TIMESTAMPTZ,
    used_at          TIMESTAMPTZ,
    used_by_operation TEXT,
    CHECK (expires_at > created_at),
    CHECK ((used_at IS NULL) = (used_by_operation IS NULL))
);

CREATE INDEX IF NOT EXISTS idx_capability_links_page
    ON {{tables.capability_links}} (installation_id, page_id);

CREATE TABLE IF NOT EXISTS {{tables.link_sessions}} (
    session_id       TEXT PRIMARY KEY,
    link_id          TEXT NOT NULL REFERENCES {{tables.capability_links}} (link_id) ON DELETE CASCADE,
    session_did_key  TEXT NOT NULL,
    csrf_sha256      BYTEA NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL,
    expires_at       TIMESTAMPTZ NOT NULL,
    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_link_sessions_expiry
    ON {{tables.link_sessions}} (expires_at);

CREATE TABLE IF NOT EXISTS {{tables.link_nonces}} (
    session_id  TEXT NOT NULL,
    nonce       TEXT NOT NULL,
    keep_until  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (session_id, nonce)
);

CREATE INDEX IF NOT EXISTS idx_link_nonces_keep_until
    ON {{tables.link_nonces}} (keep_until);
