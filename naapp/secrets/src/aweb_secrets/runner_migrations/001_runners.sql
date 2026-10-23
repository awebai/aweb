CREATE TABLE IF NOT EXISTS {{tables.runners}} (
    runner_id TEXT PRIMARY KEY,
    installation_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    record JSONB NOT NULL,
    signing_key TEXT,
    encryption_key TEXT,
    code_hash BYTEA UNIQUE,
    code_expires_at TIMESTAMPTZ,
    deregistered_at TIMESTAMPTZ,
    CHECK ((signing_key IS NULL) = (encryption_key IS NULL)),
    CHECK ((code_hash IS NULL) = (code_expires_at IS NULL))
);
CREATE INDEX IF NOT EXISTS idx_runners_installation
    ON {{tables.runners}} (installation_id);
