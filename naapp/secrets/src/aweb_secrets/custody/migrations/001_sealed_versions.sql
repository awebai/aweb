-- Sealed secret versions: the value encrypted under a fresh data key, and that
-- data key wrapped by the key-encryption key named by key_id. Both are bound to
-- (app, installation, team, secret, version), so a row copied to another
-- secret or version does not unseal. No column holds a value in the clear.

CREATE TABLE IF NOT EXISTS {{tables.sealed_versions}} (
    secret_id    TEXT NOT NULL,
    version      INTEGER NOT NULL CHECK (version > 0),
    key_id       TEXT NOT NULL,
    wrapped_key  BYTEA NOT NULL,
    nonce        BYTEA NOT NULL,
    ciphertext   BYTEA NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (secret_id, version)
);
