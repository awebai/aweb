-- Custody of secret values. One row per secret allocates its version numbers,
-- so a destroyed version's number is never reused, and records whether the
-- secret is disabled. One row per sealed version holds the value encrypted
-- under a fresh data key, and that data key wrapped by the key-encryption key
-- named by key_id. Both are bound to (app, installation, team, secret,
-- version), so a row copied to another secret or version does not unseal. No
-- column holds a value in the clear. Deleting a version's row crypto-shreds it.

CREATE TABLE IF NOT EXISTS {{tables.custody_secrets}} (
    secret_id     TEXT PRIMARY KEY,
    last_version  INTEGER NOT NULL CHECK (last_version > 0),
    disabled_at   TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS {{tables.sealed_versions}} (
    secret_id    TEXT NOT NULL REFERENCES {{tables.custody_secrets}} (secret_id),
    version      INTEGER NOT NULL CHECK (version > 0),
    key_id       TEXT NOT NULL,
    wrapped_key  BYTEA NOT NULL,
    nonce        BYTEA NOT NULL,
    ciphertext   BYTEA NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (secret_id, version)
);
