-- Custody of secret values, keyed by installation, team and secret. One row
-- per secret allocates its version numbers, so a destroyed version's number is
-- never reused, and records whether the secret is disabled. One row per sealed
-- version holds the value encrypted under a fresh data key, and that data key
-- wrapped by the key-encryption key named by key_id. Both are bound to (app,
-- installation, team, secret, version), so a row copied to another secret or
-- version does not unseal. No column holds a value in the clear.
--
-- Destroying a version deletes its row from the live store. Copies in backups
-- and the write-ahead log stay decryptable until they expire or the
-- key-encryption key is retired.

CREATE TABLE IF NOT EXISTS {{tables.custody_secrets}} (
    installation_id  TEXT NOT NULL,
    team_id          TEXT NOT NULL,
    secret_id        TEXT NOT NULL,
    last_version     INTEGER NOT NULL CHECK (last_version > 0),
    disabled_at      TIMESTAMPTZ,
    PRIMARY KEY (installation_id, team_id, secret_id)
);

CREATE TABLE IF NOT EXISTS {{tables.sealed_versions}} (
    installation_id  TEXT NOT NULL,
    team_id          TEXT NOT NULL,
    secret_id        TEXT NOT NULL,
    version          INTEGER NOT NULL CHECK (version > 0),
    key_id           TEXT NOT NULL,
    wrapped_key      BYTEA NOT NULL,
    nonce            BYTEA NOT NULL,
    ciphertext       BYTEA NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (installation_id, team_id, secret_id, version),
    FOREIGN KEY (installation_id, team_id, secret_id)
        REFERENCES {{tables.custody_secrets}} (installation_id, team_id, secret_id)
);
