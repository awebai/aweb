-- Idempotency keys: one row per app-chosen key tuple, written in the caller's
-- transaction with the canonical request hash and the receipt it produced.
-- After retention, expiring a key clears its hash and receipt; the key itself
-- stays as a tombstone, so it answers "expired" instead of executing again.

CREATE TABLE IF NOT EXISTS {{tables.idempotency_keys}} (
    key           TEXT[] PRIMARY KEY,
    request_hash  BYTEA,
    receipt_ref   TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL,
    CHECK ((request_hash IS NULL) = (receipt_ref IS NULL))
);

CREATE INDEX IF NOT EXISTS idx_idempotency_keys_unexpired
    ON {{tables.idempotency_keys}} (expires_at) WHERE request_hash IS NOT NULL;
