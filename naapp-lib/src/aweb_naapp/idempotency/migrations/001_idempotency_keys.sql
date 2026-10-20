-- Idempotency keys: one row per app-chosen key tuple, written in the caller's
-- transaction with the canonical request hash and the receipt it produced.
-- Rows outlive their retention so an expired key answers "expired" instead of
-- executing again.

CREATE TABLE IF NOT EXISTS {{tables.idempotency_keys}} (
    key           TEXT[] PRIMARY KEY,
    request_hash  BYTEA NOT NULL,
    receipt_ref   TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL
);
