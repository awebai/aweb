-- 005_identity_encryption_keys.sql
-- Identity-authorized encryption public keys for E2E message v2.
--
-- The registry stores and distributes assertions, but the assertion authority
-- remains the identity signing key. Clients must verify the assertion before
-- using the encryption key.

CREATE TABLE IF NOT EXISTS {{tables.identity_encryption_keys}} (
    did_aw                     TEXT NOT NULL REFERENCES {{tables.did_aw_mappings}}(did_aw) ON DELETE CASCADE,
    encryption_key_id          TEXT NOT NULL,
    encryption_public_key      TEXT NOT NULL,
    algorithm                  TEXT NOT NULL,
    identity_did               TEXT NOT NULL,
    identity_stable_id         TEXT NOT NULL,
    assertion_signature        TEXT NOT NULL,
    assertion_canonical        TEXT NOT NULL,
    created_at_text            TEXT NOT NULL,
    not_before_text            TEXT NOT NULL,
    expires_at_text            TEXT NOT NULL,
    assertion_created_at       TIMESTAMPTZ NOT NULL,
    not_before_at              TIMESTAMPTZ NOT NULL,
    expires_at                 TIMESTAMPTZ NOT NULL,
    previous_encryption_key_id TEXT,
    published_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at                 TIMESTAMPTZ,

    PRIMARY KEY (did_aw, encryption_key_id),
    CONSTRAINT chk_identity_encryption_keys_algorithm CHECK (algorithm IN ('x25519')),
    CONSTRAINT chk_identity_encryption_keys_key_id CHECK (encryption_key_id LIKE 'sha256:%'),
    CONSTRAINT chk_identity_encryption_keys_identity_did CHECK (identity_did LIKE 'did:key:z%'),
    CONSTRAINT chk_identity_encryption_keys_identity_stable_id CHECK (identity_stable_id LIKE 'did:aw:%')
);

CREATE INDEX IF NOT EXISTS idx_identity_encryption_keys_active
    ON {{tables.identity_encryption_keys}} (did_aw, published_at DESC)
    WHERE revoked_at IS NULL;
