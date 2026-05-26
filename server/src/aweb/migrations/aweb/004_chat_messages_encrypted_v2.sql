-- 004_chat_messages_encrypted_v2.sql
-- Opaque E2E chat storage. Existing rows are legacy plaintext v1.

ALTER TABLE {{tables.chat_messages}}
    ADD COLUMN IF NOT EXISTS message_version INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS content_mode TEXT NOT NULL DEFAULT 'legacy_plaintext_v1',
    ADD COLUMN IF NOT EXISTS encrypted_envelope JSONB,
    ADD COLUMN IF NOT EXISTS encrypted_ciphertext TEXT,
    ADD COLUMN IF NOT EXISTS encrypted_key_wraps JSONB,
    ADD COLUMN IF NOT EXISTS encrypted_ciphertext_hash TEXT,
    ADD COLUMN IF NOT EXISTS encrypted_ciphertext_size INTEGER,
    ADD COLUMN IF NOT EXISTS encrypted_key_wraps_hash TEXT,
    ADD COLUMN IF NOT EXISTS encrypted_inner_header_hash TEXT,
    ADD COLUMN IF NOT EXISTS encrypted_suite TEXT,
    ADD COLUMN IF NOT EXISTS encrypted_signing_key_id TEXT,
    ADD COLUMN IF NOT EXISTS signed_envelope_hash TEXT;

UPDATE {{tables.chat_messages}}
SET message_version = 1,
    content_mode = 'legacy_plaintext_v1'
WHERE content_mode IS NULL
   OR content_mode = '';

ALTER TABLE {{tables.chat_messages}}
    ADD CONSTRAINT chat_messages_content_mode_valid
    CHECK (content_mode IN ('legacy_plaintext_v1', 'encrypted_v2'));

ALTER TABLE {{tables.chat_messages}}
    ADD CONSTRAINT chat_messages_encrypted_v2_shape
    CHECK (
        (content_mode = 'legacy_plaintext_v1' AND message_version = 1 AND encrypted_envelope IS NULL)
        OR
        (
            content_mode = 'encrypted_v2'
            AND message_version = 2
            AND encrypted_envelope IS NOT NULL
            AND encrypted_ciphertext IS NOT NULL
            AND encrypted_key_wraps IS NOT NULL
            AND encrypted_ciphertext_hash LIKE 'sha256:%'
            AND encrypted_ciphertext_size IS NOT NULL
            AND encrypted_key_wraps_hash LIKE 'sha256:%'
            AND encrypted_inner_header_hash LIKE 'sha256:%'
            AND encrypted_suite IS NOT NULL
            AND encrypted_signing_key_id IS NOT NULL
            AND signed_envelope_hash LIKE 'sha256:%'
            AND body = ''
            AND signature IS NULL
            AND signed_payload IS NULL
        )
    );

CREATE INDEX IF NOT EXISTS idx_chat_messages_content_mode
    ON {{tables.chat_messages}} (content_mode, created_at);

CREATE INDEX IF NOT EXISTS idx_chat_messages_signed_envelope_hash
    ON {{tables.chat_messages}} (signed_envelope_hash)
    WHERE signed_envelope_hash IS NOT NULL;
