-- 005_messages_encrypted_v2_shape_legacy_fields.sql
-- Keep mail/message encrypted_v2 rows aligned with chat encrypted_v2 rows:
-- legacy plaintext signature artifacts are not valid on encrypted content.

ALTER TABLE {{tables.messages}}
    DROP CONSTRAINT IF EXISTS messages_encrypted_v2_shape;

ALTER TABLE {{tables.messages}}
    ADD CONSTRAINT messages_encrypted_v2_shape
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
            AND subject = ''
            AND body = ''
            AND signature IS NULL
            AND signed_payload IS NULL
        )
    );
