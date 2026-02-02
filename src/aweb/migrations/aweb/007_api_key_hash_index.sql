-- aweb API key verification uses full-key SHA-256 lookup (no prefix oracle).
-- Keep key_prefix as a non-authoritative identifier only.

DROP INDEX IF EXISTS idx_api_keys_prefix_unique;

CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash
ON {{tables.api_keys}} (key_hash);

