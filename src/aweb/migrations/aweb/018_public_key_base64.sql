-- Migrate public_key column from hex encoding to URL-safe base64 no-padding.
-- Hex: 64 chars for 32 bytes. Base64: 43 chars for 32 bytes.
-- Only converts rows where public_key looks like hex (64 hex chars).

UPDATE {{tables.agents}}
SET public_key = TRANSLATE(
    ENCODE(DECODE(public_key, 'hex'), 'base64'),
    '+/=', '-_ '
)
WHERE public_key IS NOT NULL
  AND LENGTH(public_key) = 64
  AND public_key ~ '^[0-9a-fA-F]+$';

-- Trim any trailing spaces left from padding removal
UPDATE {{tables.agents}}
SET public_key = RTRIM(public_key)
WHERE public_key IS NOT NULL;
