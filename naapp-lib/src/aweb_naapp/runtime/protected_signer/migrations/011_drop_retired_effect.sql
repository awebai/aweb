-- 004 is retired permanently. Preserve operations and passkey admission evidence.
ALTER TABLE {{tables.protected_signer_operations}} DROP COLUMN IF EXISTS retained_effect;
