-- Private complete request/proof retained atomically with the controller
-- signature. Never project this column into prepare or public receipt JSON.
ALTER TABLE {{tables.protected_signer_operations}} ADD COLUMN retained_effect JSONB;
