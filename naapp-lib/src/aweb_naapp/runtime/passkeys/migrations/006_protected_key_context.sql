-- Existing app proof bytes remain unchanged. Protected authorities have no
-- installation, so preserve their own closed context rather than invent one.
ALTER TABLE {{tables.passkey_proofs}} ALTER COLUMN app_id DROP NOT NULL;
ALTER TABLE {{tables.passkey_proofs}} ALTER COLUMN team_id DROP NOT NULL;
ALTER TABLE {{tables.passkey_proofs}} ALTER COLUMN installation_id DROP NOT NULL;
ALTER TABLE {{tables.passkey_proofs}} ADD COLUMN authority_context BYTEA;
ALTER TABLE {{tables.passkey_proofs}} ADD CONSTRAINT passkey_proof_context_shape CHECK (
    (authority_context IS NULL AND app_id IS NOT NULL AND team_id IS NOT NULL AND installation_id IS NOT NULL)
    OR (authority_context IS NOT NULL AND app_id IS NULL AND team_id IS NULL AND installation_id IS NULL)
);
