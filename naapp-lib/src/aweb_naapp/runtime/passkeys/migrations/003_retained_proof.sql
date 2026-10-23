-- Retain original ceremony context, never reconstruct it after verification.
ALTER TABLE {{tables.passkey_challenges}} ADD COLUMN proof_context BYTEA;
ALTER TABLE {{tables.passkey_challenges}} ADD COLUMN challenge_preimage BYTEA;
ALTER TABLE {{tables.passkey_challenges}} ADD COLUMN covered_request BYTEA;

-- Restricted historical assertion, with credential-bearing request sidecar.
CREATE TABLE {{tables.passkey_proofs}} (
    evidence_ref TEXT PRIMARY KEY REFERENCES {{tables.passkey_assertions}}(evidence_ref) ON DELETE CASCADE,
    app_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    generation BIGINT NOT NULL,
    record BYTEA NOT NULL,
    commitment TEXT NOT NULL
);
CREATE INDEX idx_passkey_proofs_installation ON {{tables.passkey_proofs}}
    (app_id,team_id,installation_id);
CREATE FUNCTION {{tables.passkey_proof_refuse_update}}() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'retained passkey proof is immutable'; END; $$;
CREATE TRIGGER passkey_proof_immutable BEFORE UPDATE ON {{tables.passkey_proofs}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.passkey_proof_refuse_update}}();
