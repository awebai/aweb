-- Original-slot equivalence metadata. The ciphertext holds ONLY a random MAC
-- key, never a released value. Core owns this table so value destruction can
-- dispose rows even when runner modules have not been composed/migrated.
CREATE TABLE {{tables.run_redaction_pins}} (
    installation_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    dispatch_id UUID NOT NULL,
    secret_id TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    observation TEXT,
    credential_version BIGINT CHECK (credential_version > 0),
    digest BYTEA NOT NULL CHECK (octet_length(digest)=32),
    deadline TIMESTAMPTZ NOT NULL,
    key_id TEXT NOT NULL,
    wrapped_key BYTEA NOT NULL,
    nonce BYTEA NOT NULL CHECK (octet_length(nonce)=12),
    ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext)=48),
    PRIMARY KEY (dispatch_id,secret_id),
    CHECK ((observation IS NULL) = (credential_version IS NULL))
);
CREATE INDEX idx_run_redaction_secret ON {{tables.run_redaction_pins}}
    (installation_id,team_id,secret_id,version);
CREATE TRIGGER run_redaction_pins_immutable BEFORE UPDATE ON {{tables.run_redaction_pins}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
