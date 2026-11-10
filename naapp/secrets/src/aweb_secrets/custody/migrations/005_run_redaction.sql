-- Secret-bearing original renderer inputs, sealed by native custody. There is
-- no FK to run stores: custody migrates before dispatch modules. RunDispatch
-- publishes this row atomically with the original assignment and S3 deadline.
CREATE TABLE {{tables.run_redaction_contexts}} (
    installation_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    dispatch_id UUID NOT NULL,
    deadline TIMESTAMPTZ NOT NULL,
    key_id TEXT NOT NULL,
    wrapped_key BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    ciphertext BYTEA NOT NULL,
    PRIMARY KEY (installation_id, team_id, dispatch_id)
);
CREATE FUNCTION {{tables.run_redaction_refuse_update}}() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'original run redaction context is immutable';
END;
$$;
CREATE TRIGGER run_redaction_contexts_immutable BEFORE UPDATE ON {{tables.run_redaction_contexts}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.run_redaction_refuse_update}}();
