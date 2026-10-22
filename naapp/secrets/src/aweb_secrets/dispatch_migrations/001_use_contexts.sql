-- Admission's immutable audit context is inserted before S3's received event.
-- The deferred dispatch FK permits that ordering inside one committing tx.
CREATE UNIQUE INDEX IF NOT EXISTS idx_intents_context_binding
    ON {{tables.intents}} (intent_id, installation_id, team_id, install_generation);

CREATE TABLE IF NOT EXISTS {{tables.use_contexts}} (
    intent_id TEXT PRIMARY KEY,
    dispatch_id UUID NOT NULL UNIQUE,
    app_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    install_generation BIGINT NOT NULL CHECK (install_generation >= 1),
    tool TEXT NOT NULL,
    request_mac TEXT NOT NULL CHECK (request_mac ~ '^[0-9a-f]{64}$'),
    params_mac TEXT CHECK (params_mac ~ '^[0-9a-f]{64}$'),
    dispatch_started_at TIMESTAMPTZ,
    FOREIGN KEY (intent_id, installation_id, team_id, install_generation)
        REFERENCES {{tables.intents}} (intent_id, installation_id, team_id, install_generation),
    FOREIGN KEY (dispatch_id) REFERENCES {{tables.dispatches}} (dispatch_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE OR REPLACE FUNCTION {{tables.secrets_use_context_immutable}}() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (to_jsonb(NEW) - 'dispatch_started_at') <> (to_jsonb(OLD) - 'dispatch_started_at')
       OR (OLD.dispatch_started_at IS NOT NULL AND
           NEW.dispatch_started_at IS DISTINCT FROM OLD.dispatch_started_at)
    THEN
        RAISE EXCEPTION 'use audit context and first dispatch start are immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE OR REPLACE TRIGGER use_contexts_immutable BEFORE UPDATE ON {{tables.use_contexts}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_use_context_immutable}}();
