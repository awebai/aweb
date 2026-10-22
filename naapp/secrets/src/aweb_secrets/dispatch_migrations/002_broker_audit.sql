-- Frozen, value-free event context. It is not dispatch or approval authority.
CREATE TABLE IF NOT EXISTS {{tables.broker_audit_contexts}} (
    dispatch_id UUID PRIMARY KEY REFERENCES {{tables.use_contexts}} (dispatch_id),
    actor JSONB NOT NULL,
    payload JSONB NOT NULL,
    signed_trace_id TEXT CHECK (signed_trace_id ~ '^[0-9a-f]{32}$' AND signed_trace_id <> repeat('0',32))
);
CREATE OR REPLACE TRIGGER broker_audit_contexts_immutable
    BEFORE UPDATE ON {{tables.broker_audit_contexts}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();

-- Console activity survives normal outbox delivery/retention cleanup. Only
-- catalog-validated value-free fields are copied here, in the same transaction.
CREATE TABLE IF NOT EXISTS {{tables.broker_use_events}} (
    event_id UUID PRIMARY KEY,
    installation_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    install_generation BIGINT NOT NULL CHECK (install_generation >= 1),
    dispatch_id UUID REFERENCES {{tables.broker_audit_contexts}} (dispatch_id),
    occurred_at TIMESTAMPTZ NOT NULL,
    action TEXT NOT NULL,
    actor JSONB NOT NULL,
    payload JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS broker_use_events_dispatch
    ON {{tables.broker_use_events}} (dispatch_id, occurred_at);
CREATE INDEX IF NOT EXISTS broker_use_events_scope
    ON {{tables.broker_use_events}} (installation_id, team_id, occurred_at);
CREATE OR REPLACE TRIGGER broker_use_events_immutable
    BEFORE UPDATE ON {{tables.broker_use_events}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
