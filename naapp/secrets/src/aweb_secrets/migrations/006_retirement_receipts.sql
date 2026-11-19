-- Value-free destruction receipts, independent of credential-bearing sidecars.
CREATE TABLE {{tables.installation_retirement_events}} (
    app_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    destroyed JSONB NOT NULL,
    PRIMARY KEY (app_id, team_id, installation_id)
);
CREATE TRIGGER installation_retirement_events_immutable
    BEFORE UPDATE OR DELETE ON {{tables.installation_retirement_events}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
CREATE TRIGGER installation_retirement_events_no_truncate
    BEFORE TRUNCATE ON {{tables.installation_retirement_events}}
    FOR EACH STATEMENT EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
