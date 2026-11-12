-- UPDATE guards alone do not preserve history against DELETE or TRUNCATE.
CREATE TRIGGER use_contexts_no_delete BEFORE DELETE ON {{tables.use_contexts}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
CREATE TRIGGER use_contexts_no_truncate BEFORE TRUNCATE ON {{tables.use_contexts}}
    FOR EACH STATEMENT EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
CREATE TRIGGER broker_audit_contexts_no_delete BEFORE DELETE ON {{tables.broker_audit_contexts}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
CREATE TRIGGER broker_audit_contexts_no_truncate BEFORE TRUNCATE ON {{tables.broker_audit_contexts}}
    FOR EACH STATEMENT EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
CREATE TRIGGER broker_use_events_no_delete BEFORE DELETE ON {{tables.broker_use_events}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
CREATE TRIGGER broker_use_events_no_truncate BEFORE TRUNCATE ON {{tables.broker_use_events}}
    FOR EACH STATEMENT EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
