CREATE FUNCTION {{tables.credential_audit_refuse_change}}() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'credential audit history is immutable';
END;
$$;
CREATE TRIGGER credential_audit_events_immutable
    BEFORE UPDATE OR DELETE ON {{tables.credential_audit_events}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.credential_audit_refuse_change}}();
CREATE TRIGGER credential_audit_events_no_truncate
    BEFORE TRUNCATE ON {{tables.credential_audit_events}}
    FOR EACH STATEMENT EXECUTE FUNCTION {{tables.credential_audit_refuse_change}}();
