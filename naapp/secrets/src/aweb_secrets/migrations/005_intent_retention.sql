-- Admission history survives credential destruction and installation retirement.
CREATE TRIGGER intents_no_delete BEFORE DELETE ON {{tables.intents}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
CREATE TRIGGER intents_no_truncate BEFORE TRUNCATE ON {{tables.intents}}
    FOR EACH STATEMENT EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
