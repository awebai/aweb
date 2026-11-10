-- Independent of the generic state machine: broker contexts impose the
-- app's stricter retention contract. A direct fact insert cannot bypass it.
CREATE FUNCTION {{tables.secrets_broker_outcome_bound}}() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM {{tables.use_contexts}} c
               WHERE c.dispatch_id=NEW.dispatch_id AND c.tool='request')
       AND NEW.result IS DISTINCT FROM {{tables.secrets_broker_metadata}}(NEW.result) THEN
        RAISE EXCEPTION 'broker outcome requires value-free metadata';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER secrets_broker_outcome_bound BEFORE INSERT ON {{tables.dispatch_observations}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_broker_outcome_bound}}();
CREATE TRIGGER broker_outcome_purges_immutable BEFORE UPDATE OR DELETE
    ON {{tables.broker_outcome_purges}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
