-- The signed assignment is released once. Bind later reports to that send,
-- without adding a runner wire field or consulting a newer attempt counter.
ALTER TABLE {{tables.run_deliveries}} ADD COLUMN assignment_attempt INTEGER
    CHECK (assignment_attempt > 0);
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM {{tables.run_deliveries}} v
               JOIN {{tables.dispatches}} d USING(dispatch_id)
               WHERE v.assignment IS NOT NULL AND d.attempts<>1) THEN
        RAISE EXCEPTION 'legacy run assignment has no provable attempt';
    END IF;
END;
$$;
UPDATE {{tables.run_deliveries}} v SET assignment_attempt=1
    WHERE v.assignment IS NOT NULL;
ALTER TABLE {{tables.run_deliveries}} ADD CONSTRAINT run_delivery_attempt_binding
    CHECK ((assignment IS NULL)=(assignment_attempt IS NULL));
CREATE FUNCTION {{tables.secrets_run_attempt_once}}() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.assignment_attempt IS NOT NULL AND
       OLD.assignment_attempt IS DISTINCT FROM NEW.assignment_attempt THEN
        RAISE EXCEPTION 'run assignment attempt is write-once';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER run_delivery_attempt_once BEFORE UPDATE ON {{tables.run_deliveries}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_run_attempt_once}}();
