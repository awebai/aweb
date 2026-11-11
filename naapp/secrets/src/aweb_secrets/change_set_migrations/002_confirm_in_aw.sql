-- A server-recorded delivery choice; never part of a caller's change/1 bytes.
ALTER TABLE {{tables.change_sets}}
    ADD COLUMN confirm_in_aw BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CHECK (NOT confirm_in_aw OR via = 'console');

CREATE FUNCTION {{tables.change_set_confirm_mark_immutable}}() RETURNS trigger AS $$
BEGIN
    IF NEW.confirm_in_aw IS DISTINCT FROM OLD.confirm_in_aw THEN
        RAISE EXCEPTION 'a change set confirmation mark is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER change_set_confirm_mark_immutable
    BEFORE UPDATE ON {{tables.change_sets}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.change_set_confirm_mark_immutable}}();
