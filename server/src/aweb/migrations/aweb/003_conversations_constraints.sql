-- 003_conversations_constraints.sql
-- Tighten first-class conversation invariants without editing prior migrations.

ALTER TABLE {{tables.conversations}}
    ALTER COLUMN created_by_did DROP DEFAULT;

ALTER TABLE {{tables.conversation_participants}}
    ALTER COLUMN alias DROP DEFAULT;

ALTER TABLE {{tables.conversations}}
    ADD CONSTRAINT conversations_created_by_did_not_blank
    CHECK (BTRIM(created_by_did) <> '');

ALTER TABLE {{tables.conversation_participants}}
    ADD CONSTRAINT conversation_participants_alias_not_blank
    CHECK (BTRIM(alias) <> '');

ALTER TABLE {{tables.conversation_participants}}
    ADD CONSTRAINT conversation_participants_reachable
    CHECK (
        NULLIF(BTRIM(COALESCE(address, '')), '') IS NOT NULL
        OR NULLIF(BTRIM(COALESCE(transport_hint, '')), '') IS NOT NULL
    );

CREATE OR REPLACE FUNCTION aweb.set_conversation_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.updated_at IS NOT DISTINCT FROM OLD.updated_at THEN
        NEW.updated_at = NOW();
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_conversations_updated_at
    BEFORE UPDATE ON {{tables.conversations}}
    FOR EACH ROW
    EXECUTE FUNCTION aweb.set_conversation_updated_at();
