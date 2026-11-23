-- Installed offline as secrets_erasure_owner; never run by service startup.
CREATE TABLE secrets_erasure.store (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    identity uuid NOT NULL,
    schema_digest text NOT NULL CHECK (schema_digest ~ '^sha256:[0-9a-f]{64}$'),
    content_schema name NOT NULL,
    application_role name NOT NULL,
    max_backup_age_seconds bigint NOT NULL CHECK (max_backup_age_seconds > 0)
);
CREATE TABLE secrets_erasure.allocations (
    installation_id text NOT NULL,
    team_id text NOT NULL,
    secret_id text NOT NULL,
    last_version bigint NOT NULL CHECK (last_version >= 0),
    PRIMARY KEY (installation_id,team_id,secret_id)
);
CREATE TABLE secrets_erasure.erasures (
    carrier text NOT NULL CHECK (carrier IN ('sealed','reference','pin')),
    installation_id text NOT NULL,
    team_id text NOT NULL,
    secret_id text NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    dispatch_id text NOT NULL DEFAULT '',
    operation_ref text NOT NULL CHECK (length(operation_ref) <= 64),
    destroyed_at timestamptz NOT NULL,
    recoverable_until timestamptz NOT NULL,
    PRIMARY KEY (carrier,installation_id,team_id,secret_id,version,dispatch_id),
    CHECK (recoverable_until > destroyed_at)
);
CREATE TABLE {{tables.erasure_store_identity}} (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    identity uuid NOT NULL
);

-- One trigger owner covers ordinary deletion, retirement and pin disposal.
-- The runtime role cannot execute this function directly or alter its tables.
CREATE FUNCTION secrets_erasure.record_erasure() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    age_seconds bigint;
    carrier_name text;
    dispatch_name text := '';
    destroyed timestamptz := clock_timestamp();
BEGIN
    SELECT max_backup_age_seconds INTO STRICT age_seconds
      FROM secrets_erasure.store WHERE content_schema=TG_TABLE_SCHEMA;
    IF TG_TABLE_NAME='sealed_versions' THEN
        carrier_name := 'sealed';
    ELSIF TG_TABLE_NAME='onepassword_versions' THEN
        carrier_name := 'reference';
        IF TG_OP='UPDATE' THEN
            IF NEW.binding IS DISTINCT FROM OLD.binding AND NEW.binding IS NOT NULL THEN
                RAISE SQLSTATE 'SE003' USING MESSAGE='Secrets reference bindings are immutable except for destruction';
            END IF;
            IF NEW.binding IS NOT NULL THEN RETURN NEW; END IF;
        END IF;
    ELSIF TG_TABLE_NAME='run_redaction_pins' THEN
        carrier_name := 'pin';
        dispatch_name := OLD.dispatch_id::text;
    ELSE
        RAISE SQLSTATE 'SE001' USING MESSAGE='Secrets erasure trigger has an unsupported carrier';
    END IF;
    INSERT INTO secrets_erasure.erasures
        (carrier,installation_id,team_id,secret_id,version,dispatch_id,
         operation_ref,destroyed_at,recoverable_until)
    VALUES (carrier_name,OLD.installation_id,OLD.team_id,OLD.secret_id,OLD.version,
            dispatch_name,TG_TABLE_NAME||':'||TG_OP,destroyed,
            destroyed + age_seconds * interval '1 second')
    ON CONFLICT DO NOTHING;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
EXCEPTION
    WHEN SQLSTATE 'SE003' THEN RAISE;
    WHEN OTHERS THEN
        RAISE SQLSTATE 'SE001' USING MESSAGE='Secrets erasure store unavailable; keep Secrets stopped';
END;
$$;

CREATE FUNCTION secrets_erasure.record_allocation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    floor bigint;
BEGIN
    PERFORM 1 FROM secrets_erasure.store WHERE content_schema=TG_TABLE_SCHEMA;
    IF NOT FOUND THEN
        RAISE SQLSTATE 'SE001' USING MESSAGE='Secrets erasure identity is unavailable';
    END IF;
    SELECT last_version INTO floor FROM secrets_erasure.allocations
      WHERE installation_id=NEW.installation_id AND team_id=NEW.team_id
        AND secret_id=NEW.secret_id FOR UPDATE;
    IF floor IS NOT NULL AND NEW.last_version<floor THEN
        RAISE SQLSTATE 'SE002' USING MESSAGE='Secrets allocation is older than retained history';
    END IF;
    IF floor IS NOT NULL AND NEW.last_version>0 AND NEW.last_version<=floor THEN
        IF TG_OP='INSERT' THEN
            RAISE SQLSTATE 'SE002' USING MESSAGE='Secrets allocation would reuse retained history';
        ELSIF NEW.last_version<>OLD.last_version THEN
            RAISE SQLSTATE 'SE002' USING MESSAGE='Secrets allocation would reuse retained history';
        END IF;
    END IF;
    INSERT INTO secrets_erasure.allocations (installation_id,team_id,secret_id,last_version)
      VALUES (NEW.installation_id,NEW.team_id,NEW.secret_id,NEW.last_version)
      ON CONFLICT (installation_id,team_id,secret_id) DO UPDATE
      SET last_version=greatest(secrets_erasure.allocations.last_version,EXCLUDED.last_version);
    RETURN NEW;
EXCEPTION
    WHEN SQLSTATE 'SE002' THEN RAISE;
    WHEN OTHERS THEN
        RAISE SQLSTATE 'SE001' USING MESSAGE='Secrets erasure store unavailable; keep Secrets stopped';
END;
$$;

CREATE FUNCTION secrets_erasure.refuse_resurrection() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    carrier_name text;
    dispatch_name text := '';
BEGIN
    PERFORM 1 FROM secrets_erasure.store WHERE content_schema=TG_TABLE_SCHEMA;
    IF NOT FOUND THEN
        RAISE SQLSTATE 'SE001' USING MESSAGE='Secrets erasure identity is unavailable';
    END IF;
    carrier_name := CASE TG_TABLE_NAME
        WHEN 'sealed_versions' THEN 'sealed'
        WHEN 'onepassword_versions' THEN 'reference'
        WHEN 'run_redaction_pins' THEN 'pin' END;
    IF carrier_name IS NULL THEN
        RAISE SQLSTATE 'SE001' USING MESSAGE='Secrets erasure carrier is unsupported';
    END IF;
    -- Resolve carrier-specific record fields only in their own branches.
    IF carrier_name='pin' THEN
        dispatch_name := NEW.dispatch_id::text;
    ELSIF carrier_name='reference' THEN
        IF NEW.binding IS NULL THEN
            RETURN NEW;
        END IF;
    END IF;
    IF EXISTS(SELECT 1 FROM secrets_erasure.erasures
       WHERE carrier=carrier_name AND installation_id=NEW.installation_id
         AND team_id=NEW.team_id AND secret_id=NEW.secret_id AND version=NEW.version
         AND dispatch_id=dispatch_name) THEN
        RAISE SQLSTATE 'SE003' USING MESSAGE='Secrets erasure prohibits resurrecting destroyed material';
    END IF;
    RETURN NEW;
EXCEPTION
    WHEN SQLSTATE 'SE003' THEN RAISE;
    WHEN OTHERS THEN
        RAISE SQLSTATE 'SE001' USING MESSAGE='Secrets erasure store unavailable; keep Secrets stopped';
END;
$$;

CREATE TRIGGER secrets_record_allocation
    AFTER INSERT OR UPDATE OF last_version ON {{tables.custody_secrets}}
    FOR EACH ROW EXECUTE FUNCTION secrets_erasure.record_allocation();
CREATE TRIGGER secrets_record_erasure
    AFTER DELETE ON {{tables.sealed_versions}}
    FOR EACH ROW EXECUTE FUNCTION secrets_erasure.record_erasure();
CREATE TRIGGER secrets_record_erasure
    AFTER UPDATE OF binding,destroyed_at OR DELETE ON {{tables.onepassword_versions}}
    FOR EACH ROW EXECUTE FUNCTION secrets_erasure.record_erasure();
CREATE TRIGGER secrets_record_erasure
    AFTER DELETE ON {{tables.run_redaction_pins}}
    FOR EACH ROW EXECUTE FUNCTION secrets_erasure.record_erasure();
CREATE TRIGGER secrets_refuse_resurrection
    BEFORE INSERT ON {{tables.sealed_versions}}
    FOR EACH ROW EXECUTE FUNCTION secrets_erasure.refuse_resurrection();
CREATE TRIGGER secrets_refuse_resurrection
    BEFORE INSERT ON {{tables.onepassword_versions}}
    FOR EACH ROW EXECUTE FUNCTION secrets_erasure.refuse_resurrection();
CREATE TRIGGER secrets_refuse_resurrection
    BEFORE INSERT ON {{tables.run_redaction_pins}}
    FOR EACH ROW EXECUTE FUNCTION secrets_erasure.refuse_resurrection();

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA secrets_erasure FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA secrets_erasure FROM PUBLIC;
