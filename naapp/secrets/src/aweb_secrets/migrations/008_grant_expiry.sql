-- Optional deadlines preserve existing revoke-only grants. The owner-confirmed
-- renewal writer may change only expiry; grant terms and revocation stay fixed.
ALTER TABLE {{tables.grants}} ADD COLUMN expires_at TIMESTAMPTZ;

CREATE OR REPLACE FUNCTION {{tables.secrets_grant_only_revoked}}() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
       AND (to_jsonb(NEW) - 'revoked_at') = (to_jsonb(OLD) - 'revoked_at') THEN
        RETURN NEW;
    END IF;
    IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NULL
       AND NEW.expires_at IS NOT NULL
       AND (to_jsonb(NEW) - ARRAY['record', 'expires_at']) =
           (to_jsonb(OLD) - ARRAY['record', 'expires_at'])
       AND (NEW.record - 'expires_at') = (OLD.record - 'expires_at')
       AND NEW.record->>'expires_at' IS NOT NULL
       AND (NEW.record->>'expires_at')::timestamptz = NEW.expires_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'grant terms are immutable; only an unrevoked deadline can be renewed';
END;
$$;
