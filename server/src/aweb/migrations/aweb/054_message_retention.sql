-- Antares 3a98a138 / coordinator 6162d1db-1979-4fa3-83dc-afd8df4b7907.
-- Storage only: retention remains OFF unless its operator separately enables it.
-- Legacy absent coverage is UNKNOWN; no roster-based ownership backfill.
CREATE TABLE {{tables.message_retention_coverage}} (
    storage_kind TEXT NOT NULL CHECK (storage_kind IN ('mail','chat')),
    message_id UUID NOT NULL,
    party_coverage_complete BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (storage_kind,message_id)
);
CREATE TABLE {{tables.message_retention_parties}} (
    storage_kind TEXT NOT NULL,
    message_id UUID NOT NULL,
    party_did TEXT NOT NULL,
    classification TEXT NOT NULL DEFAULT 'unknown' CHECK (classification IN ('unknown','known')),
    PRIMARY KEY (storage_kind,message_id,party_did),
    FOREIGN KEY (storage_kind,message_id)
        REFERENCES {{tables.message_retention_coverage}} (storage_kind,message_id) ON DELETE CASCADE
);
CREATE TABLE {{tables.message_retention_interests}} (
    storage_kind TEXT NOT NULL,
    message_id UUID NOT NULL,
    party_did TEXT NOT NULL,
    owner_team_id TEXT NOT NULL REFERENCES {{tables.teams}} (team_id),
    expired_at TIMESTAMPTZ,
    PRIMARY KEY (storage_kind,message_id,party_did,owner_team_id),
    FOREIGN KEY (storage_kind,message_id,party_did)
        REFERENCES {{tables.message_retention_parties}} (storage_kind,message_id,party_did) ON DELETE CASCADE
);
CREATE INDEX message_retention_interests_team ON {{tables.message_retention_interests}} (owner_team_id,storage_kind,message_id);
CREATE TABLE {{tables.message_retention_previews}} (
    preview_id UUID PRIMARY KEY,
    scope_team_id TEXT NOT NULL REFERENCES {{tables.teams}} (team_id),
    cutoff TIMESTAMPTZ NOT NULL,
    token_fingerprint TEXT NOT NULL,
    snapshot JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    consumed_at TIMESTAMPTZ
);

-- One native source for current message/history parties. Captured parties are
-- retained separately when memberships later disappear or are succeeded.
CREATE FUNCTION aweb.retention_current_parties(kind TEXT, id UUID)
RETURNS TABLE (party_did TEXT) LANGUAGE sql VOLATILE AS $$
    SELECT NULLIF(m.from_did,'') FROM {{tables.messages}} m WHERE kind='mail' AND m.message_id=id
    UNION SELECT NULLIF(m.to_did,'') FROM {{tables.messages}} m WHERE kind='mail' AND m.message_id=id
    UNION SELECT p.did FROM {{tables.conversation_participants}} p
      JOIN {{tables.messages}} m ON m.conversation_id=p.conversation_id WHERE kind='mail' AND m.message_id=id
    UNION SELECT NULLIF(m.from_did,'') FROM {{tables.chat_messages}} m WHERE kind='chat' AND m.message_id=id
    UNION SELECT p.did FROM {{tables.chat_participants}} p
      JOIN {{tables.chat_messages}} m USING (session_id) WHERE kind='chat' AND m.message_id=id
    UNION SELECT p.did FROM {{tables.conversation_participants}} p
      JOIN {{tables.chat_messages}} m ON m.session_id=p.conversation_id WHERE kind='chat' AND m.message_id=id
$$;

CREATE FUNCTION aweb.capture_new_message_retention() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO {{tables.message_retention_coverage}} (storage_kind,message_id,party_coverage_complete)
    SELECT TG_ARGV[0],NEW.message_id,
           EXISTS (SELECT 1 FROM aweb.retention_current_parties(TG_ARGV[0],NEW.message_id))
           AND NOT EXISTS (SELECT 1 FROM aweb.retention_current_parties(TG_ARGV[0],NEW.message_id) WHERE party_did IS NULL)
    ON CONFLICT DO NOTHING;
    INSERT INTO {{tables.message_retention_parties}} (storage_kind,message_id,party_did)
    SELECT TG_ARGV[0],NEW.message_id,party_did FROM aweb.retention_current_parties(TG_ARGV[0],NEW.message_id)
    WHERE party_did IS NOT NULL ON CONFLICT DO NOTHING;
    RETURN NEW;
END $$;
CREATE TRIGGER capture_mail_retention AFTER INSERT ON {{tables.messages}}
    FOR EACH ROW EXECUTE FUNCTION aweb.capture_new_message_retention('mail');
CREATE TRIGGER capture_chat_retention AFTER INSERT ON {{tables.chat_messages}}
    FOR EACH ROW EXECUTE FUNCTION aweb.capture_new_message_retention('chat');

-- New readable history is an interest before the participant write commits.
-- This never classifies an owner or alters/removes a participant identity.
CREATE FUNCTION aweb.capture_retention_history_party() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE cid UUID; ref RECORD;
BEGIN
    IF TG_TABLE_NAME='chat_participants' THEN cid:=NEW.session_id; ELSE cid:=NEW.conversation_id; END IF;
    FOR ref IN
        SELECT 'mail'::text AS kind,message_id FROM {{tables.messages}} WHERE conversation_id=cid
        UNION ALL SELECT 'chat',message_id FROM {{tables.chat_messages}} WHERE session_id=cid
    LOOP
        INSERT INTO {{tables.message_retention_coverage}} (storage_kind,message_id)
            VALUES (ref.kind,ref.message_id) ON CONFLICT DO NOTHING;
        IF NEW.did IS NULL THEN
            UPDATE {{tables.message_retention_coverage}} SET party_coverage_complete=FALSE
                WHERE storage_kind=ref.kind AND message_id=ref.message_id;
        ELSE
            INSERT INTO {{tables.message_retention_parties}} (storage_kind,message_id,party_did)
                VALUES (ref.kind,ref.message_id,NEW.did) ON CONFLICT DO NOTHING;
        END IF;
    END LOOP;
    RETURN NEW;
END $$;
CREATE TRIGGER capture_mail_history_retention AFTER INSERT OR UPDATE OF did ON {{tables.conversation_participants}}
    FOR EACH ROW EXECUTE FUNCTION aweb.capture_retention_history_party();
CREATE TRIGGER capture_chat_history_retention AFTER INSERT OR UPDATE OF did ON {{tables.chat_participants}}
    FOR EACH ROW EXECUTE FUNCTION aweb.capture_retention_history_party();
