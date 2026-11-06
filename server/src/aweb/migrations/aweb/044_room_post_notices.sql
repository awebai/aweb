-- Logical notice uniqueness; delivery uses the existing at-least-once stream.
CREATE TABLE {{tables.room_post_notices}} (
    message_id UUID NOT NULL REFERENCES {{tables.room_messages}} (message_id) ON DELETE CASCADE,
    recipient_agent_id UUID NOT NULL REFERENCES {{tables.agents}} (agent_id) ON DELETE CASCADE,
    PRIMARY KEY (message_id, recipient_agent_id)
);
CREATE INDEX room_post_notices_recipient ON {{tables.room_post_notices}} (recipient_agent_id);

-- Storage cleanup only. Every delivery/read still verifies current membership.
CREATE FUNCTION aweb.cleanup_removed_member_room_notices()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status <> 'active' OR NEW.deleted_at IS NOT NULL OR NEW.team_id <> OLD.team_id THEN
        DELETE FROM {{tables.room_post_notices}} WHERE recipient_agent_id = NEW.agent_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER cleanup_removed_member_room_notices
    AFTER UPDATE OF status, deleted_at, team_id ON {{tables.agents}}
    FOR EACH ROW EXECUTE FUNCTION aweb.cleanup_removed_member_room_notices();
