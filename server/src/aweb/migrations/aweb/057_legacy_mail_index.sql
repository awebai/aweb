-- Bound acquisition of the write-conflicting lock for this ordinary build.
SET LOCAL lock_timeout = '2s';

CREATE INDEX idx_messages_legacy_created_id
    ON {{tables.messages}} (created_at DESC, message_id DESC)
    WHERE conversation_id IS NULL;
