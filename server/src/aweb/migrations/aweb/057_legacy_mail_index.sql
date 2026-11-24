-- Bound both lock acquisition and the entire ordinary CREATE INDEX statement.
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '5s';

CREATE INDEX idx_messages_legacy_created_id
    ON {{tables.messages}} (created_at DESC, message_id DESC)
    WHERE conversation_id IS NULL;
