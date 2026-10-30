-- pgdbm:no-transaction
DROP INDEX CONCURRENTLY IF EXISTS {{schema}}.idx_chat_messages_history_page;
CREATE INDEX CONCURRENTLY idx_chat_messages_history_page
    ON {{tables.chat_messages}} (session_id, created_at, message_id);
