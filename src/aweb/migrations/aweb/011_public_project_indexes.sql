-- Indexes for project-wide message and chat session queries.
--
-- The public project endpoints scan all messages/sessions by project_id
-- ordered by created_at DESC. The existing idx_messages_inbox includes
-- to_agent_id in the middle, so it cannot serve project-wide scans.
-- chat_sessions has no project_id + created_at index at all.

CREATE INDEX IF NOT EXISTS idx_messages_project_created
ON {{tables.messages}} (project_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_chat_sessions_project_created
ON {{tables.chat_sessions}} (project_id, created_at DESC);
