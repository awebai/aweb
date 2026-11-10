-- Both arms of the ended-row predicates support bounded SKIP LOCKED cleanup.
-- Handoffs already have their expires_at index from migration 003.
CREATE INDEX console_sessions_expiry ON {{tables.console_sessions}} (expires_at);
CREATE INDEX console_sessions_closed ON {{tables.console_sessions}} (closed_at)
    WHERE closed_at IS NOT NULL;
CREATE INDEX console_handoffs_released ON {{tables.console_handoffs}} (released_at)
    WHERE released_at IS NOT NULL;
