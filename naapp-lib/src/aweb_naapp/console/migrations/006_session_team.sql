-- The team authenticated at a handoff start remains the session's routing context.
-- Older key-bound sessions have no context and require a fresh sign-in.
ALTER TABLE {{tables.console_sessions}} ADD COLUMN team_id TEXT;
