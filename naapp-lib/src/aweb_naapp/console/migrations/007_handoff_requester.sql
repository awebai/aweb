-- The agent that prepared a session start for its holder (handoff-wire 1a):
-- {id, address, key_fingerprint}, shown on the page and kept for audit only.
-- NULL when the holder signed the start itself.
ALTER TABLE {{tables.console_handoffs}} ADD COLUMN requester JSONB;
