-- An event whose targets cannot be resolved is tried again at next_resolve_at,
-- which backs off with each attempt, so it does not stay at the head of its
-- channel's queue ahead of other teams' events.
ALTER TABLE {{tables.outbox_events}}
    ADD COLUMN IF NOT EXISTS resolve_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE {{tables.outbox_events}}
    ADD COLUMN IF NOT EXISTS next_resolve_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_outbox_events_resolution_due
    ON {{tables.outbox_events}} (channel, next_resolve_at, position)
    WHERE materialized_at IS NULL;
