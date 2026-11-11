-- The prune of drained events past their retention reads them oldest drained
-- first, without reading events that are still owed.
CREATE INDEX IF NOT EXISTS idx_outbox_events_drained
    ON {{tables.outbox_events}} (drained_at) WHERE drained_at IS NOT NULL;
