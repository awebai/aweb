-- Channels: each kind of delivery (app-event wakes, hook deliveries, ...) drains
-- separately from the others in one producer database.
ALTER TABLE {{tables.outbox_events}} ADD COLUMN IF NOT EXISTS channel TEXT NOT NULL DEFAULT 'default';

CREATE INDEX IF NOT EXISTS idx_outbox_events_channel_unmaterialized
    ON {{tables.outbox_events}} (channel, position) WHERE materialized_at IS NULL;

-- A target id belongs to one channel, because cancel, redrive and receipts are
-- keyed by target id alone.
CREATE TABLE IF NOT EXISTS {{tables.outbox_targets}} (
    target_id TEXT PRIMARY KEY,
    channel   TEXT NOT NULL
);
