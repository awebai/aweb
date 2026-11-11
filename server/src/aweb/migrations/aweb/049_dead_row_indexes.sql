-- 049_dead_row_indexes.sql
-- Indexes on the columns that date a dead row, for the tables
-- aweb.gc.delete_dead_rows cleans. lifecycle_side_effect_outbox has its own
-- (idx_lifecycle_side_effect_outbox_delivered).

CREATE INDEX IF NOT EXISTS idx_app_events_created
    ON {{tables.app_events}} (created_at);

CREATE INDEX IF NOT EXISTS idx_control_signals_consumed
    ON {{tables.control_signals}} (consumed_at)
    WHERE consumed_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_federation_mutation_outbox_delivered
    ON {{tables.federation_mutation_outbox}} (delivered_at)
    WHERE delivered_at IS NOT NULL;
