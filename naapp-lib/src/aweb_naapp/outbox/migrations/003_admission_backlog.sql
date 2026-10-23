-- Admission reads only old unacknowledged deliveries and unmaterialized
-- events. Completed history must not turn every tool admission into a scan
-- of all delivered events. No parallel backlog tracker is maintained.
CREATE INDEX IF NOT EXISTS idx_outbox_deliveries_unacknowledged_target
    ON {{tables.outbox_deliveries}} (target_id, event_id)
    WHERE state NOT IN ('delivered', 'duplicate');

CREATE INDEX IF NOT EXISTS idx_outbox_events_admission_unmaterialized
    ON {{tables.outbox_events}} (channel, team_id, kind, created_at, occurred_at)
    WHERE materialized_at IS NULL;
