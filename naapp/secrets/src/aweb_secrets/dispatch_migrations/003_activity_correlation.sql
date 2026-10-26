-- Original correlation belongs to the immutable operational record. It never
-- includes request/response values, concrete paths, commitments or link tokens.
ALTER TABLE {{tables.broker_audit_contexts}}
    ADD COLUMN correlation JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE {{tables.broker_use_events}}
    ADD COLUMN correlation JSONB NOT NULL DEFAULT '{}'::jsonb;
CREATE INDEX broker_use_events_page
    ON {{tables.broker_use_events}} (installation_id, team_id, occurred_at DESC, event_id DESC);
