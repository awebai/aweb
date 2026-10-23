-- Local signer-loss accounting uses the ordinary sequence lock, but is never
-- a wire event. Existing rows remain ordinary events, including drained rows.
ALTER TABLE {{tables.outbox_events}}
    ADD COLUMN record_type TEXT NOT NULL DEFAULT 'event',
    ADD COLUMN reservation_scope TEXT,
    ADD COLUMN reservation_seq BIGINT,
    ADD COLUMN producer_origin TEXT,
    ADD COLUMN missing_reason TEXT,
    ADD COLUMN owed_binding_ids TEXT[],
    ALTER COLUMN payload_sha256 DROP NOT NULL;

ALTER TABLE {{tables.outbox_events}} ADD CONSTRAINT outbox_record_type CHECK (
    (record_type = 'event' AND payload_sha256 IS NOT NULL
        AND reservation_scope IS NULL AND reservation_seq IS NULL
        AND producer_origin IS NULL AND missing_reason IS NULL AND owed_binding_ids IS NULL)
    OR
    (record_type = 'missing_production' AND payload IS NULL AND payload_sha256 IS NULL
        AND signature IS NULL AND NOT critical AND materialized_at IS NULL AND drained_at IS NULL
        AND reservation_scope IS NOT NULL AND length(reservation_scope) > 0
        AND reservation_seq IS NOT NULL AND reservation_seq BETWEEN 1 AND 9007199254740991
        AND producer_origin IS NOT NULL AND length(producer_origin) > 0
        AND missing_reason IS NOT NULL AND missing_reason IN ('key_unconfigured', 'key_out_of_window')
        AND owed_binding_ids IS NOT NULL AND cardinality(owed_binding_ids) > 0
        AND array_position(owed_binding_ids, NULL) IS NULL)
);

-- A typed local record cannot acquire deliveries, even through direct SQL.
ALTER TABLE {{tables.outbox_events}} ADD CONSTRAINT outbox_event_record_identity
    UNIQUE (event_id, record_type);
ALTER TABLE {{tables.outbox_deliveries}}
    ADD COLUMN event_record_type TEXT NOT NULL DEFAULT 'event' CHECK (event_record_type = 'event'),
    ADD CONSTRAINT outbox_delivery_event_type FOREIGN KEY (event_id, event_record_type)
        REFERENCES {{tables.outbox_events}} (event_id, record_type);

CREATE UNIQUE INDEX idx_outbox_missing_sequence
    ON {{tables.outbox_events}} (reservation_scope, team_id, reservation_seq)
    WHERE record_type = 'missing_production';
CREATE INDEX idx_outbox_missing_accounting
    ON {{tables.outbox_events}} (team_id, occurred_at)
    WHERE record_type = 'missing_production';

-- Local losses remain durable, so keep them out of pending-event indexes too.
DROP INDEX {{schema}}.idx_outbox_events_unmaterialized;
CREATE INDEX idx_outbox_events_unmaterialized
    ON {{tables.outbox_events}} (position)
    WHERE record_type = 'event' AND materialized_at IS NULL;
DROP INDEX {{schema}}.idx_outbox_events_channel_unmaterialized;
CREATE INDEX idx_outbox_events_channel_unmaterialized
    ON {{tables.outbox_events}} (channel, position)
    WHERE record_type = 'event' AND materialized_at IS NULL;
DROP INDEX {{schema}}.idx_outbox_events_admission_unmaterialized;
CREATE INDEX idx_outbox_events_admission_unmaterialized
    ON {{tables.outbox_events}} (channel, team_id, kind, created_at, occurred_at)
    WHERE record_type = 'event' AND materialized_at IS NULL;
