-- The shared durable outbox: one row per event, written in the producer's own
-- transaction, and one row per (event, target) delivery, materialized at drain.

CREATE TABLE IF NOT EXISTS {{tables.outbox_events}} (
    event_id        UUID PRIMARY KEY,
    position        BIGSERIAL NOT NULL UNIQUE,
    team_id         TEXT NOT NULL,
    kind            TEXT NOT NULL,
    occurred_at     TIMESTAMPTZ NOT NULL,
    -- Exact bytes; NULL once every delivery has ended (the tombstone keeps the digest).
    payload         BYTEA,
    payload_sha256  TEXT NOT NULL,
    signature       TEXT,
    critical        BOOLEAN NOT NULL DEFAULT FALSE,
    producer        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    materialized_at TIMESTAMPTZ,
    drained_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_outbox_events_unmaterialized
    ON {{tables.outbox_events}} (position) WHERE materialized_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_outbox_events_undrained
    ON {{tables.outbox_events}} (position) WHERE materialized_at IS NOT NULL AND drained_at IS NULL;

CREATE TABLE IF NOT EXISTS {{tables.outbox_deliveries}} (
    event_id         UUID NOT NULL REFERENCES {{tables.outbox_events}}(event_id),
    target_id        TEXT NOT NULL,
    target_meta      JSONB NOT NULL DEFAULT '{}'::jsonb,
    state            TEXT NOT NULL DEFAULT 'pending' CHECK (
        state IN ('pending', 'delivered', 'duplicate', 'conflict', 'rejected', 'stalled', 'cancelled')
    ),
    attempts         INTEGER NOT NULL DEFAULT 0,
    next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error_class TEXT,
    cancel_reason    TEXT,
    receipt          BYTEA,
    -- When the target acknowledged the delivery: its arrival order at the target.
    acked_at         TIMESTAMPTZ,
    -- When an operator accepted a dead letter as lost, releasing its bytes.
    acknowledged_at  TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (event_id, target_id)
);

CREATE INDEX IF NOT EXISTS idx_outbox_deliveries_due
    ON {{tables.outbox_deliveries}} (next_attempt_at) WHERE state IN ('pending', 'stalled');

CREATE INDEX IF NOT EXISTS idx_outbox_deliveries_target
    ON {{tables.outbox_deliveries}} (target_id, state);

CREATE TABLE IF NOT EXISTS {{tables.outbox_sequences}} (
    scope    TEXT NOT NULL,
    team_id  TEXT NOT NULL,
    last_seq BIGINT NOT NULL,
    PRIMARY KEY (scope, team_id)
);
