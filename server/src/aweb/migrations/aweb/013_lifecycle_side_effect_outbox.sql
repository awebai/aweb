-- Durable lifecycle side effects captured in the same transaction as cleanup.
-- Redis publication/cleanup is replayed only after this row becomes visible,
-- so nested savepoint release cannot expose an uncommitted lifecycle change.
CREATE TABLE IF NOT EXISTS {{tables.lifecycle_side_effect_outbox}} (
    outbox_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id    UUID NOT NULL,
    effect_order    INTEGER NOT NULL,
    team_id         TEXT NOT NULL,
    effect_kind     TEXT NOT NULL CHECK (
        effect_kind IN (
            'workspace_task_unclaimed',
            'team_task_unclaimed',
            'chat_waiting_clear',
            'presence_clear'
        )
    ),
    payload_json    JSONB NOT NULL,
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at    TIMESTAMPTZ,

    UNIQUE (operation_id, effect_order)
);

CREATE INDEX IF NOT EXISTS idx_lifecycle_side_effect_outbox_pending
    ON {{tables.lifecycle_side_effect_outbox}} (
        next_attempt_at, created_at, operation_id, effect_order
    )
    WHERE delivered_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_lifecycle_side_effect_outbox_delivered
    ON {{tables.lifecycle_side_effect_outbox}} (delivered_at)
    WHERE delivered_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_lifecycle_side_effect_outbox_team
    ON {{tables.lifecycle_side_effect_outbox}} (team_id);
