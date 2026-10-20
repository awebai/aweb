-- External-effect dispatches: one row per intent, moved through its states
-- in the caller's transactions. A row in 'dispatching' carries the time after
-- which the sweeper may declare its outcome unknown.

CREATE TABLE IF NOT EXISTS {{tables.dispatches}} (
    dispatch_id   UUID PRIMARY KEY,
    subject       TEXT NOT NULL,
    action        TEXT NOT NULL,
    retry_exempt  BOOLEAN NOT NULL DEFAULT FALSE,
    state         TEXT NOT NULL CHECK (
        state IN (
            'received', 'refused', 'awaiting_approval', 'approval_denied',
            'approval_expired', 'cancelled', 'admitted', 'dispatching', 'completed',
            'not_sent', 'outcome_unknown', 'reconciled_completed', 'reconciled_failed',
            'reconciled_unknown'
        )
    ),
    attempts      INTEGER NOT NULL DEFAULT 0,
    sweep_after   TIMESTAMPTZ,
    result        JSONB,
    late_results  JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dispatches_sweep
    ON {{tables.dispatches}} (sweep_after) WHERE state = 'dispatching';

CREATE INDEX IF NOT EXISTS idx_dispatches_unreconciled
    ON {{tables.dispatches}} (subject, action) WHERE state = 'outcome_unknown';
