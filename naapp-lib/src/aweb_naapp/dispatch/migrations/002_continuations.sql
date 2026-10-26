-- The one repeat of an outcome_unknown dispatch: a continuation names the
-- dispatch it continues, and the unique index makes that claim once per
-- original, across crashes and concurrent workers.

ALTER TABLE {{tables.dispatches}}
    ADD COLUMN IF NOT EXISTS continues UUID REFERENCES {{tables.dispatches}} (dispatch_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_dispatches_continues
    ON {{tables.dispatches}} (continues);
