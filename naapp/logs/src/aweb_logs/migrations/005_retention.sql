-- Each team's owner-set retention, per event class (audit-substrate.md §B6): a
-- hook's own setting, or "all" for every hook without one. An event whose
-- class keeps it (retention_days NULL), or that no setting names, is kept.
-- Setting a class again replaces its row and its setting_id, so a purge's act
-- names the setting that caused it.
CREATE TABLE IF NOT EXISTS {{tables.retention_settings}} (
    team_id        TEXT NOT NULL,
    event_class    TEXT NOT NULL,
    retention_days INTEGER CHECK (retention_days BETWEEN 1 AND 36500),
    setting_id     UUID NOT NULL UNIQUE,
    set_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (team_id, event_class)
);

-- Retention reads, per hook, only the events with content received before its
-- cutoff: one range scan each, so a pass costs what has expired, not the
-- team's history.
CREATE INDEX IF NOT EXISTS idx_chain_events_retained
    ON {{tables.chain_events}} (team_id, hook, received_at) WHERE purge_act IS NULL;
