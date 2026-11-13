-- Never restore this database from a content backup. It is the erasure fence:
-- one tombstone per purged event, which Logs reapplies to its content database
-- before it serves, so a restored backup never brings purged content back.
-- A tombstone is keyed by event_id, not chain position: a restored chain can
-- hold another event at the same position.
CREATE TABLE {{tables.event_purges}} (
    team_id    TEXT NOT NULL,
    event_id   UUID NOT NULL,
    event_hash TEXT NOT NULL,
    purge_act  TEXT NOT NULL,
    purged_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (team_id, event_id)
);
