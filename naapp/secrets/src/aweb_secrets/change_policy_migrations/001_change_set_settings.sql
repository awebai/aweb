-- Each installation's four-eyes setting for change sets (decision 61): whether
-- a change set's drafter may confirm it. Requiring four eyes is applied
-- directly; relaxing it only through a confirmed change set. revision is the
-- configuration revision at which the setting last changed.

CREATE TABLE IF NOT EXISTS {{tables.change_set_settings}} (
    installation_id    TEXT PRIMARY KEY,
    distinct_approver  TEXT NOT NULL DEFAULT 'not_required'
        CHECK (distinct_approver IN ('required', 'not_required')),
    revision           BIGINT NOT NULL DEFAULT 0,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
