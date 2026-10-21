-- Each installation's configuration revision. A change set is drafted against
-- one revision and confirmed only at that revision. Every applied change set
-- and every narrowing act moves it on, so a draft computed before either is
-- refused as stale.

CREATE TABLE IF NOT EXISTS {{tables.config_revisions}} (
    installation_id  TEXT PRIMARY KEY,
    revision         INTEGER NOT NULL CHECK (revision > 0)
);
