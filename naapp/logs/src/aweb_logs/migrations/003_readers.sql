-- What readers query: one projection per chain event, derived from its retained
-- envelope and never adding content it did not carry (audit-substrate.md §B4).
-- A purged event's projection keeps only its position; its content columns are
-- null, so no content filter matches it.
CREATE TABLE IF NOT EXISTS {{tables.read_events}} (
    team_id        TEXT NOT NULL,
    chain_epoch    INTEGER NOT NULL,
    team_seq       BIGINT NOT NULL,
    purged         BOOLEAN NOT NULL,
    hook           TEXT NOT NULL,
    event_id       UUID,
    event_type     TEXT,
    mediation      TEXT CHECK (mediation IN ('server', 'registry_observed', 'client')),
    occurred_at    TIMESTAMPTZ,
    result_status  TEXT,
    trace_id       TEXT,
    actor_did_key  TEXT,
    actor_did_aw   TEXT,
    app_id         TEXT,
    operation_id   TEXT,
    job_id         TEXT,
    dispatch_id    TEXT,
    approval_id    TEXT,
    grant_id       TEXT,
    secret_id      TEXT,
    PRIMARY KEY (team_id, chain_epoch, team_seq),
    FOREIGN KEY (team_id, chain_epoch, team_seq)
        REFERENCES {{tables.chain_events}} (team_id, chain_epoch, team_seq),
    CHECK (purged = (event_id IS NULL))
);

CREATE INDEX IF NOT EXISTS idx_read_events_trace ON {{tables.read_events}} (team_id, trace_id);
CREATE INDEX IF NOT EXISTS idx_read_events_job ON {{tables.read_events}} (team_id, job_id);
CREATE INDEX IF NOT EXISTS idx_read_events_dispatch ON {{tables.read_events}} (team_id, dispatch_id);
CREATE INDEX IF NOT EXISTS idx_read_events_operation ON {{tables.read_events}} (team_id, operation_id);
CREATE INDEX IF NOT EXISTS idx_read_events_actor ON {{tables.read_events}} (team_id, actor_did_key);
CREATE INDEX IF NOT EXISTS idx_read_events_occurred ON {{tables.read_events}} (team_id, occurred_at);

-- Each reader an owner act designated: the installation and team it reads, and
-- the contact the act committed to by hash. Whether the reader holds the scope
-- now, and with which passkey, is B3's record of the scope.
CREATE TABLE IF NOT EXISTS {{tables.readers}} (
    scope           TEXT PRIMARY KEY,
    installation_id TEXT NOT NULL,
    team_id         TEXT NOT NULL,
    contact_sha256  TEXT NOT NULL,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_readers_installation ON {{tables.readers}} (installation_id, team_id);
