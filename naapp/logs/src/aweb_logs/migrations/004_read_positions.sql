-- Readers follow one trace, reference or actor and page through it by
-- position (audit-substrate.md §B4). Each exact-identifier filter's index ends
-- with the position, so a filtered page or tail reads only its matching events
-- past its cursor, in order. 003's indexes on the same identifiers are
-- prefixes of these and are dropped.
DROP INDEX IF EXISTS {{schema}}.idx_read_events_trace;
DROP INDEX IF EXISTS {{schema}}.idx_read_events_job;
DROP INDEX IF EXISTS {{schema}}.idx_read_events_dispatch;
DROP INDEX IF EXISTS {{schema}}.idx_read_events_operation;
DROP INDEX IF EXISTS {{schema}}.idx_read_events_actor;

CREATE INDEX IF NOT EXISTS idx_read_events_trace_position
    ON {{tables.read_events}} (team_id, trace_id, chain_epoch, team_seq);
CREATE INDEX IF NOT EXISTS idx_read_events_operation_position
    ON {{tables.read_events}} (team_id, operation_id, chain_epoch, team_seq);
CREATE INDEX IF NOT EXISTS idx_read_events_job_position
    ON {{tables.read_events}} (team_id, job_id, chain_epoch, team_seq);
CREATE INDEX IF NOT EXISTS idx_read_events_dispatch_position
    ON {{tables.read_events}} (team_id, dispatch_id, chain_epoch, team_seq);
CREATE INDEX IF NOT EXISTS idx_read_events_approval_position
    ON {{tables.read_events}} (team_id, approval_id, chain_epoch, team_seq);
CREATE INDEX IF NOT EXISTS idx_read_events_grant_position
    ON {{tables.read_events}} (team_id, grant_id, chain_epoch, team_seq);
CREATE INDEX IF NOT EXISTS idx_read_events_secret_position
    ON {{tables.read_events}} (team_id, secret_id, chain_epoch, team_seq);
CREATE INDEX IF NOT EXISTS idx_read_events_actor_key_position
    ON {{tables.read_events}} (team_id, actor_did_key, chain_epoch, team_seq);
CREATE INDEX IF NOT EXISTS idx_read_events_actor_aw_position
    ON {{tables.read_events}} (team_id, actor_did_aw, chain_epoch, team_seq);
