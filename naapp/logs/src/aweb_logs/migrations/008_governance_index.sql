-- logs' own governance entries in a team's chain (audit-substrate.md §B6).
-- verify reads them across the team's earlier epochs to report the legal holds
-- still active; this index makes that read cost those entries, not the team's
-- history.
CREATE INDEX IF NOT EXISTS idx_chain_events_governance
    ON {{tables.chain_events}} (team_id, chain_epoch, team_seq)
    WHERE hook = 'post-governance-hook';
