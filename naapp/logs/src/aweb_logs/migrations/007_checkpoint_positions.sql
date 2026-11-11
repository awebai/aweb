-- An export reads an epoch's checkpoints by the team_seq they witness, one page
-- of events at a time; issue order (position) breaks ties.
CREATE INDEX IF NOT EXISTS idx_chain_checkpoints_seq
    ON {{tables.chain_checkpoints}} (team_id, chain_epoch, team_seq, position);
