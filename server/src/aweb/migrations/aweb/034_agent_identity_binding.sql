-- Historical projections have no verified identity attribution. Their own
-- authenticated connect/request can establish current registry evidence.
ALTER TABLE {{tables.agents}}
    ADD COLUMN did_aw_verified_key TEXT;
