-- The transaction that ended a holding, so the end can be attributed to the act
-- that ended it in that same transaction. NULL while held and for a holding
-- that never ended; holding the role again clears it.
ALTER TABLE {{tables.role_holdings}} ADD COLUMN ended_in BIGINT;
