-- A cap is any integer an owner act may carry (up to 2^53 - 1) that the
-- deployment ceiling allows.
ALTER TABLE {{tables.credential_caps}} ALTER COLUMN cap TYPE BIGINT;
