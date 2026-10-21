-- Owner-act nonces: each verifier accepts an owner act once. The row is
-- inserted in the same transaction as the act's effect, so of two concurrent
-- uses one commits and the other conflicts and rolls back with nonce_reused;
-- a failed effect rolls its row back, and the owner may retry the same act.
-- Rows are kept at least until the act's expires_at plus the 60-second clock
-- allowance, after which the act could not verify anyway.

CREATE TABLE IF NOT EXISTS {{tables.owner_act_nonces}} (
    scope       TEXT NOT NULL,
    team_id     TEXT NOT NULL,
    nonce       TEXT NOT NULL,
    act_sha256  TEXT NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (scope, team_id, nonce)
);

CREATE INDEX IF NOT EXISTS idx_owner_act_nonces_expires_at
    ON {{tables.owner_act_nonces}} (expires_at);
