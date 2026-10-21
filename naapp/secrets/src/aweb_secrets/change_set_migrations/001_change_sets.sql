-- Change sets (design §6.2-§6.3, decision 54). A draft is inert until an owner
-- confirms it. Its B2 approval is minted in the draft's own transaction.
-- change_set_sealed lists the sealed versions a draft brought in, destroyed
-- if the draft expires or is cancelled. approvers holds each approver an
-- applied change set designated, and the secrets it covers.

CREATE TABLE IF NOT EXISTS {{tables.change_sets}} (
    change_id        TEXT PRIMARY KEY,
    installation_id  TEXT NOT NULL,
    team_id          TEXT NOT NULL,
    base_revision    INTEGER NOT NULL CHECK (base_revision >= 0),
    request          JSONB NOT NULL,
    via              TEXT NOT NULL CHECK (via IN ('team_auth', 'console')),
    drafted_by       TEXT NOT NULL,
    approval_id      TEXT NOT NULL,
    state            TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'applied', 'expired', 'cancelled')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at       TIMESTAMPTZ NOT NULL,
    closed_at        TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_change_sets_drafter
    ON {{tables.change_sets}} (installation_id, drafted_by, created_at);
CREATE INDEX IF NOT EXISTS idx_change_sets_pending_expiry
    ON {{tables.change_sets}} (expires_at) WHERE state = 'pending';

CREATE TABLE IF NOT EXISTS {{tables.change_set_sealed}} (
    change_id        TEXT NOT NULL REFERENCES {{tables.change_sets}} (change_id),
    installation_id  TEXT NOT NULL,
    team_id          TEXT NOT NULL,
    secret_id        TEXT NOT NULL,
    version          INTEGER NOT NULL,
    PRIMARY KEY (change_id, installation_id, team_id, secret_id, version)
);

CREATE TABLE IF NOT EXISTS {{tables.approvers}} (
    installation_id  TEXT NOT NULL,
    team_id          TEXT NOT NULL,
    approver_ref     TEXT NOT NULL,
    scope            TEXT NOT NULL UNIQUE,
    covers           JSONB NOT NULL,
    principal_did    TEXT,
    change_id        TEXT NOT NULL REFERENCES {{tables.change_sets}} (change_id),
    PRIMARY KEY (installation_id, team_id, approver_ref)
);

CREATE INDEX IF NOT EXISTS idx_approvers_covers ON {{tables.approvers}} USING GIN (covers);
