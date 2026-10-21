-- A use's approval: which B2 approval decides the intent, for which dispatch,
-- at which secret version, and the frozen request it was approved on.
CREATE TABLE IF NOT EXISTS {{tables.use_approvals}} (
    intent_id        TEXT PRIMARY KEY REFERENCES {{tables.intents}} (intent_id),
    dispatch_id      UUID NOT NULL UNIQUE,
    installation_id  TEXT NOT NULL,
    team_id          TEXT NOT NULL,
    secret_id        TEXT NOT NULL,
    secret_version   INTEGER NOT NULL,
    approval_id      TEXT NOT NULL UNIQUE,
    approval_ref     TEXT NOT NULL UNIQUE,
    request          TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Voiding a secret's approvals when its value or external item changes.
CREATE INDEX IF NOT EXISTS idx_use_approvals_secret
    ON {{tables.use_approvals}} (installation_id, team_id, secret_id);
