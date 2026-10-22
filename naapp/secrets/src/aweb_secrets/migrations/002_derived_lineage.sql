-- Server-managed issuance provenance; never an owner/agent-editable secret/1 field.
CREATE UNIQUE INDEX IF NOT EXISTS idx_grants_installation_team_id
    ON {{tables.grants}} (installation_id, team_id, grant_id);

CREATE TABLE IF NOT EXISTS {{tables.derived_secrets}} (
    installation_id     TEXT NOT NULL,
    team_id             TEXT NOT NULL,
    secret_id           TEXT NOT NULL,
    parent_secret_id    TEXT NOT NULL,
    parent_version      INTEGER NOT NULL CHECK (parent_version >= 1),
    source_dispatch_id  TEXT NOT NULL,
    source_grant_id     TEXT NOT NULL,
    issuing_principal   TEXT NOT NULL,
    policy_digest       TEXT NOT NULL,
    dispatch_started_at TIMESTAMPTZ NOT NULL,
    upstream_expires_at TIMESTAMPTZ NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (installation_id, team_id, secret_id),
    UNIQUE (installation_id, source_dispatch_id),
    CHECK (secret_id <> parent_secret_id),
    CHECK (dispatch_started_at < expires_at AND expires_at <= upstream_expires_at),
    FOREIGN KEY (installation_id, team_id, secret_id)
        REFERENCES {{tables.secrets}} (installation_id, team_id, secret_id),
    FOREIGN KEY (installation_id, team_id, parent_secret_id)
        REFERENCES {{tables.secrets}} (installation_id, team_id, secret_id),
    FOREIGN KEY (installation_id, team_id, source_grant_id)
        REFERENCES {{tables.grants}} (installation_id, team_id, grant_id),
    FOREIGN KEY (installation_id, policy_digest)
        REFERENCES {{tables.policies}} (installation_id, digest)
);

CREATE INDEX IF NOT EXISTS idx_derived_parent
    ON {{tables.derived_secrets}} (installation_id, team_id, parent_secret_id);
CREATE INDEX IF NOT EXISTS idx_derived_source_grant
    ON {{tables.derived_secrets}} (installation_id, source_grant_id);

CREATE OR REPLACE TRIGGER derived_secrets_immutable
    BEFORE UPDATE ON {{tables.derived_secrets}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
