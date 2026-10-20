-- secrets' records: the secrets an installation brokers, the policies and grants
-- under which a principal may use them, and the templates derived secrets'
-- grants are copied from. Every record belongs to one installation and team.
-- Policies are immutable, and a grant changes only by being revoked.

CREATE TABLE IF NOT EXISTS {{tables.secrets}} (
    secret_id        TEXT PRIMARY KEY,
    installation_id  TEXT NOT NULL,
    team_id          TEXT NOT NULL,
    ref              TEXT NOT NULL,
    record           JSONB NOT NULL,
    state            TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'disabled')),
    -- The custody version the broker opens: set only when a change set
    -- confirming that version commits, never the latest sealed one.
    active_version   INTEGER CHECK (active_version >= 1),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (installation_id, team_id, secret_id),
    UNIQUE (installation_id, ref)
);

CREATE TABLE IF NOT EXISTS {{tables.policies}} (
    installation_id  TEXT NOT NULL,
    digest           TEXT NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    body             JSONB NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (installation_id, digest)
);

CREATE TABLE IF NOT EXISTS {{tables.grants}} (
    grant_id           TEXT PRIMARY KEY,
    installation_id    TEXT NOT NULL,
    team_id            TEXT NOT NULL,
    secret_id          TEXT NOT NULL,
    subject_principal  TEXT,
    subject_role       TEXT,
    capability         TEXT NOT NULL CHECK (capability IN ('use', 'run')),
    open_request       BOOLEAN NOT NULL,
    policy_digest      TEXT NOT NULL,
    record             JSONB NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at         TIMESTAMPTZ,
    CHECK ((subject_principal IS NULL) <> (subject_role IS NULL)),
    FOREIGN KEY (installation_id, team_id, secret_id)
        REFERENCES {{tables.secrets}} (installation_id, team_id, secret_id),
    FOREIGN KEY (installation_id, policy_digest)
        REFERENCES {{tables.policies}} (installation_id, digest)
);

CREATE INDEX IF NOT EXISTS idx_grants_active_by_secret
    ON {{tables.grants}} (installation_id, secret_id) WHERE revoked_at IS NULL;

-- The operations and jobs a grant allows, each at the digest it was granted at.
CREATE TABLE IF NOT EXISTS {{tables.grant_operations}} (
    grant_id      TEXT NOT NULL REFERENCES {{tables.grants}} (grant_id),
    operation_id  TEXT NOT NULL,
    digest        TEXT NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (grant_id, operation_id, digest)
);

CREATE TABLE IF NOT EXISTS {{tables.grant_jobs}} (
    grant_id  TEXT NOT NULL REFERENCES {{tables.grants}} (grant_id),
    job_id    TEXT NOT NULL,
    digest    TEXT NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (grant_id, job_id, digest)
);

CREATE TABLE IF NOT EXISTS {{tables.grant_templates}} (
    installation_id    TEXT NOT NULL,
    grant_template_id  TEXT NOT NULL,
    record             JSONB NOT NULL,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (installation_id, grant_template_id)
);

CREATE OR REPLACE FUNCTION {{tables.secrets_refuse_change}}() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is immutable', TG_TABLE_NAME;
END;
$$;

CREATE OR REPLACE FUNCTION {{tables.secrets_grant_only_revoked}}() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
       AND (to_jsonb(NEW) - 'revoked_at') = (to_jsonb(OLD) - 'revoked_at') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'a grant changes only by being revoked';
END;
$$;

CREATE OR REPLACE TRIGGER policies_immutable
    BEFORE UPDATE ON {{tables.policies}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();

CREATE OR REPLACE TRIGGER grant_operations_immutable
    BEFORE UPDATE ON {{tables.grant_operations}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();

CREATE OR REPLACE TRIGGER grant_jobs_immutable
    BEFORE UPDATE ON {{tables.grant_jobs}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();

CREATE OR REPLACE TRIGGER grants_only_revoked
    BEFORE UPDATE ON {{tables.grants}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_grant_only_revoked}}();

-- Token buckets of policies' rate limits (§4.4): one per (secret, principal) and
-- one per secret, whose principal_did is ''. Charged in the admission transaction.
CREATE TABLE IF NOT EXISTS {{tables.rate_buckets}} (
    installation_id  TEXT NOT NULL,
    secret_id        TEXT NOT NULL,
    scope            TEXT NOT NULL CHECK (scope IN ('principal_secret', 'secret')),
    principal_did    TEXT NOT NULL,
    tokens           DOUBLE PRECISION NOT NULL,
    refilled_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (installation_id, secret_id, scope, principal_did),
    CHECK ((scope = 'secret') = (principal_did = ''))
);

-- Admitted uses (§4.1): what was admitted, for whom, under which installation
-- generation, grant, policy and secret version. A request's idempotency key
-- stands for its intent, so a replay returns this record.
CREATE TABLE IF NOT EXISTS {{tables.intents}} (
    intent_id           TEXT PRIMARY KEY,
    installation_id     TEXT NOT NULL,
    install_generation  BIGINT NOT NULL CHECK (install_generation >= 1),
    team_id             TEXT NOT NULL,
    principal_did       TEXT NOT NULL,
    member_did_key      TEXT NOT NULL,
    certificate_id      TEXT NOT NULL,
    request_id          TEXT NOT NULL,
    request_sha256      BYTEA NOT NULL,
    secret_id           TEXT NOT NULL,
    secret_version      INTEGER NOT NULL,
    grant_id            TEXT NOT NULL REFERENCES {{tables.grants}} (grant_id),
    policy_digest       TEXT NOT NULL,
    action              TEXT NOT NULL CHECK (action IN ('operation', 'open_request')),
    operation_id        TEXT,
    operation_digest    TEXT,
    approval_required   BOOLEAN NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK ((action = 'operation') = (operation_id IS NOT NULL AND operation_digest IS NOT NULL)),
    FOREIGN KEY (installation_id, team_id, secret_id)
        REFERENCES {{tables.secrets}} (installation_id, team_id, secret_id),
    FOREIGN KEY (installation_id, policy_digest)
        REFERENCES {{tables.policies}} (installation_id, digest)
);

CREATE OR REPLACE TRIGGER intents_immutable
    BEFORE UPDATE ON {{tables.intents}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
