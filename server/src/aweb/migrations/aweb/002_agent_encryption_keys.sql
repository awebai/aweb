-- 002_agent_encryption_keys.sql
-- Identity-signed E2E encryption-key assertions for same-team/local discovery.

CREATE TABLE IF NOT EXISTS {{tables.agent_encryption_keys}} (
    agent_id                    UUID NOT NULL REFERENCES {{tables.agents}}(agent_id)
                                ON DELETE CASCADE,
    team_id                     TEXT NOT NULL REFERENCES {{tables.teams}}(team_id)
                                ON DELETE CASCADE,
    encryption_key_id           TEXT NOT NULL,
    encryption_public_key       TEXT NOT NULL,
    algorithm                   TEXT NOT NULL,
    identity_did                TEXT NOT NULL,
    identity_stable_id          TEXT,
    assertion_signature         TEXT NOT NULL,
    assertion_canonical         TEXT NOT NULL,
    created_at_text             TEXT NOT NULL,
    not_before_text             TEXT NOT NULL,
    expires_at_text             TEXT NOT NULL,
    assertion_created_at        TIMESTAMPTZ NOT NULL,
    not_before_at               TIMESTAMPTZ NOT NULL,
    expires_at                  TIMESTAMPTZ NOT NULL,
    previous_encryption_key_id  TEXT,
    published_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at                  TIMESTAMPTZ,
    PRIMARY KEY (agent_id, encryption_key_id),
    CONSTRAINT agent_encryption_keys_algorithm_valid
        CHECK (algorithm = 'x25519'),
    CONSTRAINT agent_encryption_keys_key_id_valid
        CHECK (encryption_key_id LIKE 'sha256:%'),
    CONSTRAINT agent_encryption_keys_identity_did_valid
        CHECK (identity_did LIKE 'did:key:z%'),
    CONSTRAINT agent_encryption_keys_stable_id_valid
        CHECK (identity_stable_id IS NULL OR identity_stable_id LIKE 'did:aw:%')
);

CREATE INDEX IF NOT EXISTS idx_agent_encryption_keys_active
    ON {{tables.agent_encryption_keys}} (team_id, agent_id, published_at DESC)
    WHERE revoked_at IS NULL;
