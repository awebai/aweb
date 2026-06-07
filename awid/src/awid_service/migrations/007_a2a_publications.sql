-- 007_a2a_publications.sql
-- AWID A2A Agent Card publication and delegated bridge assertions.

CREATE TABLE IF NOT EXISTS {{tables.a2a_bridge_delegations}} (
    delegation_id              TEXT PRIMARY KEY,
    delegator_did_aw           TEXT NOT NULL REFERENCES {{tables.did_aw_mappings}}(did_aw) ON DELETE CASCADE,
    delegator_current_did_key  TEXT NOT NULL,
    delegated_gateway_identity TEXT NOT NULL,
    address                    TEXT NOT NULL,
    route_id                   TEXT NOT NULL,
    card_url                   TEXT NOT NULL,
    rpc_url                    TEXT NOT NULL,
    allowed_operations         JSONB NOT NULL,
    card_digest_alg            TEXT NOT NULL,
    card_digest                TEXT NOT NULL,
    custody_mode               TEXT NOT NULL,
    authority_source           TEXT NOT NULL,
    signer_did                 TEXT NOT NULL,
    signer_kid                 TEXT NOT NULL,
    issued_at_text             TEXT NOT NULL,
    expires_at_text            TEXT NOT NULL,
    status                     TEXT NOT NULL,
    revoked_at_text            TEXT,
    revocation_reason          TEXT,
    registry_url               TEXT NOT NULL,
    assertion_signature        TEXT NOT NULL,
    assertion_canonical        TEXT NOT NULL,
    assertion_digest           TEXT NOT NULL,
    issued_at                  TIMESTAMPTZ NOT NULL,
    expires_at                 TIMESTAMPTZ NOT NULL,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at                 TIMESTAMPTZ,

    CONSTRAINT chk_a2a_delegations_card_digest_alg CHECK (card_digest_alg = 'sha256'),
    CONSTRAINT chk_a2a_delegations_status CHECK (status IN ('active', 'revoked')),
    CONSTRAINT chk_a2a_delegations_card_digest CHECK (card_digest LIKE 'sha256:%'),
    CONSTRAINT chk_a2a_delegations_assertion_digest CHECK (assertion_digest LIKE 'sha256:%')
);

CREATE INDEX IF NOT EXISTS idx_a2a_delegations_address_route_active
    ON {{tables.a2a_bridge_delegations}} (address, route_id)
    WHERE status = 'active' AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_a2a_delegations_gateway_active
    ON {{tables.a2a_bridge_delegations}} (delegated_gateway_identity)
    WHERE status = 'active' AND revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS {{tables.a2a_route_publications}} (
    assertion_id        TEXT PRIMARY KEY,
    address             TEXT NOT NULL,
    did_aw              TEXT NOT NULL REFERENCES {{tables.did_aw_mappings}}(did_aw) ON DELETE CASCADE,
    current_did_key     TEXT NOT NULL,
    signer_did          TEXT NOT NULL,
    signer_kid          TEXT NOT NULL,
    card_url            TEXT NOT NULL,
    rpc_url             TEXT NOT NULL,
    route_id            TEXT NOT NULL,
    tenant              TEXT,
    gateway_identity    TEXT NOT NULL,
    delegation_id       TEXT REFERENCES {{tables.a2a_bridge_delegations}}(delegation_id),
    delegation_digest   TEXT,
    card_digest_alg     TEXT NOT NULL,
    card_digest         TEXT NOT NULL,
    card_revision       TEXT NOT NULL,
    default_for_host    BOOLEAN NOT NULL DEFAULT FALSE,
    status              TEXT NOT NULL,
    published_at_text   TEXT NOT NULL,
    expires_at_text     TEXT NOT NULL,
    registry_url        TEXT NOT NULL,
    identity_custody    TEXT NOT NULL,
    authority_source    TEXT NOT NULL,
    assertion_signature TEXT NOT NULL,
    assertion_canonical TEXT NOT NULL,
    assertion_digest    TEXT NOT NULL,
    published_at        TIMESTAMPTZ NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at          TIMESTAMPTZ,

    CONSTRAINT chk_a2a_publications_card_digest_alg CHECK (card_digest_alg = 'sha256'),
    CONSTRAINT chk_a2a_publications_status CHECK (status IN ('active', 'revoked')),
    CONSTRAINT chk_a2a_publications_card_digest CHECK (card_digest LIKE 'sha256:%'),
    CONSTRAINT chk_a2a_publications_assertion_digest CHECK (assertion_digest LIKE 'sha256:%')
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_a2a_publications_natural_active
    ON {{tables.a2a_route_publications}}
        (address, route_id, card_url, rpc_url, gateway_identity, card_revision)
    WHERE status = 'active' AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_a2a_publications_address_active
    ON {{tables.a2a_route_publications}} (address, route_id, published_at DESC)
    WHERE status = 'active' AND revoked_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_a2a_publications_address_route_unique_active
    ON {{tables.a2a_route_publications}} (address, route_id)
    WHERE status = 'active' AND revoked_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_a2a_publications_default_host_active
    ON {{tables.a2a_route_publications}} (split_part(address, '/', 1))
    WHERE default_for_host IS TRUE AND status = 'active' AND revoked_at IS NULL;
