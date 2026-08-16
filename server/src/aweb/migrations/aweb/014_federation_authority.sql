-- Inactive strict external-sender authority security and coordination state.
-- PostgreSQL is the sole authority for these rows; Redis/process caches cannot
-- authorize or substitute when this state is unavailable.

CREATE TABLE IF NOT EXISTS {{tables.federation_did_checkpoints}} (
    did_aw              TEXT PRIMARY KEY CHECK (did_aw LIKE 'did:aw:%' AND btrim(did_aw) = did_aw),
    seq                 BIGINT NOT NULL CHECK (seq BETWEEN 1 AND 9007199254740991),
    entry_hash          TEXT NOT NULL CHECK (entry_hash ~ '^[0-9a-f]{64}$'),
    state_hash          TEXT NOT NULL CHECK (state_hash ~ '^[0-9a-f]{64}$'),
    current_did_key     TEXT NOT NULL CHECK (current_did_key LIKE 'did:key:z%'),
    revision            BIGINT NOT NULL CHECK (revision > 0),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),

    UNIQUE (did_aw, revision)
);

CREATE TABLE IF NOT EXISTS {{tables.federation_address_authority_cohorts}} (
    canonical_address               TEXT PRIMARY KEY CHECK (btrim(canonical_address) = canonical_address AND canonical_address LIKE '%/%'),
    authority_selection             TEXT NOT NULL CHECK (authority_selection IN ('dns', 'public_default')),
    authority_name                  TEXT NOT NULL,
    controller_did                  TEXT NOT NULL CHECK (controller_did LIKE 'did:key:z%'),
    authority_statement_version     TEXT NOT NULL CHECK (authority_statement_version = 'aweb.federation-authority.dns.v1'),
    authority_statement_digest      TEXT NOT NULL CHECK (authority_statement_digest ~ '^sha256:[0-9a-f]{64}$'),
    inherited                       BOOLEAN NOT NULL,
    registry_explicit               BOOLEAN NOT NULL,
    registry_origin                 TEXT NOT NULL CHECK (btrim(registry_origin) = registry_origin AND registry_origin <> ''),
    address_id                      TEXT,
    bound_did_aw                    TEXT NOT NULL CHECK (bound_did_aw LIKE 'did:aw:%'),
    bound_current_did_key           TEXT NOT NULL CHECK (bound_current_did_key LIKE 'did:key:z%'),
    checkpoint_seq                  BIGINT NOT NULL CHECK (checkpoint_seq BETWEEN 1 AND 9007199254740991),
    checkpoint_entry_hash           TEXT NOT NULL CHECK (checkpoint_entry_hash ~ '^[0-9a-f]{64}$'),
    checkpoint_revision             BIGINT NOT NULL CHECK (checkpoint_revision > 0),
    authoritative_delivery_origin   TEXT NOT NULL CHECK (btrim(authoritative_delivery_origin) = authoritative_delivery_origin AND authoritative_delivery_origin <> ''),
    authoritative_read_completed_at TIMESTAMPTZ NOT NULL,
    expires_at                      TIMESTAMPTZ NOT NULL,
    generation                      BIGINT NOT NULL CHECK (generation > 0),
    revision                        BIGINT NOT NULL CHECK (revision > 0),
    publishing_fence                BIGINT NOT NULL CHECK (publishing_fence > 0),
    created_at                      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),

    CHECK (expires_at >= authoritative_read_completed_at),
    CHECK (expires_at <= authoritative_read_completed_at + INTERVAL '60 seconds')
);

CREATE INDEX IF NOT EXISTS idx_federation_authority_cohorts_did_checkpoint
    ON {{tables.federation_address_authority_cohorts}} (
        bound_did_aw, checkpoint_revision, checkpoint_seq
    );
CREATE INDEX IF NOT EXISTS idx_federation_authority_cohorts_expiry
    ON {{tables.federation_address_authority_cohorts}} (expires_at);

-- Fence counters are durable tombstones and must never be deleted by expiry GC.
CREATE TABLE IF NOT EXISTS {{tables.federation_authority_fences}} (
    scope_key       TEXT PRIMARY KEY CHECK (btrim(scope_key) = scope_key AND scope_key <> ''),
    last_fence      BIGINT NOT NULL CHECK (last_fence > 0),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS {{tables.federation_authority_leases}} (
    scope_key       TEXT PRIMARY KEY REFERENCES {{tables.federation_authority_fences}}(scope_key) ON DELETE RESTRICT,
    owner_id        UUID NOT NULL,
    fence           BIGINT NOT NULL CHECK (fence > 0),
    acquired_at     TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    CHECK (expires_at > acquired_at),
    UNIQUE (scope_key, fence)
);
CREATE INDEX IF NOT EXISTS idx_federation_authority_leases_expiry
    ON {{tables.federation_authority_leases}} (expires_at);

CREATE TABLE IF NOT EXISTS {{tables.federation_authority_results}} (
    scope_key       TEXT PRIMARY KEY REFERENCES {{tables.federation_authority_fences}}(scope_key) ON DELETE RESTRICT,
    fence           BIGINT NOT NULL CHECK (fence > 0),
    status          TEXT NOT NULL CHECK (btrim(status) = status AND status <> ''),
    evidence        JSONB NOT NULL,
    source_digest   TEXT CHECK (source_digest IS NULL OR source_digest ~ '^sha256:[0-9a-f]{64}$'),
    created_at      TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS idx_federation_authority_results_expiry
    ON {{tables.federation_authority_results}} (expires_at);

CREATE TABLE IF NOT EXISTS {{tables.federation_authority_permits}} (
    permit_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_kind      TEXT NOT NULL CHECK (scope_kind IN ('global', 'domain', 'origin')),
    scope_key       TEXT NOT NULL CHECK (btrim(scope_key) = scope_key AND scope_key <> ''),
    owner_id        UUID NOT NULL,
    acquired_at     TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    CHECK (expires_at > acquired_at)
);
CREATE INDEX IF NOT EXISTS idx_federation_authority_permits_scope_expiry
    ON {{tables.federation_authority_permits}} (scope_kind, scope_key, expires_at);
CREATE INDEX IF NOT EXISTS idx_federation_authority_permits_owner
    ON {{tables.federation_authority_permits}} (owner_id);

CREATE TABLE IF NOT EXISTS {{tables.federation_authority_token_buckets}} (
    bucket_kind     TEXT NOT NULL CHECK (bucket_kind IN ('source_ip', 'domain', 'origin')),
    bucket_key      TEXT NOT NULL CHECK (btrim(bucket_key) = bucket_key AND bucket_key <> ''),
    tokens          DOUBLE PRECISION NOT NULL CHECK (tokens >= 0),
    refilled_at     TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (bucket_kind, bucket_key)
);
