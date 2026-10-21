-- Each team's hash chain (docs/logs-chain.md): its epochs, the head every
-- append locks, the events, the checkpoints logs signed, and the faults it saw.

-- One row per chain epoch, holding its genesis exactly as hashed.
CREATE TABLE IF NOT EXISTS {{tables.chain_epochs}} (
    team_id                    TEXT NOT NULL,
    chain_epoch                INTEGER NOT NULL CHECK (chain_epoch >= 1),
    logs_origin                TEXT NOT NULL,
    created_at                 TEXT NOT NULL,
    previous_checkpoint_sha256 TEXT,
    genesis_hash               TEXT NOT NULL,
    PRIMARY KEY (team_id, chain_epoch),
    CHECK ((chain_epoch = 1) = (previous_checkpoint_sha256 IS NULL))
);

-- One row per team: its current epoch and head. Every append and checkpoint
-- holds this row's lock, so team_seq is assigned once and without gaps.
CREATE TABLE IF NOT EXISTS {{tables.chain_heads}} (
    team_id     TEXT PRIMARY KEY,
    chain_epoch INTEGER NOT NULL,
    team_seq    BIGINT NOT NULL CHECK (team_seq >= 0),
    event_hash  TEXT NOT NULL,
    FOREIGN KEY (team_id, chain_epoch) REFERENCES {{tables.chain_epochs}} (team_id, chain_epoch)
);

-- One row per appended event. The skeleton (the link fields and event_hash) is
-- kept forever. The content (salt, envelope bytes and signature) is purged
-- together, and purge_act then names the act that purged it.
CREATE TABLE IF NOT EXISTS {{tables.chain_events}} (
    team_id            TEXT NOT NULL,
    chain_epoch        INTEGER NOT NULL,
    team_seq           BIGINT NOT NULL CHECK (team_seq >= 1),
    event_id           UUID NOT NULL,
    prev_event_hash    TEXT NOT NULL,
    event_hash         TEXT NOT NULL,
    received_at        TEXT NOT NULL,
    hook               TEXT NOT NULL,
    producer_origin    TEXT NOT NULL,
    content_commitment TEXT NOT NULL,
    salt               BYTEA,
    signing_bytes      BYTEA,
    signature          TEXT,
    -- The producer key and binding facts ingest verified the envelope against.
    key_evidence       JSONB NOT NULL,
    receipt_bytes      BYTEA NOT NULL,
    receipt_signature  TEXT NOT NULL,
    purge_act          TEXT,
    PRIMARY KEY (team_id, chain_epoch, team_seq),
    UNIQUE (team_id, event_id),
    FOREIGN KEY (team_id, chain_epoch) REFERENCES {{tables.chain_epochs}} (team_id, chain_epoch),
    CHECK ((salt IS NULL) = (signing_bytes IS NULL) AND (salt IS NULL) = (signature IS NULL)),
    CHECK ((salt IS NULL) = (purge_act IS NOT NULL))
);

-- Every checkpoint logs signed, in issue order.
CREATE TABLE IF NOT EXISTS {{tables.chain_checkpoints}} (
    position                   BIGSERIAL PRIMARY KEY,
    team_id                    TEXT NOT NULL,
    chain_epoch                INTEGER NOT NULL,
    team_seq                   BIGINT NOT NULL CHECK (team_seq >= 0),
    event_hash                 TEXT NOT NULL,
    signing_bytes              BYTEA NOT NULL,
    signature                  TEXT NOT NULL,
    checkpoint_sha256          TEXT NOT NULL UNIQUE,
    previous_checkpoint_sha256 TEXT,
    FOREIGN KEY (team_id, chain_epoch) REFERENCES {{tables.chain_epochs}} (team_id, chain_epoch)
);

CREATE INDEX IF NOT EXISTS idx_chain_checkpoints_epoch
    ON {{tables.chain_checkpoints}} (team_id, chain_epoch, position);

-- Deliveries logs refused without appending, kept for verify to report. A
-- conflict keeps the digest of the refused bytes, never the bytes.
CREATE TABLE IF NOT EXISTS {{tables.chain_faults}} (
    fault_id       BIGSERIAL PRIMARY KEY,
    team_id        TEXT NOT NULL,
    event_id       UUID NOT NULL,
    kind           TEXT NOT NULL CHECK (kind IN ('event_conflict')),
    refused_sha256 TEXT NOT NULL,
    key_evidence   JSONB NOT NULL,
    recorded_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chain_faults_team ON {{tables.chain_faults}} (team_id, fault_id);
