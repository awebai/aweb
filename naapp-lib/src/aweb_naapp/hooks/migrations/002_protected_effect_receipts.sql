-- Historical exact-effect confirmation; recorded atomically with owner acts.
CREATE TABLE {{tables.protected_effect_receipts}} (
    operation_id UUID NOT NULL,
    team_id TEXT NOT NULL,
    service_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    variant TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    header_sha256 TEXT NOT NULL CHECK (header_sha256 ~ '^[0-9a-f]{64}$'),
    applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (operation_id, team_id)
);
CREATE INDEX ON {{tables.protected_effect_receipts}} (operation_id, header_sha256);
