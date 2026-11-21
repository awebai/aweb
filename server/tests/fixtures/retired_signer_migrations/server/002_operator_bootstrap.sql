-- Once-only independent-host administrator admission. Never delete this record
-- to replace an authorizer or recover a credential. No worker-facing writer.
CREATE TABLE {{tables.protected_operator_bootstraps}} (
    service_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    bootstrap_id TEXT NOT NULL UNIQUE,
    binding TEXT NOT NULL,
    subject TEXT NOT NULL,
    b3_scope TEXT NOT NULL UNIQUE,
    requester TEXT NOT NULL,
    contact TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    consumed_at TIMESTAMPTZ,
    PRIMARY KEY (service_id, team_id)
);
