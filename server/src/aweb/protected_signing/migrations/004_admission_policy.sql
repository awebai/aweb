-- Operator-authorized first provisioning only. No worker-facing policy writer.
-- Replacement/widening needs its own exact protected policy-change admission.
CREATE TABLE {{tables.protected_admission_policies}} (
    service_id TEXT PRIMARY KEY,
    version BIGINT NOT NULL CHECK (version > 0 AND version < 9007199254740992),
    digest TEXT NOT NULL,
    policy JSONB NOT NULL,
    provisioned_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
