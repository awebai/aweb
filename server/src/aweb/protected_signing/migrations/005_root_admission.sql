-- Retained service endorsement, distinct from an ordinary human-parent issuance.
CREATE TABLE {{tables.protected_root_endorsements}} (
    service_id TEXT NOT NULL,
    root_id TEXT NOT NULL,
    human_id TEXT NOT NULL,
    human_domain TEXT NOT NULL,
    operation_id TEXT NOT NULL UNIQUE,
    certificate_id TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    PRIMARY KEY (service_id,root_id)
);
-- Uncertain registrations keep their reservation. A root key rotation cannot
-- reset either bound: all counters select the stable root ID, never its key.
CREATE TABLE {{tables.protected_root_admissions}} (
    operation_id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    root_id TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    certificate_id TEXT NOT NULL UNIQUE,
    child_id TEXT,
    child_key TEXT NOT NULL,
    admitted_at TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved','active','removed'))
);
CREATE INDEX protected_admission_quota ON {{tables.protected_root_admissions}} (service_id,team_id,root_id,admitted_at);
