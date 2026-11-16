-- acxy.15 skeleton: explicit registry-host provisioning, never automatic opt-in.
-- A canonical team's protection survives deletion/recreation of its registry row.
-- No worker/controller-key-only network operation writes this authority binding.
CREATE TABLE IF NOT EXISTS {{tables.team_protection}} (
    domain          TEXT NOT NULL,
    name            TEXT NOT NULL,
    service_id      TEXT NOT NULL CHECK (length(service_id) > 0),
    service_did_key TEXT NOT NULL CHECK (service_did_key LIKE 'did:key:%'),
    generation      BIGINT NOT NULL CHECK (generation > 0),
    PRIMARY KEY (domain, name)
);
