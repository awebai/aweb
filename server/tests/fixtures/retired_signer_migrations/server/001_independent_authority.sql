-- Explicit protected-host provisioning. No worker-facing writer or key store.
CREATE TABLE {{tables.protected_authorizer_bindings}} (
    service_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    human_id TEXT NOT NULL CHECK (human_id LIKE 'did:aw:%'),
    human_domain TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    subject TEXT NOT NULL,
    b3_scope TEXT NOT NULL UNIQUE,
    policy_version BIGINT NOT NULL CHECK (policy_version > 0),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (service_id, team_id, human_id, human_domain)
);
CREATE TABLE {{tables.protected_requester_bindings}} (
    b3_scope TEXT NOT NULL REFERENCES {{tables.protected_authorizer_bindings}}(b3_scope),
    principal TEXT NOT NULL CHECK (principal LIKE 'did:aw:%'),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (b3_scope, principal)
);
CREATE TABLE {{tables.protected_local_audit}} (
    sequence BIGSERIAL PRIMARY KEY,
    kind TEXT NOT NULL,
    actor TEXT NOT NULL,
    subject TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    approval_id TEXT,
    details JSONB NOT NULL
);
