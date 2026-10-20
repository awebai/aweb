-- Publicly readable, current-team-key-signed optional credential policy.
CREATE TABLE {{tables.team_credential_policies}} (
    team_uuid UUID PRIMARY KEY REFERENCES {{tables.teams}} (team_uuid),
    record_json TEXT NOT NULL,
    signature TEXT NOT NULL,
    team_did_key TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    issued_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE {{tables.team_credential_policy_audit}} (
    audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_uuid UUID NOT NULL REFERENCES {{tables.teams}} (team_uuid),
    actor_did_key TEXT NOT NULL,
    old_record_json TEXT,
    new_record_json TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
