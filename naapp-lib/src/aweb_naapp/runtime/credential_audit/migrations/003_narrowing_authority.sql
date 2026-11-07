-- Restricted authority association, not a second outbox. Survives key rotation
-- and normal outbox delivery cleanup; application lifecycle deletion owns it.
CREATE TABLE {{tables.credential_narrowing_authority}} (
    event_id UUID PRIMARY KEY,
    subject TEXT NOT NULL,
    app_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    authority TEXT NOT NULL CHECK (authority IN ('team_cert','passkey_session')),
    actor JSONB NOT NULL,
    commitment TEXT,
    retained_proof JSONB,
    occurred_at TIMESTAMPTZ NOT NULL,
    CHECK ((authority = 'passkey_session') = (commitment IS NOT NULL AND retained_proof IS NOT NULL))
);
