-- Member requests grant nothing. Approval uses the same current admin policy,
-- origin fetch and conditional installation writer as a direct confirmation.
CREATE TABLE {{tables.app_installation_requests}} (
    request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id TEXT NOT NULL REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    app_id TEXT NOT NULL,
    origin TEXT NOT NULL,
    digest TEXT NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    requested_scopes TEXT[] NOT NULL,
    requested_by JSONB NOT NULL,
    manifest_bytes BYTEA NOT NULL CHECK (octet_length(manifest_bytes) <= 10485760),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'declined')),
    installation_id TEXT,
    generation BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    resolved_at TIMESTAMPTZ,
    CHECK (digest = 'sha256:' || encode(pg_catalog.sha256(manifest_bytes), 'hex')),
    CHECK ((state = 'approved') = (installation_id IS NOT NULL AND generation IS NOT NULL)),
    CHECK ((state = 'pending') = (resolved_at IS NULL))
);
CREATE INDEX ON {{tables.app_installation_requests}} (team_id, created_at DESC);

-- A request queues this job; an operator worker performs the origin fetch
-- outside HTTP and installation locks. A crashed worker's lease expires.
CREATE TABLE {{tables.app_installation_verifications}} (
    job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id TEXT NOT NULL REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    app_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    generation BIGINT NOT NULL,
    digest TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'complete')),
    lease_until TIMESTAMPTZ,
    result JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX ON {{tables.app_installation_verifications}} (team_id, app_id)
    WHERE state IN ('queued', 'running');

-- The public generation type is BIGINT; the pre-F6 hook table used INTEGER.
ALTER TABLE {{tables.app_hook_bindings}} ALTER COLUMN generation TYPE BIGINT;
