-- Role assignments: one row per (team, principal, role). The principal is the
-- member's did:aw when the team certificate carries one, else its did:key, and
-- is always scoped by the team, so a did:aw on another team holds nothing here.

CREATE TABLE IF NOT EXISTS {{tables.role_assignments}} (
    team_id        TEXT NOT NULL,
    principal_did  TEXT NOT NULL,
    role           TEXT NOT NULL,
    assigned_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (team_id, principal_did, role),
    CHECK (team_id <> ''),
    CHECK (principal_did LIKE 'did:aw:_%' OR principal_did LIKE 'did:key:_%'),
    CHECK (char_length(role) <= 128),
    CHECK (role ~ '^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+$')
);

CREATE INDEX IF NOT EXISTS idx_role_assignments_role
    ON {{tables.role_assignments}} (team_id, role);
