-- Library domain: profile packs, profiles (versions = (ref, version) rows),
-- agent-profile bindings, team registrations, and learning proposals.
--
-- visibility, owner_team, and tags are MUTABLE access/organization metadata on
-- the record — they are NOT part of the content digest, so flipping visibility
-- or editing tags never changes a profile's version or digest.

CREATE TABLE IF NOT EXISTS {{tables.profile_packs}} (
    owner_team TEXT NOT NULL REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    pack_ref TEXT NOT NULL,
    version TEXT NOT NULL,
    digest TEXT NOT NULL,
    visibility TEXT NOT NULL DEFAULT 'private' CHECK (visibility IN ('public', 'private')),
    tags TEXT[] NOT NULL DEFAULT '{}',
    name TEXT NOT NULL,
    summary TEXT,
    description TEXT,
    recommendations JSONB NOT NULL DEFAULT '[]'::jsonb,
    runtime_hints TEXT[] NOT NULL DEFAULT '{}',
    expected_apps TEXT[] NOT NULL DEFAULT '{}',
    first_mission_examples TEXT[] NOT NULL DEFAULT '{}',
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (owner_team, pack_ref, version)
);

CREATE INDEX IF NOT EXISTS idx_library_packs_visibility
    ON {{tables.profile_packs}}(visibility);

CREATE TABLE IF NOT EXISTS {{tables.profiles}} (
    owner_team TEXT NOT NULL REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    profile_ref TEXT NOT NULL,
    version TEXT NOT NULL,
    digest TEXT NOT NULL,
    pack_ref TEXT,
    pack_version TEXT,
    visibility TEXT NOT NULL DEFAULT 'private' CHECK (visibility IN ('public', 'private')),
    tags TEXT[] NOT NULL DEFAULT '{}',
    name TEXT NOT NULL,
    mission TEXT,
    accepted_work TEXT[] NOT NULL DEFAULT '{}',
    runtime_assumptions TEXT[] NOT NULL DEFAULT '{}',
    memory_policy JSONB,
    expected_apps TEXT[] NOT NULL DEFAULT '{}',
    event_subscriptions JSONB NOT NULL DEFAULT '[]'::jsonb,
    approval_required TEXT[] NOT NULL DEFAULT '{}',
    files JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (owner_team, profile_ref, version)
);

CREATE INDEX IF NOT EXISTS idx_library_profiles_visibility
    ON {{tables.profiles}}(visibility);
CREATE INDEX IF NOT EXISTS idx_library_profiles_tags
    ON {{tables.profiles}} USING GIN (tags);

CREATE TABLE IF NOT EXISTS {{tables.team_registrations}} (
    team_id TEXT PRIMARY KEY REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    owner TEXT,
    display_name TEXT,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS {{tables.profile_bindings}} (
    team_id TEXT NOT NULL REFERENCES {{tables.team_registrations}}(team_id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL,
    profile_ref TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    profile_digest TEXT NOT NULL,
    source_profile_pack_ref TEXT,
    bound_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (team_id, agent_id)
);

CREATE TABLE IF NOT EXISTS {{tables.proposals}} (
    proposal_id UUID PRIMARY KEY,
    team_id TEXT NOT NULL REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    target TEXT NOT NULL CHECK (target IN ('profile', 'memory', 'skill', 'workflow')),
    profile_ref TEXT,
    profile_version TEXT,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'approved', 'rejected')),
    content JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by_alias TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_library_proposals_team_status
    ON {{tables.proposals}}(team_id, status);
