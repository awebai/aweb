-- Library model v2: public packs (the catalog) + private shelves (team copies).
-- Visibility is STRUCTURAL: a profile in a public pack is public; a profile on a
-- team's shelf is private. There is no visibility flag. Bindings, materialize, and
-- proposals all target SHELF profiles. Tags (mutable, never digested) live on both
-- packs and shelf profiles.

-- Public catalog packs: always public, versioned, tagged, owned by a publishing team.
CREATE TABLE IF NOT EXISTS {{tables.profile_packs}} (
    owner_team TEXT NOT NULL REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    pack_ref TEXT NOT NULL,
    version TEXT NOT NULL,
    digest TEXT NOT NULL,
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

CREATE INDEX IF NOT EXISTS idx_library_packs_tags
    ON {{tables.profile_packs}} USING GIN (tags);

-- Public profile snapshots within a pack version.
CREATE TABLE IF NOT EXISTS {{tables.pack_profiles}} (
    owner_team TEXT NOT NULL,
    pack_ref TEXT NOT NULL,
    pack_version TEXT NOT NULL,
    profile_ref TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    digest TEXT NOT NULL,
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
    PRIMARY KEY (owner_team, pack_ref, pack_version, profile_ref),
    FOREIGN KEY (owner_team, pack_ref, pack_version)
        REFERENCES {{tables.profile_packs}}(owner_team, pack_ref, version) ON DELETE CASCADE
);

-- A team registers with library only once at least one agent has a bound profile.
CREATE TABLE IF NOT EXISTS {{tables.team_registrations}} (
    team_id TEXT PRIMARY KEY REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    owner TEXT,
    display_name TEXT,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- A team's private working copies. Versions are (profile_ref, version) rows.
-- part_baselines records, per content part, its digest at copy/last-sync from the
-- source pack version, so update-from-source can do a per-part 3-way merge.
CREATE TABLE IF NOT EXISTS {{tables.shelf_profiles}} (
    team_id TEXT NOT NULL REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    profile_ref TEXT NOT NULL,
    version TEXT NOT NULL,
    digest TEXT NOT NULL,
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
    source_profile_pack_ref TEXT,
    source_profile_pack_version TEXT,
    source_profile_pack_digest TEXT,
    source_profile_ref TEXT,
    source_profile_version TEXT,
    source_profile_digest TEXT,
    part_baselines JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (team_id, profile_ref, version)
);

CREATE INDEX IF NOT EXISTS idx_library_shelf_source
    ON {{tables.shelf_profiles}}(team_id, source_profile_pack_ref, source_profile_ref);

CREATE INDEX IF NOT EXISTS idx_library_shelf_tags
    ON {{tables.shelf_profiles}} USING GIN (tags);

-- An agent binds to a SHELF profile. The FK to team_registrations means a binding
-- cannot exist without a registration (auto-registered on first bind).
CREATE TABLE IF NOT EXISTS {{tables.profile_bindings}} (
    team_id TEXT NOT NULL REFERENCES {{tables.team_registrations}}(team_id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL,
    profile_ref TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    profile_digest TEXT NOT NULL,
    bound_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (team_id, agent_id)
);

-- Learning proposals against a team's shelf profiles (lifecycle only in chunk A;
-- version-minting on approve lands once the proposal-content body is pinned).
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
