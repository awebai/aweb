-- 032_app_hook_bindings.sql
-- An installed app's declared hook bindings (docs/design/audit-substrate.md
-- §A3). A registration names a hook the app receives through one of its
-- tools; a production names a hook the app may emit. Each install generation
-- writes its bindings as pending. Only an owner act activates or revokes one;
-- a new generation supersedes every earlier binding and uninstall revokes the
-- live ones, so an activation is never inherited.
--
-- installation_id and generation come from the naapp installation model. Until
-- an install carries them, its bindings stay pending: an active binding must
-- name both.

CREATE TABLE IF NOT EXISTS {{tables.app_hook_bindings}} (
    binding_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind                  TEXT NOT NULL CHECK (kind IN ('registration', 'production')),
    team_id               TEXT NOT NULL REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    installation_id       TEXT,
    generation            INTEGER CHECK (generation > 0),
    app_id                TEXT NOT NULL,
    origin                TEXT NOT NULL,
    digest                TEXT NOT NULL,
    catalog_id            TEXT NOT NULL,
    catalog_version       INTEGER NOT NULL CHECK (catalog_version > 0),
    hook                  TEXT NOT NULL,
    tool                  TEXT,
    method                TEXT,
    path                  TEXT,
    scopes                TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    reads                 TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    state                 TEXT NOT NULL DEFAULT 'pending'
                          CHECK (state IN ('pending', 'active', 'revoked', 'superseded')),
    ended_by              TEXT CHECK (ended_by IN ('owner_act', 'uninstall', 'generation')),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at          TIMESTAMPTZ,
    active_from           TIMESTAMPTZ,
    revoked_at            TIMESTAMPTZ,
    activation_act_sha256 TEXT CHECK (activation_act_sha256 ~ '^[0-9a-f]{64}$'),
    revocation_act_sha256 TEXT CHECK (revocation_act_sha256 ~ '^[0-9a-f]{64}$'),
    FOREIGN KEY (app_id, origin, digest)
        REFERENCES {{tables.app_registry_entries}}(app_id, origin, digest),
    CONSTRAINT app_hook_bindings_digest_sha256 CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT app_hook_bindings_identity_together
        CHECK ((installation_id IS NULL) = (generation IS NULL)),
    CONSTRAINT app_hook_bindings_registration_target CHECK (
        kind <> 'registration'
        OR (tool IS NOT NULL AND method IS NOT NULL AND path IS NOT NULL AND cardinality(reads) = 0)
    ),
    CONSTRAINT app_hook_bindings_production_target CHECK (
        kind <> 'production'
        OR (tool IS NULL AND method IS NULL AND path IS NULL AND cardinality(scopes) = 0)
    ),
    CONSTRAINT app_hook_bindings_activation CHECK (
        (activated_at IS NULL AND active_from IS NULL AND activation_act_sha256 IS NULL)
        OR (
            state <> 'pending'
            AND installation_id IS NOT NULL
            AND activated_at IS NOT NULL
            AND active_from IS NOT NULL
            AND active_from = activated_at + INTERVAL '60 seconds'
            AND activation_act_sha256 IS NOT NULL
        )
    ),
    CONSTRAINT app_hook_bindings_active_was_activated CHECK (state <> 'active' OR activated_at IS NOT NULL),
    CONSTRAINT app_hook_bindings_end CHECK (
        (state IN ('pending', 'active') AND revoked_at IS NULL AND ended_by IS NULL AND revocation_act_sha256 IS NULL)
        OR (state = 'revoked' AND revoked_at IS NOT NULL AND ended_by IS NOT NULL
            AND ended_by IN ('owner_act', 'uninstall'))
        OR (state = 'superseded' AND revoked_at IS NOT NULL AND ended_by IS NOT NULL
            AND ended_by = 'generation')
    ),
    CONSTRAINT app_hook_bindings_revocation_act CHECK (
        (COALESCE(ended_by, '') = 'owner_act') = (revocation_act_sha256 IS NOT NULL)
    )
);

-- One live binding per declaration per install generation and digest. Ended
-- rows are history and never hold the key, so a reinstall writes fresh pending
-- bindings. Before an install carries its installation identity the
-- generation is NULL, so the key reads it through COALESCE: NULLs would
-- otherwise never conflict.
CREATE UNIQUE INDEX IF NOT EXISTS idx_app_hook_bindings_declaration
    ON {{tables.app_hook_bindings}} (
        team_id, app_id, digest, COALESCE(installation_id, ''), COALESCE(generation, 0),
        kind, catalog_id, catalog_version, hook, COALESCE(tool, '')
    )
    WHERE state IN ('pending', 'active');

-- Producers' and consumers' queries: the active registrations or productions
-- of one hook in one team.
CREATE INDEX IF NOT EXISTS idx_app_hook_bindings_active
    ON {{tables.app_hook_bindings}} (team_id, catalog_id, catalog_version, hook, kind)
    WHERE state = 'active';

-- An app's own bindings by hook, in every state.
CREATE INDEX IF NOT EXISTS idx_app_hook_bindings_app
    ON {{tables.app_hook_bindings}} (team_id, app_id, catalog_id, catalog_version, hook);
