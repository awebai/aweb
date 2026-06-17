-- 009_app_events.sql
-- App-emitted events and per-agent subscriptions.

CREATE TABLE IF NOT EXISTS {{tables.app_registry_event_types}} (
    app_id                  TEXT NOT NULL,
    origin                  TEXT NOT NULL,
    digest                  TEXT NOT NULL,
    event_type              TEXT NOT NULL,
    default_delivery_intent TEXT NOT NULL DEFAULT 'ambient'
                            CHECK (default_delivery_intent IN ('wake', 'steer', 'ambient')),
    description             TEXT NOT NULL DEFAULT '',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (app_id, origin, digest, event_type),
    FOREIGN KEY (app_id, origin, digest)
        REFERENCES {{tables.app_registry_entries}}(app_id, origin, digest),
    CONSTRAINT app_registry_event_types_event_not_blank
        CHECK (BTRIM(event_type) <> '')
);

CREATE TABLE IF NOT EXISTS {{tables.app_registry_emit_keys}} (
    app_id     TEXT NOT NULL,
    origin     TEXT NOT NULL,
    digest     TEXT NOT NULL,
    key_id     TEXT NOT NULL,
    did_key    TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (app_id, origin, digest, key_id),
    FOREIGN KEY (app_id, origin, digest)
        REFERENCES {{tables.app_registry_entries}}(app_id, origin, digest),
    CONSTRAINT app_registry_emit_keys_key_id_not_blank
        CHECK (BTRIM(key_id) <> ''),
    CONSTRAINT app_registry_emit_keys_did_key_not_blank
        CHECK (BTRIM(did_key) <> '')
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_app_registry_emit_keys_active_did
    ON {{tables.app_registry_emit_keys}} (app_id, origin, digest, did_key)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS {{tables.app_events}} (
    event_id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id                  TEXT NOT NULL REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    app_id                   TEXT NOT NULL,
    event_type               TEXT NOT NULL,
    resource_ref             TEXT,
    producer_delivery_intent TEXT NOT NULL DEFAULT 'ambient'
                             CHECK (producer_delivery_intent IN ('wake', 'steer', 'ambient')),
    payload                  JSONB NOT NULL DEFAULT '{}'::jsonb,
    producer_key_id          TEXT NOT NULL,
    producer_did_key         TEXT NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT app_events_app_id_not_blank
        CHECK (BTRIM(app_id) <> ''),
    CONSTRAINT app_events_event_type_not_blank
        CHECK (BTRIM(event_type) <> ''),
    CONSTRAINT app_events_producer_key_id_not_blank
        CHECK (BTRIM(producer_key_id) <> ''),
    CONSTRAINT app_events_producer_did_key_not_blank
        CHECK (BTRIM(producer_did_key) <> '')
);

CREATE INDEX IF NOT EXISTS idx_app_events_team_created
    ON {{tables.app_events}} (team_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_app_events_team_type_resource
    ON {{tables.app_events}} (team_id, event_type, resource_ref, created_at DESC);

CREATE TABLE IF NOT EXISTS {{tables.app_event_subscriptions}} (
    subscription_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         TEXT NOT NULL REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    agent_id        UUID NOT NULL REFERENCES {{tables.agents}}(agent_id) ON DELETE CASCADE,
    event_type      TEXT NOT NULL,
    resource_ref    TEXT,
    delivery_intent TEXT NOT NULL DEFAULT 'ambient'
                    CHECK (delivery_intent IN ('wake', 'steer', 'ambient')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT app_event_subscriptions_event_type_not_blank
        CHECK (BTRIM(event_type) <> '')
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_app_event_subscriptions_unique
    ON {{tables.app_event_subscriptions}} (
        team_id,
        agent_id,
        event_type,
        COALESCE(resource_ref, '')
    );

CREATE INDEX IF NOT EXISTS idx_app_event_subscriptions_agent
    ON {{tables.app_event_subscriptions}} (team_id, agent_id, event_type);
