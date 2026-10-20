-- 026_team_app_event_types.sql
-- An app's event declarations and its version projection belong to the team
-- whose install supplied them, so one team's install cannot change another
-- team's declared types, default delivery intents or descriptions.
--
-- Rows of app_registry_event_types are not copied, for the same reason as the
-- emit keys of 024: they record no installing team. The operator command
-- `aweb reseed-app-registrations` recreates every team's declarations and
-- keys from the app's manifest bytes. The version projection is copied from
-- the registry entry so listings stay complete until that reseed rewrites it
-- from the bytes.

CREATE TABLE IF NOT EXISTS {{tables.team_app_event_types}} (
    team_id                 TEXT NOT NULL REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    app_id                  TEXT NOT NULL,
    origin                  TEXT NOT NULL,
    digest                  TEXT NOT NULL,
    event_type              TEXT NOT NULL,
    default_delivery_intent TEXT NOT NULL DEFAULT 'ambient'
                            CHECK (default_delivery_intent IN ('wake', 'steer', 'ambient')),
    description             TEXT NOT NULL DEFAULT '',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (team_id, app_id, origin, digest, event_type),
    FOREIGN KEY (app_id, origin, digest)
        REFERENCES {{tables.app_registry_entries}}(app_id, origin, digest),
    CONSTRAINT team_app_event_types_event_not_blank
        CHECK (BTRIM(event_type) <> '')
);

ALTER TABLE {{tables.team_app_installs}}
    ADD COLUMN IF NOT EXISTS app_version TEXT,
    ADD COLUMN IF NOT EXISTS manifest_version INTEGER;

UPDATE {{tables.team_app_installs}} AS i
SET app_version = r.app_version,
    manifest_version = r.manifest_version
FROM {{tables.app_registry_entries}} AS r
WHERE r.app_id = i.app_id
  AND r.origin = i.origin
  AND r.digest = i.digest
  AND i.app_version IS NULL;

ALTER TABLE {{tables.team_app_installs}}
    ALTER COLUMN app_version SET NOT NULL,
    ALTER COLUMN manifest_version SET NOT NULL;
