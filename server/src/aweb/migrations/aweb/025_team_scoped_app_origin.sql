-- 025_team_scoped_app_origin.sql
-- An app id's origin is bound per team by that team's install, not across the
-- registry: one team's install cannot claim an app id's origin for another
-- team. app_registry_apps keeps one row per (app_id, origin) for the registry
-- entries that reference it.

ALTER TABLE {{tables.app_registry_apps}}
    DROP CONSTRAINT app_registry_apps_pkey;

ALTER TABLE {{tables.app_registry_apps}}
    ADD CONSTRAINT app_registry_apps_pkey PRIMARY KEY (app_id, origin);
