-- Network-free schema change. Legacy NULL rows are bound on their first fresh,
-- active G1 observation only when installed_at < created_at. A refused legacy
-- row is permanently marked and is never adopted by a later installation.
ALTER TABLE {{tables.presentation_links}}
    ADD COLUMN installation_id TEXT,
    ADD COLUMN installation_refused BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT folio_present_installation_not_blank
        CHECK (installation_id IS NULL OR BTRIM(installation_id) <> '');
ALTER TABLE {{tables.edit_sessions}}
    ADD COLUMN installation_id TEXT,
    ADD COLUMN installation_refused BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT folio_edit_installation_not_blank
        CHECK (installation_id IS NULL OR BTRIM(installation_id) <> '');
