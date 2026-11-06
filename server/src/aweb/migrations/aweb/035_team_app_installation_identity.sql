-- Legacy pins are not proof that this server fetched their origin bytes.
-- The operator verifier runs after migration; migrations perform no network.
ALTER TABLE {{tables.team_app_installs}}
    ADD COLUMN installation_id TEXT NOT NULL DEFAULT gen_random_uuid()::TEXT,
    ADD COLUMN generation BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN state TEXT NOT NULL DEFAULT 'pending_origin_verification',
    ADD COLUMN origin_verified BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN origin_verification_error TEXT,
    ADD COLUMN manifest_bytes BYTEA,
    ADD CONSTRAINT team_app_installs_installation_id_unique UNIQUE (installation_id),
    ADD CONSTRAINT team_app_installs_generation_positive CHECK (generation > 0),
    ADD CONSTRAINT team_app_installs_state CHECK (state IN ('pending_origin_verification', 'active', 'uninstalled')),
    ADD CONSTRAINT team_app_installs_verification_error_bound
        CHECK (origin_verification_error IS NULL OR length(origin_verification_error) <= 128),
    ADD CONSTRAINT team_app_installs_manifest_size
        CHECK (manifest_bytes IS NULL OR octet_length(manifest_bytes) <= 10485760),
    ADD CONSTRAINT team_app_installs_manifest_digest
        CHECK (manifest_bytes IS NULL OR digest = 'sha256:' || encode(pg_catalog.sha256(manifest_bytes), 'hex')),
    ADD CONSTRAINT team_app_installs_active_verified
        CHECK (state <> 'active' OR (origin_verified AND manifest_bytes IS NOT NULL));

-- An uninstall may remove every installation record. Authority ordering must
-- still survive: never delete this counter, even on team deletion. Reusing a
-- team_id must not issue generations below those remembered by remote apps.
CREATE TABLE {{tables.team_app_install_counters}} (
    team_id TEXT NOT NULL,
    app_id TEXT NOT NULL,
    last_generation BIGINT NOT NULL CHECK (last_generation > 0),
    PRIMARY KEY (team_id, app_id)
);
INSERT INTO {{tables.team_app_install_counters}} (team_id, app_id, last_generation)
SELECT team_id, app_id, generation FROM {{tables.team_app_installs}};
