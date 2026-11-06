-- Juan approved ancestor delegation on 2026-10-30 (aweb 6e689d14).
-- Existing rows stay unproven until an explicit parent-signed reaffirmation.
ALTER TABLE {{tables.dns_namespaces}}
    ADD COLUMN parent_domain TEXT,
    ADD COLUMN parent_controller_key TEXT,
    ADD CONSTRAINT namespace_delegation_complete CHECK (
        (parent_domain IS NULL AND parent_controller_key IS NULL)
        OR (parent_domain IS NOT NULL AND parent_controller_key IS NOT NULL
            AND domain <> parent_domain AND domain LIKE ('%.' || parent_domain))
    );
CREATE INDEX ON {{tables.dns_namespaces}} (parent_domain) WHERE deleted_at IS NULL;
