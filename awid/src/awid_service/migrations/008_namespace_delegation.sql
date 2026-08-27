-- 008_namespace_delegation.sql
-- Portable parent-delegation history, rollover fences, and registry cutover state.

ALTER TABLE {{tables.dns_namespaces}}
    ADD COLUMN IF NOT EXISTS active_delegation_hash TEXT,
    ADD COLUMN IF NOT EXISTS last_verified_dns_ttl_seconds INTEGER;

CREATE TABLE IF NOT EXISTS {{tables.namespace_delegation_heads}} (
    child_domain TEXT PRIMARY KEY,
    parent_domain TEXT NOT NULL,
    head_sequence BIGINT NOT NULL CHECK (head_sequence > 0),
    head_hash TEXT NOT NULL UNIQUE CHECK (head_hash ~ '^sha256:[0-9a-f]{64}$'),
    head_operation TEXT NOT NULL CHECK (head_operation IN ('delegate', 'rotate', 'revoke')),
    head_controller_did TEXT NOT NULL,
    state_source_registry_id UUID,
    state_cutover_id UUID,
    state_generation BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (child_domain, parent_domain)
);

CREATE TABLE IF NOT EXISTS {{tables.namespace_delegation_entries}} (
    child_domain TEXT NOT NULL,
    parent_domain TEXT NOT NULL,
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    operation TEXT NOT NULL CHECK (operation IN ('delegate', 'rotate', 'revoke')),
    child_controller_did TEXT NOT NULL,
    previous_delegation_hash TEXT,
    canonical_payload BYTEA NOT NULL,
    entry_hash TEXT NOT NULL UNIQUE CHECK (entry_hash ~ '^sha256:[0-9a-f]{64}$'),
    state_source_registry_id UUID,
    state_cutover_id UUID,
    state_generation BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (child_domain, sequence),
    FOREIGN KEY (child_domain, parent_domain)
        REFERENCES {{tables.namespace_delegation_heads}} (child_domain, parent_domain),
    CHECK (
        (sequence = 1 AND previous_delegation_hash IS NULL)
        OR (sequence > 1 AND previous_delegation_hash ~ '^sha256:[0-9a-f]{64}$')
    )
);

CREATE TABLE IF NOT EXISTS {{tables.namespace_delegation_signatures}} (
    child_domain TEXT NOT NULL,
    sequence BIGINT NOT NULL,
    controller_did TEXT NOT NULL,
    signature TEXT NOT NULL,
    state_source_registry_id UUID,
    state_cutover_id UUID,
    state_generation BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (child_domain, sequence, controller_did),
    FOREIGN KEY (child_domain, sequence)
        REFERENCES {{tables.namespace_delegation_entries}} (child_domain, sequence)
);

CREATE TABLE IF NOT EXISTS {{tables.namespace_delegation_read_snapshots}} (
    snapshot_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    child_domain TEXT NOT NULL REFERENCES {{tables.namespace_delegation_heads}} (child_domain),
    head_sequence BIGINT NOT NULL,
    head_hash TEXT NOT NULL,
    original_after BIGINT NOT NULL CHECK (original_after >= 0),
    page_limit INTEGER CHECK (page_limit BETWEEN 1 AND 100),
    first_response_projection JSONB,
    expires_at TIMESTAMPTZ NOT NULL,
    invalidated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS {{tables.namespace_delegation_read_pages}} (
    token_hash TEXT PRIMARY KEY CHECK (token_hash ~ '^sha256:[0-9a-f]{64}$'),
    snapshot_id UUID NOT NULL REFERENCES {{tables.namespace_delegation_read_snapshots}} (snapshot_id),
    page_start_sequence BIGINT NOT NULL CHECK (page_start_sequence > 0),
    page_limit INTEGER NOT NULL CHECK (page_limit BETWEEN 1 AND 100),
    response_projection JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (snapshot_id, page_start_sequence, page_limit)
);

CREATE TABLE IF NOT EXISTS {{tables.namespace_controller_rollovers}} (
    rollover_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_domain TEXT NOT NULL,
    old_controller_did TEXT NOT NULL,
    new_controller_did TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'preparing', 'ready', 'overlap', 'recovery_overlap_unbounded',
        'overlap_risk_accepted', 'completed', 'canceled'
    )),
    recovery_mode TEXT NOT NULL DEFAULT 'none'
        CHECK (recovery_mode IN ('none', 'exact_dns', 'delegated')),
    recovery_assertion BYTEA,
    previous_dns_ttl_seconds INTEGER CHECK (previous_dns_ttl_seconds > 0),
    previous_dns_evidence JSONB,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cutover_at TIMESTAMPTZ,
    first_new_dns_observed_at TIMESTAMPTZ,
    complete_after TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_namespace_controller_rollovers_active
    ON {{tables.namespace_controller_rollovers}} (parent_domain)
    WHERE state NOT IN ('completed', 'canceled');

CREATE TABLE IF NOT EXISTS {{tables.namespace_controller_rollover_children}} (
    rollover_id UUID NOT NULL REFERENCES {{tables.namespace_controller_rollovers}} (rollover_id),
    child_domain TEXT NOT NULL,
    head_hash TEXT NOT NULL,
    canonical_payload BYTEA NOT NULL,
    new_signature TEXT,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    PRIMARY KEY (rollover_id, child_domain),
    UNIQUE (rollover_id, ordinal)
);

CREATE TABLE IF NOT EXISTS {{tables.namespace_controller_rollover_risk_acceptances}} (
    rollover_id UUID PRIMARY KEY REFERENCES {{tables.namespace_controller_rollovers}} (rollover_id),
    canonical_acceptance BYTEA NOT NULL,
    acceptance_hash TEXT NOT NULL UNIQUE,
    operator_id TEXT NOT NULL,
    reason_bytes BYTEA NOT NULL,
    reason_hash TEXT NOT NULL,
    dns_changed_at TIMESTAMPTZ NOT NULL,
    assumed_previous_ttl_seconds INTEGER NOT NULL CHECK (
        assumed_previous_ttl_seconds BETWEEN 1 AND 2147483647
    ),
    new_controller_signature TEXT NOT NULL,
    signature_timestamp TIMESTAMPTZ NOT NULL,
    live_dns_name TEXT NOT NULL,
    live_dns_answer_digest TEXT NOT NULL,
    live_dns_observed_at TIMESTAMPTZ NOT NULL,
    complete_after TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS {{tables.registry_state}} (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    registry_instance_id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    current_generation BIGINT NOT NULL DEFAULT 0 CHECK (current_generation >= 0)
);
INSERT INTO {{tables.registry_state}} (singleton) VALUES (TRUE)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS {{tables.registry_migration_cutovers}} (
    cutover_id UUID NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('source', 'destination')),
    source_registry_id UUID NOT NULL,
    destination_registry_id UUID NOT NULL,
    expected_destination_origin TEXT NOT NULL,
    root_domain TEXT NOT NULL,
    source_generation BIGINT NOT NULL CHECK (source_generation >= 0),
    snapshot_digest TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'preparing', 'frozen', 'importing', 'verified', 'dns_authorized',
        'overlap', 'completed', 'canceled'
    )),
    old_selection_evidence JSONB,
    destination_observation_payload BYTEA,
    destination_observation_hash TEXT,
    overlap_payload BYTEA,
    overlap_receipt_hash TEXT,
    overlap_started_at TIMESTAMPTZ,
    complete_after TIMESTAMPTZ,
    destination_complete_payload BYTEA,
    destination_complete_hash TEXT,
    destination_completed_at TIMESTAMPTZ,
    source_final_observation JSONB,
    dns_authorization_payload BYTEA,
    dns_authorization_hash TEXT,
    cancel_counts JSONB,
    cancel_digest TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (cutover_id, role)
);

CREATE TABLE IF NOT EXISTS {{tables.registry_migration_items}} (
    cutover_id UUID NOT NULL,
    role TEXT NOT NULL,
    kind TEXT NOT NULL,
    item_key TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    source_item_digest TEXT,
    semantic_digest TEXT,
    disposition TEXT CHECK (disposition IN ('inserted', 'reused')),
    owner_source_registry_id UUID,
    owner_cutover_id UUID,
    owner_generation BIGINT,
    source_registry_id UUID NOT NULL,
    source_generation BIGINT NOT NULL,
    imported BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (cutover_id, role, kind, item_key),
    FOREIGN KEY (cutover_id, role)
        REFERENCES {{tables.registry_migration_cutovers}} (cutover_id, role)
);


ALTER TABLE {{tables.did_aw_mappings}} ADD COLUMN IF NOT EXISTS state_source_registry_id UUID, ADD COLUMN IF NOT EXISTS state_cutover_id UUID, ADD COLUMN IF NOT EXISTS state_generation BIGINT NOT NULL DEFAULT 0;
ALTER TABLE {{tables.did_aw_log}} ADD COLUMN IF NOT EXISTS state_source_registry_id UUID, ADD COLUMN IF NOT EXISTS state_cutover_id UUID, ADD COLUMN IF NOT EXISTS state_generation BIGINT NOT NULL DEFAULT 0;
ALTER TABLE {{tables.dns_namespaces}} ADD COLUMN IF NOT EXISTS state_source_registry_id UUID, ADD COLUMN IF NOT EXISTS state_cutover_id UUID, ADD COLUMN IF NOT EXISTS state_generation BIGINT NOT NULL DEFAULT 0;
ALTER TABLE {{tables.public_addresses}} ADD COLUMN IF NOT EXISTS state_source_registry_id UUID, ADD COLUMN IF NOT EXISTS state_cutover_id UUID, ADD COLUMN IF NOT EXISTS state_generation BIGINT NOT NULL DEFAULT 0;
ALTER TABLE {{tables.replacement_announcements}} ADD COLUMN IF NOT EXISTS state_source_registry_id UUID, ADD COLUMN IF NOT EXISTS state_cutover_id UUID, ADD COLUMN IF NOT EXISTS state_generation BIGINT NOT NULL DEFAULT 0;
ALTER TABLE {{tables.teams}} ADD COLUMN IF NOT EXISTS state_source_registry_id UUID, ADD COLUMN IF NOT EXISTS state_cutover_id UUID, ADD COLUMN IF NOT EXISTS state_generation BIGINT NOT NULL DEFAULT 0;
ALTER TABLE {{tables.team_certificates}} ADD COLUMN IF NOT EXISTS state_source_registry_id UUID, ADD COLUMN IF NOT EXISTS state_cutover_id UUID, ADD COLUMN IF NOT EXISTS state_generation BIGINT NOT NULL DEFAULT 0;
ALTER TABLE {{tables.identity_encryption_keys}} ADD COLUMN IF NOT EXISTS state_source_registry_id UUID, ADD COLUMN IF NOT EXISTS state_cutover_id UUID, ADD COLUMN IF NOT EXISTS state_generation BIGINT NOT NULL DEFAULT 0;
ALTER TABLE {{tables.a2a_bridge_delegations}} ADD COLUMN IF NOT EXISTS state_source_registry_id UUID, ADD COLUMN IF NOT EXISTS state_cutover_id UUID, ADD COLUMN IF NOT EXISTS state_generation BIGINT NOT NULL DEFAULT 0;
ALTER TABLE {{tables.a2a_route_publications}} ADD COLUMN IF NOT EXISTS state_source_registry_id UUID, ADD COLUMN IF NOT EXISTS state_cutover_id UUID, ADD COLUMN IF NOT EXISTS state_generation BIGINT NOT NULL DEFAULT 0;

CREATE OR REPLACE FUNCTION {{tables.registry_state_mutation_guard}}()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    row_data JSONB := CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
    old_data JSONB := CASE WHEN TG_OP = 'UPDATE' THEN to_jsonb(OLD) ELSE NULL END;
    affected_domain TEXT;
    affected_did TEXT;
    old_domain TEXT;
    old_did TEXT;
    affected_item_kind TEXT;
    affected_item_key TEXT;
    old_item_kind TEXT;
    old_item_key TEXT;
    active_fence RECORD;
    local_registry UUID;
    generation BIGINT;
    import_mode TEXT := COALESCE(current_setting('awid.registry_import_mode', TRUE), 'false');
    import_cutover TEXT := current_setting('awid.registry_import_cutover_id', TRUE);
    import_source TEXT := current_setting('awid.registry_import_source_registry_id', TRUE);
    import_generation TEXT := current_setting('awid.registry_import_source_generation', TRUE);
    cleanup_mode TEXT := COALESCE(current_setting('awid.cancel_cleanup_mode', TRUE), 'false');
    cleanup_source TEXT := current_setting('awid.cancel_cleanup_source_registry_id', TRUE);
    cleanup_cutover TEXT := current_setting('awid.cancel_cleanup_cutover_id', TRUE);
    cleanup_generation TEXT := current_setting('awid.cancel_cleanup_source_generation', TRUE);
BEGIN
    IF TG_OP = 'DELETE' AND cleanup_mode = 'true'
       AND row_data->>'state_source_registry_id' = cleanup_source
       AND row_data->>'state_cutover_id' = cleanup_cutover
       AND row_data->>'state_generation' = cleanup_generation
       AND EXISTS (
           SELECT 1 FROM {{tables.registry_migration_cutovers}}
           WHERE cutover_id = cleanup_cutover::uuid AND role = 'destination'
             AND source_registry_id = cleanup_source::uuid
             AND source_generation = cleanup_generation::bigint
             AND state IN ('importing', 'verified')
       ) THEN
        RETURN OLD;
    END IF;

    IF TG_TABLE_NAME IN ('dns_namespaces', 'teams') THEN
        affected_domain := row_data->>'domain';
    ELSIF TG_TABLE_NAME IN ('namespace_delegation_heads', 'namespace_delegation_entries', 'namespace_delegation_signatures') THEN
        affected_domain := row_data->>'child_domain';
        IF TG_TABLE_NAME = 'namespace_delegation_heads' THEN
            affected_item_kind := 'delegation_head';
            affected_item_key := row_data->>'child_domain';
        ELSIF TG_TABLE_NAME = 'namespace_delegation_entries' THEN
            affected_item_kind := 'delegation_entry';
            affected_item_key := (row_data->>'child_domain') || ':' || (row_data->>'sequence');
        ELSE
            affected_item_kind := 'delegation_signature';
            affected_item_key := (row_data->>'child_domain') || ':' || (row_data->>'sequence') || ':' || (row_data->>'controller_did');
        END IF;
    ELSIF TG_TABLE_NAME = 'public_addresses' THEN
        SELECT domain INTO affected_domain FROM {{tables.dns_namespaces}}
        WHERE namespace_id = (row_data->>'namespace_id')::uuid;
        affected_did := row_data->>'did_aw';
    ELSIF TG_TABLE_NAME = 'replacement_announcements' THEN
        SELECT domain INTO affected_domain FROM {{tables.dns_namespaces}}
        WHERE namespace_id = (row_data->>'namespace_id')::uuid;
    ELSIF TG_TABLE_NAME = 'team_certificates' THEN
        SELECT domain INTO affected_domain FROM {{tables.teams}}
        WHERE team_uuid = (row_data->>'team_uuid')::uuid;
    ELSIF TG_TABLE_NAME IN ('did_aw_mappings', 'did_aw_log', 'identity_encryption_keys') THEN
        affected_did := row_data->>'did_aw';
    ELSIF TG_TABLE_NAME IN ('a2a_bridge_delegations', 'a2a_route_publications') THEN
        affected_domain := split_part(row_data->>'address', '/', 1);
        affected_did := COALESCE(row_data->>'did_aw', row_data->>'delegator_did_aw');
    END IF;

    IF old_data IS NOT NULL THEN
        IF TG_TABLE_NAME IN ('dns_namespaces', 'teams') THEN
            old_domain := old_data->>'domain';
        ELSIF TG_TABLE_NAME IN ('namespace_delegation_heads', 'namespace_delegation_entries', 'namespace_delegation_signatures') THEN
            old_domain := old_data->>'child_domain';
            IF TG_TABLE_NAME = 'namespace_delegation_heads' THEN
                old_item_kind := 'delegation_head';
                old_item_key := old_data->>'child_domain';
            ELSIF TG_TABLE_NAME = 'namespace_delegation_entries' THEN
                old_item_kind := 'delegation_entry';
                old_item_key := (old_data->>'child_domain') || ':' || (old_data->>'sequence');
            ELSE
                old_item_kind := 'delegation_signature';
                old_item_key := (old_data->>'child_domain') || ':' || (old_data->>'sequence') || ':' || (old_data->>'controller_did');
            END IF;
        ELSIF TG_TABLE_NAME = 'public_addresses' THEN
            SELECT domain INTO old_domain FROM {{tables.dns_namespaces}}
            WHERE namespace_id = (old_data->>'namespace_id')::uuid;
            old_did := old_data->>'did_aw';
        ELSIF TG_TABLE_NAME = 'replacement_announcements' THEN
            SELECT domain INTO old_domain FROM {{tables.dns_namespaces}}
            WHERE namespace_id = (old_data->>'namespace_id')::uuid;
        ELSIF TG_TABLE_NAME = 'team_certificates' THEN
            SELECT domain INTO old_domain FROM {{tables.teams}}
            WHERE team_uuid = (old_data->>'team_uuid')::uuid;
        ELSIF TG_TABLE_NAME IN ('did_aw_mappings', 'did_aw_log', 'identity_encryption_keys') THEN
            old_did := old_data->>'did_aw';
        ELSIF TG_TABLE_NAME IN ('a2a_bridge_delegations', 'a2a_route_publications') THEN
            old_domain := split_part(old_data->>'address', '/', 1);
            old_did := COALESCE(old_data->>'did_aw', old_data->>'delegator_did_aw');
        END IF;
    END IF;

    FOR active_fence IN
    SELECT c.*
    FROM {{tables.registry_migration_cutovers}} c
    WHERE c.state NOT IN ('completed', 'canceled')
      AND (
        (affected_domain IS NOT NULL AND
         (affected_domain = c.root_domain OR affected_domain LIKE ('%.' || c.root_domain)))
        OR
        (affected_did IS NOT NULL AND EXISTS (
            SELECT 1 FROM {{tables.registry_migration_items}} i
            WHERE i.cutover_id = c.cutover_id AND i.role = c.role
              AND i.kind = 'did' AND i.item_key = affected_did
        ))
        OR
        (affected_item_kind IS NOT NULL AND EXISTS (
            SELECT 1 FROM {{tables.registry_migration_items}} i
            WHERE i.cutover_id = c.cutover_id AND i.role = c.role
              AND (
                (i.kind = affected_item_kind AND i.item_key = affected_item_key)
                OR (i.kind = 'delegation_head' AND i.item_key = affected_domain)
              )
        ))
        OR (old_domain IS NOT NULL AND
            (old_domain = c.root_domain OR old_domain LIKE ('%.' || c.root_domain)))
        OR (old_did IS NOT NULL AND EXISTS (
            SELECT 1 FROM {{tables.registry_migration_items}} i
            WHERE i.cutover_id = c.cutover_id AND i.role = c.role
              AND i.kind = 'did' AND i.item_key = old_did
        ))
        OR (old_item_kind IS NOT NULL AND EXISTS (
            SELECT 1 FROM {{tables.registry_migration_items}} i
            WHERE i.cutover_id = c.cutover_id AND i.role = c.role
              AND (
                (i.kind = old_item_kind AND i.item_key = old_item_key)
                OR (i.kind = 'delegation_head' AND i.item_key = old_domain)
              )
        ))
      )
    ORDER BY c.created_at, c.cutover_id, c.role
    FOR UPDATE
    LOOP
        IF NOT (
            import_mode = 'true'
            AND active_fence.role = 'destination'
            AND active_fence.cutover_id::text = import_cutover
            AND active_fence.source_registry_id::text = import_source
            AND active_fence.source_generation::text = import_generation
            AND active_fence.state IN ('importing', 'verified')
        ) AND NOT (
            import_mode = 'true'
            AND active_fence.state IN ('dns_authorized', 'overlap')
            AND EXISTS (
                SELECT 1 FROM {{tables.registry_migration_items}} dependency
                WHERE dependency.cutover_id = import_cutover::uuid
                  AND dependency.role = 'destination'
                  AND dependency.disposition = 'reused'
                  AND (
                    dependency.owner_cutover_id = active_fence.cutover_id
                    OR (
                      dependency.owner_cutover_id IS NULL
                      AND EXISTS (
                        SELECT 1 FROM {{tables.registry_migration_items}} active_item
                        WHERE active_item.cutover_id = active_fence.cutover_id
                          AND active_item.role = active_fence.role
                          AND active_item.disposition = 'reused'
                          AND active_item.owner_cutover_id IS NULL
                          AND active_item.kind = dependency.kind
                          AND active_item.item_key = dependency.item_key
                      )
                    )
                  )
                  AND (
                    (affected_did IS NOT NULL AND dependency.kind = 'did'
                     AND dependency.item_key = affected_did)
                    OR (old_did IS NOT NULL AND dependency.kind = 'did'
                        AND dependency.item_key = old_did)
                    OR (affected_item_kind IS NOT NULL
                        AND dependency.kind = affected_item_kind
                        AND dependency.item_key = affected_item_key)
                    OR (old_item_kind IS NOT NULL
                        AND dependency.kind = old_item_kind
                        AND dependency.item_key = old_item_key)
                  )
            )
        ) THEN
            RAISE EXCEPTION 'registry_migration_fenced'
                USING ERRCODE = '55000';
        END IF;
    END LOOP;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;

    IF import_mode = 'true' THEN
        NEW.state_source_registry_id := import_source::uuid;
        NEW.state_cutover_id := import_cutover::uuid;
        NEW.state_generation := import_generation::bigint;
        RETURN NEW;
    END IF;

    generation := NULLIF(current_setting('awid.mutation_generation', TRUE), '')::bigint;
    local_registry := NULLIF(current_setting('awid.mutation_registry_id', TRUE), '')::uuid;
    IF generation IS NULL OR local_registry IS NULL THEN
        UPDATE {{tables.registry_state}}
        SET current_generation = current_generation + 1
        WHERE singleton = TRUE
        RETURNING registry_instance_id, current_generation INTO local_registry, generation;
        PERFORM set_config('awid.mutation_generation', generation::text, TRUE);
        PERFORM set_config('awid.mutation_registry_id', local_registry::text, TRUE);
    END IF;
    NEW.state_source_registry_id := local_registry;
    NEW.state_cutover_id := NULL;
    NEW.state_generation := generation;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_registry_state_mutation_guard ON {{tables.did_aw_mappings}};
CREATE TRIGGER trg_registry_state_mutation_guard
    BEFORE INSERT OR UPDATE OR DELETE ON {{tables.did_aw_mappings}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_state_mutation_guard}}();

DROP TRIGGER IF EXISTS trg_registry_state_mutation_guard ON {{tables.did_aw_log}};
CREATE TRIGGER trg_registry_state_mutation_guard
    BEFORE INSERT OR UPDATE OR DELETE ON {{tables.did_aw_log}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_state_mutation_guard}}();

DROP TRIGGER IF EXISTS trg_registry_state_mutation_guard ON {{tables.dns_namespaces}};
CREATE TRIGGER trg_registry_state_mutation_guard
    BEFORE INSERT OR UPDATE OR DELETE ON {{tables.dns_namespaces}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_state_mutation_guard}}();

DROP TRIGGER IF EXISTS trg_registry_state_mutation_guard ON {{tables.public_addresses}};
CREATE TRIGGER trg_registry_state_mutation_guard
    BEFORE INSERT OR UPDATE OR DELETE ON {{tables.public_addresses}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_state_mutation_guard}}();

DROP TRIGGER IF EXISTS trg_registry_state_mutation_guard ON {{tables.replacement_announcements}};
CREATE TRIGGER trg_registry_state_mutation_guard
    BEFORE INSERT OR UPDATE OR DELETE ON {{tables.replacement_announcements}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_state_mutation_guard}}();

DROP TRIGGER IF EXISTS trg_registry_state_mutation_guard ON {{tables.teams}};
CREATE TRIGGER trg_registry_state_mutation_guard
    BEFORE INSERT OR UPDATE OR DELETE ON {{tables.teams}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_state_mutation_guard}}();

DROP TRIGGER IF EXISTS trg_registry_state_mutation_guard ON {{tables.team_certificates}};
CREATE TRIGGER trg_registry_state_mutation_guard
    BEFORE INSERT OR UPDATE OR DELETE ON {{tables.team_certificates}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_state_mutation_guard}}();

DROP TRIGGER IF EXISTS trg_registry_state_mutation_guard ON {{tables.identity_encryption_keys}};
CREATE TRIGGER trg_registry_state_mutation_guard
    BEFORE INSERT OR UPDATE OR DELETE ON {{tables.identity_encryption_keys}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_state_mutation_guard}}();

DROP TRIGGER IF EXISTS trg_registry_state_mutation_guard ON {{tables.a2a_bridge_delegations}};
CREATE TRIGGER trg_registry_state_mutation_guard
    BEFORE INSERT OR UPDATE OR DELETE ON {{tables.a2a_bridge_delegations}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_state_mutation_guard}}();

DROP TRIGGER IF EXISTS trg_registry_state_mutation_guard ON {{tables.a2a_route_publications}};
CREATE TRIGGER trg_registry_state_mutation_guard
    BEFORE INSERT OR UPDATE OR DELETE ON {{tables.a2a_route_publications}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_state_mutation_guard}}();

DROP TRIGGER IF EXISTS trg_registry_state_mutation_guard ON {{tables.namespace_delegation_heads}};
CREATE TRIGGER trg_registry_state_mutation_guard
    BEFORE INSERT OR UPDATE OR DELETE ON {{tables.namespace_delegation_heads}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_state_mutation_guard}}();

DROP TRIGGER IF EXISTS trg_registry_state_mutation_guard ON {{tables.namespace_delegation_entries}};
CREATE TRIGGER trg_registry_state_mutation_guard
    BEFORE INSERT OR UPDATE OR DELETE ON {{tables.namespace_delegation_entries}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_state_mutation_guard}}();

DROP TRIGGER IF EXISTS trg_registry_state_mutation_guard ON {{tables.namespace_delegation_signatures}};
CREATE TRIGGER trg_registry_state_mutation_guard
    BEFORE INSERT OR UPDATE OR DELETE ON {{tables.namespace_delegation_signatures}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_state_mutation_guard}}();

CREATE OR REPLACE FUNCTION {{tables.namespace_delegation_append_only_guard}}()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    cleanup_mode TEXT := COALESCE(current_setting('awid.cancel_cleanup_mode', TRUE), 'false');
    cleanup_source TEXT := current_setting('awid.cancel_cleanup_source_registry_id', TRUE);
    cleanup_cutover TEXT := current_setting('awid.cancel_cleanup_cutover_id', TRUE);
    cleanup_generation TEXT := current_setting('awid.cancel_cleanup_source_generation', TRUE);
BEGIN
    IF cleanup_mode = 'true'
       AND OLD.state_source_registry_id::text = cleanup_source
       AND OLD.state_cutover_id::text = cleanup_cutover
       AND OLD.state_generation::text = cleanup_generation
       AND EXISTS (
           SELECT 1 FROM {{tables.registry_migration_cutovers}}
           WHERE cutover_id = cleanup_cutover::uuid
             AND role = 'destination'
             AND source_registry_id = cleanup_source::uuid
             AND source_generation = cleanup_generation::bigint
             AND state IN ('importing', 'verified')
       ) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'namespace delegation history is append-only'
        USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS trg_namespace_delegation_entries_append_only
    ON {{tables.namespace_delegation_entries}};
CREATE TRIGGER trg_namespace_delegation_entries_append_only
    BEFORE UPDATE OR DELETE ON {{tables.namespace_delegation_entries}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.namespace_delegation_append_only_guard}}();

DROP TRIGGER IF EXISTS trg_namespace_delegation_signatures_append_only
    ON {{tables.namespace_delegation_signatures}};
CREATE TRIGGER trg_namespace_delegation_signatures_append_only
    BEFORE UPDATE OR DELETE ON {{tables.namespace_delegation_signatures}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.namespace_delegation_append_only_guard}}();



CREATE TABLE IF NOT EXISTS {{tables.namespace_controller_rollover_read_pages}} (
    token_hash TEXT PRIMARY KEY CHECK (token_hash ~ '^sha256:[0-9a-f]{64}$'),
    rollover_id UUID NOT NULL REFERENCES {{tables.namespace_controller_rollovers}} (rollover_id),
    page_start_ordinal INTEGER NOT NULL CHECK (page_start_ordinal >= 0),
    page_limit INTEGER NOT NULL CHECK (page_limit BETWEEN 1 AND 100),
    response_projection JSONB,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (rollover_id, page_start_ordinal, page_limit)
);


CREATE UNIQUE INDEX IF NOT EXISTS idx_namespace_delegation_snapshot_request
    ON {{tables.namespace_delegation_read_snapshots}}
       (child_domain, head_sequence, head_hash, original_after, page_limit);


CREATE TABLE IF NOT EXISTS {{tables.namespace_controller_rollover_first_pages}} (
    rollover_id UUID NOT NULL REFERENCES {{tables.namespace_controller_rollovers}} (rollover_id),
    page_limit INTEGER NOT NULL CHECK (page_limit BETWEEN 1 AND 100),
    response_projection JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (rollover_id, page_limit)
);



-- provenance other than the exact still-cancelable destination import.

CREATE OR REPLACE FUNCTION {{tables.registry_cancel_cleanup_guard}}()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    cleanup_mode TEXT := COALESCE(current_setting('awid.cancel_cleanup_mode', TRUE), 'false');
    cleanup_source TEXT := current_setting('awid.cancel_cleanup_source_registry_id', TRUE);
    cleanup_cutover TEXT := current_setting('awid.cancel_cleanup_cutover_id', TRUE);
    cleanup_generation TEXT := current_setting('awid.cancel_cleanup_source_generation', TRUE);
BEGIN
    IF cleanup_mode IS DISTINCT FROM 'true' THEN
        RETURN OLD;
    END IF;
    IF OLD.state_source_registry_id::text = cleanup_source
       AND OLD.state_cutover_id::text = cleanup_cutover
       AND OLD.state_generation::text = cleanup_generation
       AND EXISTS (
           SELECT 1 FROM {{tables.registry_migration_cutovers}}
           WHERE cutover_id = cleanup_cutover::uuid
             AND role = 'destination'
             AND source_registry_id = cleanup_source::uuid
             AND source_generation = cleanup_generation::bigint
             AND state IN ('importing', 'verified')
       ) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'invalid_registry_cancel_cleanup_provenance'
        USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS trg_registry_cancel_cleanup_guard ON {{tables.did_aw_mappings}};
CREATE TRIGGER trg_registry_cancel_cleanup_guard
    BEFORE DELETE ON {{tables.did_aw_mappings}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_cancel_cleanup_guard}}();

DROP TRIGGER IF EXISTS trg_registry_cancel_cleanup_guard ON {{tables.did_aw_log}};
CREATE TRIGGER trg_registry_cancel_cleanup_guard
    BEFORE DELETE ON {{tables.did_aw_log}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_cancel_cleanup_guard}}();

DROP TRIGGER IF EXISTS trg_registry_cancel_cleanup_guard ON {{tables.dns_namespaces}};
CREATE TRIGGER trg_registry_cancel_cleanup_guard
    BEFORE DELETE ON {{tables.dns_namespaces}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_cancel_cleanup_guard}}();

DROP TRIGGER IF EXISTS trg_registry_cancel_cleanup_guard ON {{tables.public_addresses}};
CREATE TRIGGER trg_registry_cancel_cleanup_guard
    BEFORE DELETE ON {{tables.public_addresses}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_cancel_cleanup_guard}}();

DROP TRIGGER IF EXISTS trg_registry_cancel_cleanup_guard ON {{tables.replacement_announcements}};
CREATE TRIGGER trg_registry_cancel_cleanup_guard
    BEFORE DELETE ON {{tables.replacement_announcements}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_cancel_cleanup_guard}}();

DROP TRIGGER IF EXISTS trg_registry_cancel_cleanup_guard ON {{tables.teams}};
CREATE TRIGGER trg_registry_cancel_cleanup_guard
    BEFORE DELETE ON {{tables.teams}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_cancel_cleanup_guard}}();

DROP TRIGGER IF EXISTS trg_registry_cancel_cleanup_guard ON {{tables.team_certificates}};
CREATE TRIGGER trg_registry_cancel_cleanup_guard
    BEFORE DELETE ON {{tables.team_certificates}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_cancel_cleanup_guard}}();

DROP TRIGGER IF EXISTS trg_registry_cancel_cleanup_guard ON {{tables.identity_encryption_keys}};
CREATE TRIGGER trg_registry_cancel_cleanup_guard
    BEFORE DELETE ON {{tables.identity_encryption_keys}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_cancel_cleanup_guard}}();

DROP TRIGGER IF EXISTS trg_registry_cancel_cleanup_guard ON {{tables.a2a_bridge_delegations}};
CREATE TRIGGER trg_registry_cancel_cleanup_guard
    BEFORE DELETE ON {{tables.a2a_bridge_delegations}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_cancel_cleanup_guard}}();

DROP TRIGGER IF EXISTS trg_registry_cancel_cleanup_guard ON {{tables.a2a_route_publications}};
CREATE TRIGGER trg_registry_cancel_cleanup_guard
    BEFORE DELETE ON {{tables.a2a_route_publications}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_cancel_cleanup_guard}}();

DROP TRIGGER IF EXISTS trg_registry_cancel_cleanup_guard ON {{tables.namespace_delegation_heads}};
CREATE TRIGGER trg_registry_cancel_cleanup_guard
    BEFORE DELETE ON {{tables.namespace_delegation_heads}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_cancel_cleanup_guard}}();

DROP TRIGGER IF EXISTS trg_registry_cancel_cleanup_guard ON {{tables.namespace_delegation_entries}};
CREATE TRIGGER trg_registry_cancel_cleanup_guard
    BEFORE DELETE ON {{tables.namespace_delegation_entries}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_cancel_cleanup_guard}}();

DROP TRIGGER IF EXISTS trg_registry_cancel_cleanup_guard ON {{tables.namespace_delegation_signatures}};
CREATE TRIGGER trg_registry_cancel_cleanup_guard
    BEFORE DELETE ON {{tables.namespace_delegation_signatures}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.registry_cancel_cleanup_guard}}();
