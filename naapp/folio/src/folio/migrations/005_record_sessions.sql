-- Records authority is captured only by authenticated new link mints. Legacy
-- rows deliberately have no canonical records identity or mutation grants.
ALTER TABLE {{tables.presentation_links}}
    ADD COLUMN records_creator_id TEXT,
    ADD COLUMN record_write_grants JSONB NOT NULL DEFAULT '{}'::jsonb;

-- This public audit identifier is separate from the header credential/hash.
ALTER TABLE {{tables.edit_sessions}}
    ADD COLUMN record_session_id UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE;
