-- 003_identity_delivery_origin.sql
-- Global/local identity routing: canonical mail/chat delivery origin belongs to
-- the global did:aw identity, not to namespace/address aliases.

ALTER TABLE {{tables.did_aw_mappings}}
    ADD COLUMN IF NOT EXISTS delivery_origin TEXT;
