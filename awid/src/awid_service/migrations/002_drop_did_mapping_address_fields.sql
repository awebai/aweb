-- 002_drop_did_mapping_address_fields.sql
-- Identity rows carry only did_aw <-> current_did_key plus timestamps.

ALTER TABLE {{tables.did_aw_mappings}}
    DROP COLUMN IF EXISTS server_url,
    DROP COLUMN IF EXISTS address,
    DROP COLUMN IF EXISTS handle;
