-- 003_drop_public_address_current_key.sql
-- Address rows reference did_aw; the current key is resolved from did_aw_mappings.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM {{tables.public_addresses}} pa
        LEFT JOIN {{tables.did_aw_mappings}} m ON m.did_aw = pa.did_aw
        WHERE m.did_aw IS NULL
        LIMIT 1
    ) THEN
        RAISE EXCEPTION 'public_addresses contains did_aw values without did_aw_mappings rows';
    END IF;
END $$;

ALTER TABLE {{tables.public_addresses}}
    DROP COLUMN IF EXISTS current_did_key;

ALTER TABLE {{tables.public_addresses}}
    ADD CONSTRAINT public_addresses_did_aw_fkey
    FOREIGN KEY (did_aw) REFERENCES {{tables.did_aw_mappings}}(did_aw);
