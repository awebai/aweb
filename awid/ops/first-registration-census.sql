-- AWID database, schema awid. Read-only aggregate; no identities leave SQL.
-- Compare the retained entry hash with canonical bytes of its stored fields.
-- The submitted state_hash itself is NOT retained separately (see companion report).
BEGIN READ ONLY;
WITH first_entries AS (
    SELECT *,
        '{"current_did_key":' || to_json(new_did_key)::text ||
        ',"did_aw":' || to_json(did_aw)::text || '}' AS canonical_state,
        '{"authorized_by":' || to_json(authorized_by)::text ||
        ',"did_aw":' || to_json(did_aw)::text ||
        ',"new_did_key":' || to_json(new_did_key)::text ||
        ',"operation":' || to_json(operation)::text ||
        ',"prev_entry_hash":' || COALESCE(to_json(prev_entry_hash)::text, 'null') ||
        ',"previous_did_key":' || COALESCE(to_json(previous_did_key)::text, 'null') ||
        ',"seq":' || seq::text ||
        ',"state_hash":' || to_json(state_hash)::text ||
        ',"timestamp":' || to_json(timestamp)::text || '}' AS canonical_entry
    FROM awid.did_aw_log
    WHERE seq = 1 AND operation = 'register_did'
), checked AS (
    SELECT state_hash, entry_hash,
           encode(sha256(convert_to(canonical_state, 'UTF8')), 'hex') AS computed_state_hash,
           encode(sha256(convert_to(canonical_entry, 'UTF8')), 'hex') AS reconstructed_entry_hash
    FROM first_entries
)
SELECT count(*) AS first_registration_entries,
       count(*) FILTER (WHERE state_hash IS DISTINCT FROM computed_state_hash)
           AS stored_state_hash_mismatch,
       count(*) FILTER (WHERE entry_hash IS DISTINCT FROM reconstructed_entry_hash)
           AS stored_fields_entry_hash_mismatch,
       count(*) FILTER (
           WHERE state_hash = computed_state_hash
             AND entry_hash IS DISTINCT FROM reconstructed_entry_hash
       ) AS computed_state_but_signed_entry_inconsistent_candidates
FROM checked;
ROLLBACK;
