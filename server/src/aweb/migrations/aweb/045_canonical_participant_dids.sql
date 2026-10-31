-- Canonical participant identity, authorized for the 1.27.43 cohort by
-- aweb 6a5658e3 (2026-10-31), following Athena 8cd10cab. Signing keys remain
-- unchanged in historical messages. Membership/actor IDs are only projections.
DO $$
DECLARE
    mapping RECORD;
BEGIN
    -- Freeze the verified mapping and participant/read state for this repair.
    LOCK TABLE {{tables.agents}}, {{tables.conversation_participants}},
        {{tables.chat_participants}}, {{tables.chat_message_reads}},
        {{tables.chat_read_receipts}} IN SHARE ROW EXCLUSIVE MODE;

    IF EXISTS (
        SELECT did_key FROM {{tables.agents}}
        WHERE did_key LIKE 'did:key:%' AND NULLIF(BTRIM(did_aw), '') IS NOT NULL
          AND did_aw_verified_key = did_key
        GROUP BY did_key HAVING COUNT(DISTINCT did_aw) > 1
    ) THEN
        RAISE EXCEPTION 'ambiguous verified participant key mapping';
    END IF;

    -- A key-named chat participant can have exact read receipts. Defer their
    -- FK while changing BOTH ends, then restore the original immediate FK.
    ALTER TABLE {{tables.chat_message_reads}}
        ALTER CONSTRAINT chat_message_reads_session_id_did_fkey
        DEFERRABLE INITIALLY DEFERRED;

    FOR mapping IN
        SELECT did_key, MIN(did_aw) AS did_aw FROM {{tables.agents}}
        WHERE did_key LIKE 'did:key:%' AND NULLIF(BTRIM(did_aw), '') IS NOT NULL
          AND did_aw_verified_key = did_key
        GROUP BY did_key ORDER BY did_key
    LOOP
        -- Retain the canonical row's ID, display metadata and route. Preserve
        -- earliest admission and initiator state, and fill only a missing actor.
        UPDATE {{tables.conversation_participants}} canonical
        SET joined_at = LEAST(canonical.joined_at, old.joined_at),
            agent_id = COALESCE(canonical.agent_id, old.agent_id),
            current_did_key = COALESCE(NULLIF(canonical.current_did_key, ''), old.did),
            role = CASE WHEN old.role = 'initiator' THEN 'initiator' ELSE canonical.role END
        FROM {{tables.conversation_participants}} old
        WHERE old.did = mapping.did_key AND canonical.did = mapping.did_aw
          AND canonical.conversation_id = old.conversation_id;
        DELETE FROM {{tables.conversation_participants}} old
        USING {{tables.conversation_participants}} canonical
        WHERE old.did = mapping.did_key AND canonical.did = mapping.did_aw
          AND canonical.conversation_id = old.conversation_id;
        UPDATE {{tables.conversation_participants}}
        SET did = mapping.did_aw, current_did_key = COALESCE(NULLIF(current_did_key, ''), did)
        WHERE did = mapping.did_key;

        UPDATE {{tables.chat_participants}} canonical
        SET joined_at = LEAST(canonical.joined_at, old.joined_at),
            agent_id = COALESCE(canonical.agent_id, old.agent_id),
            current_did_key = COALESCE(NULLIF(canonical.current_did_key, ''), old.did),
            left_at = CASE WHEN canonical.left_at IS NULL OR old.left_at IS NULL
                           THEN NULL ELSE GREATEST(canonical.left_at, old.left_at) END
        FROM {{tables.chat_participants}} old
        WHERE old.did = mapping.did_key AND canonical.did = mapping.did_aw
          AND canonical.session_id = old.session_id;

        -- Union exact acknowledgements, taking the latest receipt on overlap.
        UPDATE {{tables.chat_message_reads}} canonical
        SET read_at = GREATEST(canonical.read_at, old.read_at),
            agent_id = COALESCE(canonical.agent_id, old.agent_id)
        FROM {{tables.chat_message_reads}} old
        WHERE old.did = mapping.did_key AND canonical.did = mapping.did_aw
          AND canonical.session_id = old.session_id AND canonical.message_id = old.message_id;
        DELETE FROM {{tables.chat_message_reads}} old
        USING {{tables.chat_message_reads}} canonical
        WHERE old.did = mapping.did_key AND canonical.did = mapping.did_aw
          AND canonical.session_id = old.session_id AND canonical.message_id = old.message_id;
        UPDATE {{tables.chat_message_reads}}
        SET did = mapping.did_aw WHERE did = mapping.did_key;

        -- Legacy range cursors are preserved independently of exact receipts.
        -- Message chronology chooses the furthest cursor; receipt time chooses
        -- the most recent acknowledgement, even if those came from two rows.
        UPDATE {{tables.chat_read_receipts}} canonical
        SET last_read_at = GREATEST(canonical.last_read_at, old.last_read_at),
            agent_id = COALESCE(canonical.agent_id, old.agent_id),
            last_read_message_id = CASE
                WHEN canonical.last_read_message_id IS NULL THEN old.last_read_message_id
                WHEN old.last_read_message_id IS NULL THEN canonical.last_read_message_id
                WHEN (SELECT (created_at, message_id) FROM {{tables.chat_messages}}
                      WHERE message_id = old.last_read_message_id)
                   > (SELECT (created_at, message_id) FROM {{tables.chat_messages}}
                      WHERE message_id = canonical.last_read_message_id)
                THEN old.last_read_message_id ELSE canonical.last_read_message_id END
        FROM {{tables.chat_read_receipts}} old
        WHERE old.did = mapping.did_key AND canonical.did = mapping.did_aw
          AND canonical.session_id = old.session_id;
        DELETE FROM {{tables.chat_read_receipts}} old
        USING {{tables.chat_read_receipts}} canonical
        WHERE old.did = mapping.did_key AND canonical.did = mapping.did_aw
          AND canonical.session_id = old.session_id;
        UPDATE {{tables.chat_read_receipts}}
        SET did = mapping.did_aw WHERE did = mapping.did_key;

        -- Child exact-read rows now name the retained parent, so deleting a
        -- duplicate key parent cannot cascade away acknowledged messages.
        DELETE FROM {{tables.chat_participants}} old
        USING {{tables.chat_participants}} canonical
        WHERE old.did = mapping.did_key AND canonical.did = mapping.did_aw
          AND canonical.session_id = old.session_id;
        UPDATE {{tables.chat_participants}}
        SET did = mapping.did_aw, current_did_key = COALESCE(NULLIF(current_did_key, ''), did)
        WHERE did = mapping.did_key;
    END LOOP;

    SET CONSTRAINTS ALL IMMEDIATE;
    ALTER TABLE {{tables.chat_message_reads}}
        ALTER CONSTRAINT chat_message_reads_session_id_did_fkey
        NOT DEFERRABLE INITIALLY IMMEDIATE;

    IF EXISTS (
        SELECT 1 FROM (
            SELECT did FROM {{tables.conversation_participants}}
            UNION ALL SELECT did FROM {{tables.chat_participants}}
        ) participant
        JOIN {{tables.agents}} agent ON agent.did_key = participant.did
        WHERE NULLIF(BTRIM(agent.did_aw), '') IS NOT NULL
          AND agent.did_aw_verified_key = agent.did_key
    ) THEN
        RAISE EXCEPTION 'canonical participant normalization incomplete';
    END IF;
END
$$;
