-- Baseline query from 7012c772; retained for semantic/plan comparison.
SELECT
            s.session_id,
            s.team_id,
            array_agg(p2.alias ORDER BY p2.alias) AS participants,
            array_agg(p2.did ORDER BY p2.alias) AS participant_dids,
            array_agg(p2.address ORDER BY p2.alias) AS participant_addresses,
            CASE WHEN lm.content_mode = 'encrypted_v2' THEN '' ELSE lm.body END AS last_message,
            COALESCE(lm.content_mode, 'legacy_plaintext_v1') AS last_message_content_mode,
            COALESCE(lm.message_version, 1) AS last_message_version,
            lm.encrypted_envelope AS last_encrypted_envelope,
            lm.from_alias AS last_from,
            lm.from_address AS last_from_address,
            lm.from_did AS last_from_did,
            lm.from_agent_id AS last_from_agent_id,
            lm.hang_on AS last_message_hang_on,
            lm.created_at AS last_activity,
            COALESCE(unread.cnt, 0) AS unread_count,
            s.wait_seconds,
            s.wait_started_at,
            s.wait_started_by,
            COALESCE(wait_ext.total_seconds, 0) AS extended_wait_seconds
        FROM {{tables.chat_sessions}} s
        JOIN LATERAL (
            SELECT participant.did, participant.agent_id
            FROM {{tables.chat_participants}} participant
            WHERE participant.session_id = s.session_id
              AND (
                    participant.did = $1
                    OR (
                        $3::uuid IS NOT NULL
                        AND participant.agent_id = $3
                    )
                  )
            ORDER BY CASE WHEN participant.did = $1 THEN 0 ELSE 1 END
            LIMIT 1
        ) p ON TRUE
        JOIN {{tables.chat_participants}} p2
          ON p2.session_id = s.session_id
        LEFT JOIN LATERAL (
            SELECT body, content_mode, message_version, encrypted_envelope,
                   from_alias, from_address, from_did, from_agent_id, hang_on, created_at
            FROM {{tables.chat_messages}}
            WHERE session_id = s.session_id
            ORDER BY created_at DESC
            LIMIT 1
        ) lm ON TRUE
        LEFT JOIN LATERAL (
            SELECT COUNT(*)::int AS cnt
            FROM {{tables.chat_messages}} m
            WHERE m.session_id = s.session_id
              AND m.from_did <> p.did
              AND NOT EXISTS (
                  SELECT 1
                  FROM {{tables.chat_message_reads}} mr
                  WHERE mr.session_id = m.session_id
                    AND mr.did = p.did
                    AND mr.message_id = m.message_id
              )
        ) unread ON TRUE
        LEFT JOIN LATERAL (
            SELECT COALESCE(SUM($2::int), 0)::int AS total_seconds
            FROM {{tables.chat_messages}} m
            WHERE m.session_id = s.session_id
              AND m.hang_on = TRUE
              AND (s.wait_started_at IS NULL OR m.created_at >= s.wait_started_at)
        ) wait_ext ON TRUE
        GROUP BY
            s.session_id,
            s.team_id,
            lm.body,
            lm.content_mode,
            lm.message_version,
            lm.encrypted_envelope,
            lm.from_alias,
            lm.from_address,
            lm.from_did,
            lm.from_agent_id,
            lm.hang_on,
            lm.created_at,
            unread.cnt,
            s.wait_seconds,
            s.wait_started_at,
            s.wait_started_by,
            p.did,
            wait_ext.total_seconds
        HAVING COALESCE(unread.cnt, 0) > 0
            OR (
                s.wait_started_at IS NOT NULL
                AND s.wait_seconds IS NOT NULL
                AND (
                    $3::uuid IS NULL
                    OR s.wait_started_by IS NULL
                    OR s.wait_started_by <> $3
                )
                AND (
                    lm.from_did IS NULL
                    OR lm.from_did <> p.did
                    OR COALESCE(lm.hang_on, FALSE) = TRUE
                )
                AND s.wait_started_at
                    + ((s.wait_seconds + COALESCE(wait_ext.total_seconds, 0)) * INTERVAL '1 second')
                    > NOW()
            )
        ORDER BY lm.created_at DESC
