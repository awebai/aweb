-- Preserve stored chat history before removing runtime coverage repair.
-- Coordinator 912666c1 / 2a443a9b: include one-participant readable sessions;
-- zero-participant sessions retain their rows and have no participant reader.
-- No roster lookup, current membership, owner classification or route discovery
-- participates. Retention owner coverage therefore remains UNKNOWN.
WITH uncovered AS MATERIALIZED (
    SELECT s.session_id, s.team_id, s.created_at,
           creator.did AS created_by_did,
           GREATEST(s.created_at, s.wait_started_at,
                    (SELECT max(m.created_at) FROM {{tables.chat_messages}} m
                     WHERE m.session_id = s.session_id)) AS updated_at
    FROM {{tables.chat_sessions}} s
    JOIN LATERAL (
        SELECT p.did
        FROM {{tables.chat_participants}} p
        WHERE p.session_id = s.session_id
        ORDER BY CASE WHEN p.did = s.created_by THEN 0
                      WHEN p.alias = s.created_by THEN 1 ELSE 2 END,
                 p.joined_at, p.did
        LIMIT 1
    ) creator ON TRUE
    WHERE NOT EXISTS (
        SELECT 1 FROM {{tables.conversations}} c
        WHERE c.conversation_id = s.session_id
    )
    ORDER BY s.session_id
    FOR UPDATE OF s
), inserted AS (
    INSERT INTO {{tables.conversations}}
        (conversation_id, conversation_type, team_id, created_by_did,
         created_at, updated_at)
    SELECT session_id, 'chat', team_id, created_by_did, created_at, updated_at
    FROM uncovered
    ON CONFLICT (conversation_id) DO NOTHING
    RETURNING conversation_id, created_by_did
)
INSERT INTO {{tables.conversation_participants}}
    (conversation_id, participant_id, participant_kind, did, agent_id, alias,
     address, delivery_origin, current_did_key, transport_hint, role, joined_at,
     bridge_did, guest_subject, guest_opted_out_at)
SELECT c.conversation_id, p.participant_id, p.participant_kind,
       p.did, p.agent_id, p.alias, p.address, p.delivery_origin, p.current_did_key,
       CASE WHEN p.delivery_origin IS NULL THEN 'local'
            ELSE 'federation:' || p.delivery_origin END,
       CASE WHEN p.did = c.created_by_did THEN 'initiator' ELSE 'participant' END,
       p.joined_at, p.bridge_did, p.guest_subject, p.guest_opted_out_at
FROM inserted c
JOIN {{tables.chat_participants}} p ON p.session_id = c.conversation_id;
