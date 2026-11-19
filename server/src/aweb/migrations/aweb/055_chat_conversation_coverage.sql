-- Preserve stored chat history before removing runtime coverage repair.
-- Coordinator 4798efa1: copy valid snapshots exactly; leave zero-party and
-- blank-DID/alias snapshots unchanged and readable through direct history.
-- The existing active canonical pair wins; otherwise only the newest valid
-- uncovered pair becomes active. Older pairs are closed, retaining history.
-- No roster, owner classification or route discovery is used. Retention's
-- missing historical coverage remains UNKNOWN.
WITH snapshots AS MATERIALIZED (
    SELECT p.session_id, count(*) AS party_count,
           array_agg(p.did ORDER BY p.did) AS party_dids,
           bool_and(COALESCE(btrim(p.did), '') <> ''
                    AND COALESCE(btrim(p.alias), '') <> '') AS valid_parties
    FROM {{tables.chat_participants}} p
    GROUP BY p.session_id
), canonical_pairs AS MATERIALIZED (
    SELECT array_agg(p.did ORDER BY p.did) AS party_dids
    FROM {{tables.conversations}} c
    JOIN {{tables.conversation_participants}} p
      ON p.conversation_id = c.conversation_id
    WHERE c.conversation_type = 'chat' AND c.status = 'active'
      AND (c.expires_at IS NULL OR c.expires_at > CURRENT_TIMESTAMP)
    GROUP BY c.conversation_id
    HAVING count(*) = 2
), uncovered AS MATERIALIZED (
    SELECT s.session_id, s.team_id, s.created_at,
           snapshot.party_count, snapshot.party_dids,
           creator.did AS created_by_did,
           GREATEST(s.created_at, s.wait_started_at,
                    (SELECT max(m.created_at) FROM {{tables.chat_messages}} m
                     WHERE m.session_id = s.session_id)) AS updated_at
    FROM {{tables.chat_sessions}} s
    JOIN snapshots snapshot ON snapshot.session_id = s.session_id
    JOIN LATERAL (
        SELECT p.did
        FROM {{tables.chat_participants}} p
        WHERE p.session_id = s.session_id
        ORDER BY CASE WHEN p.did = s.created_by THEN 0
                      WHEN p.alias = s.created_by THEN 1 ELSE 2 END,
                 p.joined_at, p.did
        LIMIT 1
    ) creator ON TRUE
    WHERE snapshot.valid_parties AND NOT EXISTS (
        SELECT 1 FROM {{tables.conversations}} c
        WHERE c.conversation_id = s.session_id
    )
    ORDER BY s.session_id
    FOR UPDATE OF s
), ranked AS MATERIALIZED (
    SELECT u.*,
           row_number() OVER (
               PARTITION BY u.party_dids
               ORDER BY u.created_at DESC, u.session_id DESC
           ) AS pair_rank
    FROM uncovered u
), classified AS MATERIALIZED (
    SELECT r.*,
           r.party_count = 2 AND (
               r.pair_rank > 1 OR EXISTS (
                   SELECT 1 FROM canonical_pairs cp
                   WHERE cp.party_dids = r.party_dids
               )
           ) AS replaced_pair
    FROM ranked r
), inserted AS (
    INSERT INTO {{tables.conversations}}
        (conversation_id, conversation_type, team_id, created_by_did,
         created_at, updated_at, status, closed_at)
    SELECT session_id, 'chat', team_id, created_by_did, created_at, updated_at,
           CASE WHEN replaced_pair THEN 'closed' ELSE 'active' END,
           CASE WHEN replaced_pair THEN updated_at ELSE NULL END
    FROM classified
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
