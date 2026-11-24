"""Read one participant's ordered conversation page before enriching it."""

from aweb.messaging.mail_attribution import incoming_mail_sql


def _chat_participants(session_id: str) -> str:
    # Both the optional peer filter and the displayed participants use the
    # canonical projection, falling back only for chats without coverage.
    return f"""
        WITH canonical AS (
            SELECT cp.did, cp.alias, cp.address
            FROM {{{{tables.conversations}}}} c
            JOIN {{{{tables.conversation_participants}}}} cp USING (conversation_id)
            WHERE c.conversation_id = {session_id} AND c.conversation_type = 'chat'
        )
        SELECT did, alias, address FROM canonical
        UNION ALL
        SELECT did, alias, address FROM {{{{tables.chat_participants}}}}
        WHERE session_id = {session_id} AND NOT EXISTS (SELECT 1 FROM canonical)
    """


# Args: participant DIDs, peer DID/address, cursor timestamp/key, limit, type.
# Page keys retain the released textual tie-break, including legacy mail.
CONVERSATION_PAGE_SQL = f"""
WITH candidates AS (
    SELECT owned.conversation_id AS row_id, 'mail' AS kind,
           'mail:' || owned.conversation_id::text AS cursor_key, latest.created_at
    FROM (
        SELECT DISTINCT cp.conversation_id
        FROM {{{{tables.conversation_participants}}}} cp
        WHERE cp.did = ANY($1::text[])
          AND ($7::text IS NULL OR $7::text = 'mail')
          AND (($2::text IS NULL AND $3::text IS NULL) OR EXISTS (
              SELECT 1 FROM {{{{tables.conversation_participants}}}} peer
              WHERE peer.conversation_id = cp.conversation_id
                AND (peer.did = $2::text OR peer.address = $3::text)
          ))
    ) owned
    JOIN LATERAL (
        SELECT m.created_at FROM {{{{tables.messages}}}} m
        WHERE m.conversation_id = owned.conversation_id
        ORDER BY m.created_at DESC LIMIT 1
    ) latest ON TRUE

    UNION ALL
    SELECT m.message_id, 'legacy', 'mail:legacy:' || m.message_id::text, m.created_at
    FROM {{{{tables.messages}}}} m
    WHERE ($7::text IS NULL OR $7::text = 'mail')
      AND $2::text IS NULL AND $3::text IS NULL AND m.conversation_id IS NULL
      AND (m.from_did = ANY($1::text[]) OR m.to_did = ANY($1::text[]))

    UNION ALL
    SELECT own.session_id, 'chat', 'chat:' || own.session_id::text, latest.created_at
    FROM {{{{tables.chat_participants}}}} own
    JOIN LATERAL (
        SELECT cm.created_at FROM {{{{tables.chat_messages}}}} cm
        WHERE cm.session_id = own.session_id
        ORDER BY cm.created_at DESC LIMIT 1
    ) latest ON TRUE
    WHERE ($7::text IS NULL OR $7::text = 'chat') AND own.did = ($1::text[])[1]
      AND (($2::text IS NULL AND $3::text IS NULL) OR EXISTS (
          SELECT 1 FROM ({_chat_participants('own.session_id')}) peer
          WHERE peer.did = $2::text OR peer.address = $3::text
      ))
), boundary AS MATERIALIZED (
    SELECT row_id, kind, cursor_key, created_at
    FROM candidates
    WHERE $4::timestamptz IS NULL OR created_at < $4::timestamptz
       OR (created_at = $4::timestamptz AND cursor_key < $5::text)
    ORDER BY created_at DESC, cursor_key DESC
    LIMIT ($6::int + 1)
), page AS MATERIALIZED (
    SELECT row_id, kind, cursor_key, created_at
    FROM boundary ORDER BY created_at DESC, cursor_key DESC LIMIT $6::int
)
SELECT p.*, (SELECT count(*) > $6::int FROM boundary) AS has_more,
       mail.message_id, mail.first_message_id, mail.status, mail.subject, mail.title,
       mail.from_address, mail.to_alias, mail.to_did,
       COALESCE(mail.from_alias, chat.from_alias) AS from_alias,
       COALESCE(mail.from_did, chat.from_did) AS from_did,
       COALESCE(mail.preview, chat.preview) AS preview,
       COALESCE(mail.unread_count, chat.unread_count) AS unread_count,
       COALESCE(mail.participants, chat.participants) AS participants,
       chat.participant_details, chat.participant_dids, chat.participant_addresses
FROM page p
LEFT JOIN LATERAL (
    -- Materialize only the selected thread's narrow history. Fetch the first
    -- subject and 100-character preview separately through message IDs.
    WITH history AS MATERIALIZED (
        SELECT m.message_id, m.created_at, m.from_alias, m.from_did, m.to_alias, m.to_did,
               m.read_at, {incoming_mail_sql('$1')} AS incoming
        FROM {{{{tables.messages}}}} m
        WHERE p.kind = 'mail' AND m.conversation_id = p.row_id
        UNION ALL
        SELECT m.message_id, m.created_at, m.from_alias, m.from_did, m.to_alias, m.to_did,
               m.read_at, {incoming_mail_sql('$1')} AS incoming
        FROM {{{{tables.messages}}}} m
        WHERE p.kind = 'legacy' AND m.message_id = p.row_id
    )
    SELECT newest.message_id, newest.from_alias, newest.from_did, newest.from_address,
           newest.to_alias, newest.to_did, newest.subject,
           LEFT(COALESCE(newest.body, ''), 100) AS preview,
           first.message_id AS first_message_id,
           CASE WHEN first.content_mode = 'encrypted_v2' THEN '' ELSE first.subject END AS title,
           (SELECT count(*)::int FROM history WHERE incoming AND read_at IS NULL) AS unread_count,
           CASE WHEN c.status = 'active' AND c.expires_at <= CURRENT_TIMESTAMP
                THEN 'expired' ELSE c.status END AS status,
           labels.participants
    FROM (
        SELECT message_id FROM history ORDER BY created_at DESC, message_id DESC LIMIT 1
    ) last_id
    JOIN {{{{tables.messages}}}} newest ON newest.message_id = last_id.message_id
    JOIN {{{{tables.messages}}}} first ON first.message_id = (
        SELECT message_id FROM history ORDER BY created_at, message_id LIMIT 1
    )
    LEFT JOIN {{{{tables.conversations}}}} c ON c.conversation_id = newest.conversation_id
    LEFT JOIN LATERAL (
        SELECT array_agg(ranked.label ORDER BY ranked.first_ord) AS participants
        FROM (
            SELECT labelled.label, MIN(labelled.ord) AS first_ord
            FROM (
                SELECT COALESCE(NULLIF(BTRIM(COALESCE(pair.alias, '')), ''),
                                BTRIM(COALESCE(pair.did, ''))) AS label,
                       ROW_NUMBER() OVER (ORDER BY h.created_at DESC, h.message_id DESC)
                           * 2 + pair.pos AS ord
                FROM history h
                CROSS JOIN LATERAL (
                    VALUES (h.from_alias, h.from_did, 0), (h.to_alias, h.to_did, 1)
                ) pair(alias, did, pos)
            ) labelled
            WHERE labelled.label <> ''
            GROUP BY labelled.label
        ) ranked
    ) labels ON TRUE
) mail ON p.kind IN ('mail', 'legacy')
LEFT JOIN LATERAL (
    SELECT lm.from_alias, lm.from_did, LEFT(COALESCE(lm.body, ''), 100) AS preview,
           (SELECT count(*)::int FROM {{{{tables.chat_messages}}}} cm
            WHERE cm.session_id = p.row_id AND cm.from_did <> own.did
              AND cm.from_did IS DISTINCT FROM own.current_did_key
              AND NOT EXISTS (
                  SELECT 1 FROM {{{{tables.chat_message_reads}}}} mr
                  WHERE mr.session_id = cm.session_id AND mr.did = own.did
                    AND mr.message_id = cm.message_id
              )) AS unread_count,
           labels.participant_details, labels.participants,
           labels.participant_dids, labels.participant_addresses
    FROM {{{{tables.chat_participants}}}} own
    JOIN LATERAL (
        SELECT message_id FROM {{{{tables.chat_messages}}}}
        WHERE session_id = p.row_id ORDER BY created_at DESC, message_id DESC LIMIT 1
    ) last_id ON TRUE
    JOIN {{{{tables.chat_messages}}}} lm ON lm.message_id = last_id.message_id
    CROSS JOIN LATERAL (
        SELECT jsonb_agg(jsonb_build_object('did', cp.did, 'alias', cp.alias, 'address', cp.address)
                         ORDER BY cp.alias, cp.did) AS participant_details,
               array_agg(cp.alias ORDER BY cp.alias, cp.did) AS participants,
               array_agg(cp.did ORDER BY cp.alias, cp.did) AS participant_dids,
               array_agg(cp.address ORDER BY cp.alias, cp.did) AS participant_addresses
        FROM ({_chat_participants('p.row_id')}) cp
    ) labels
    WHERE p.kind = 'chat' AND own.session_id = p.row_id AND own.did = ($1::text[])[1]
) chat ON p.kind = 'chat'
ORDER BY p.created_at DESC, p.cursor_key DESC
"""
