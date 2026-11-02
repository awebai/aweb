"""Mail attribution from canonical identity and its own thread-local key.

The key is evidence about messages inside this thread, never an additional
participant authority. No cross-thread or registry key equivalence is used.
"""


def mail_identity_sql(field: str, dids_parameter: str) -> str:
    """SQL over messages alias m; arguments are internal query fragments."""
    if field not in {'from_did', 'to_did'}:
        raise ValueError('Not a mail identity field')
    return f"""(
        m.{field} = ANY({dids_parameter}::text[])
        OR EXISTS (
            SELECT 1 FROM {{{{tables.conversation_participants}}}} own
            WHERE own.conversation_id = m.conversation_id
              AND own.did = ANY({dids_parameter}::text[])
              AND NULLIF(own.current_did_key, '') = m.{field}
        )
    )"""


def incoming_mail_sql(dids_parameter: str) -> str:
    """Require read authority before interpreting historical incoming keys."""
    return (
        f"({readable_mail_sql(dids_parameter)}"
        f" AND {mail_identity_sql('to_did', dids_parameter)}"
        f" AND NOT {mail_identity_sql('from_did', dids_parameter)})"
    )


def readable_mail_sql(dids_parameter: str) -> str:
    return f"""(
        (m.conversation_id IS NULL AND
            (m.from_did = ANY({dids_parameter}::text[]) OR m.to_did = ANY({dids_parameter}::text[])))
        OR EXISTS (
            SELECT 1 FROM {{{{tables.conversation_participants}}}} own
            WHERE own.conversation_id = m.conversation_id
              AND own.did = ANY({dids_parameter}::text[])
        )
    )"""
