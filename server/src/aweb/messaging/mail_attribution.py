"""Mail attribution from canonical identity and its own thread-local key.

The key is evidence about messages inside this thread, never an additional
participant authority. No cross-thread or registry key equivalence is used.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aweb.identity_auth_deps import MessagingAuth
    from aweb.messaging.participant_succession import MailSuccessionScope


def _incoming_mail_predicate(*, recipient: str, sender: str) -> str:
    """Incoming means addressed to this identity and not authored by it."""
    return f"({recipient} AND NOT {sender})"


@dataclass(frozen=True, kw_only=True)
class IncomingMailPredicate:
    sql: str
    arguments: tuple[object, ...]


def incoming_mail_snapshot_predicate(
    *,
    inbox_dids: list[str],
    scope: "MailSuccessionScope",
) -> IncomingMailPredicate:
    """Use exact thread evidence preloaded at stream establishment.

    Global And Local Identities (docs/identity-messaging-contract.md:123-136) keeps historical
    key evidence
    within its recorded thread. Snapshotting
    keeps event ticks from querying succession/participant tables again.
    """
    args: list[object] = [list(inbox_dids)]
    targets = ["m.to_did = ANY($1::text[])"]
    senders = ["m.from_did = ANY($1::text[])"]
    for dids, conversations in scope.identity_threads:
        did_param, conversation_param = len(args) + 1, len(args) + 2
        args.extend((list(dids), list(conversations)))
        for field, clauses in (("to_did", targets), ("from_did", senders)):
            clauses.append(
                f"(m.{field} = ANY(${did_param}::text[]) "
                f"AND m.conversation_id = ANY(${conversation_param}::uuid[]))"
            )
    return IncomingMailPredicate(
        sql=_incoming_mail_predicate(
            recipient=f"({' OR '.join(targets)})",
            sender=f"COALESCE(({' OR '.join(senders)}), FALSE)",
        ),
        arguments=tuple(args),
    )


def mail_identity_sql(field: str, dids_parameter: str) -> str:
    """SQL over messages alias m; arguments are internal query fragments."""
    if field not in {"from_did", "to_did"}:
        raise ValueError("Not a mail identity field")
    return f"""(
        m.{field} = ANY({dids_parameter}::text[])
        OR EXISTS (
            SELECT 1 FROM {{{{tables.conversation_participants}}}} own
            WHERE own.conversation_id = m.conversation_id
              AND own.did = ANY({dids_parameter}::text[])
              AND NULLIF(own.current_did_key, '') = m.{field}
        )
        OR EXISTS (
            SELECT 1 FROM {{{{tables.conversation_participant_successions}}}} history
            JOIN {{{{tables.local_human_successions}}}} succession USING (predecessor_did)
            JOIN {{{{tables.conversation_participants}}}} own
              ON own.conversation_id = history.conversation_id
             AND own.did = succession.successor_did
            WHERE history.conversation_id = m.conversation_id
              AND own.did = ANY({dids_parameter}::text[])
              AND m.{field} IN (succession.predecessor_did, succession.predecessor_did_key)
        )
    )"""


def incoming_mail_sql(dids_parameter: str) -> str:
    """Require read authority before interpreting historical incoming keys."""
    incoming = _incoming_mail_predicate(
        recipient=mail_identity_sql("to_did", dids_parameter),
        sender=mail_identity_sql("from_did", dids_parameter),
    )
    return f"({readable_mail_sql(dids_parameter)} AND {incoming})"


def readable_mail_sql(dids_parameter: str) -> str:
    """Build the shared participant-access predicate for ordinary and conversation mail."""
    return f"""(
        (m.conversation_id IS NULL AND
            (m.from_did = ANY({dids_parameter}::text[]) OR m.to_did = ANY({dids_parameter}::text[])))
        OR EXISTS (
            SELECT 1 FROM {{{{tables.conversation_participants}}}} own
            WHERE own.conversation_id = m.conversation_id
              AND own.did = ANY({dids_parameter}::text[])
        )
    )"""


async def has_authored_mail(*, db, auth: "MessagingAuth") -> bool:
    """Existence of authored mail within this authenticated reader's authority.

    The host supplies its already authorized scoped native manager/transaction.
    History comes only from the same canonical participant and thread-local
    attribution predicates as native mail reads, never a caller's predecessor
    list. This reads no content or keys and propagates database failures.
    """
    from aweb.identity_auth_deps import participant_dids

    return bool(
        await db.fetch_value(
            f"""SELECT EXISTS (
            SELECT 1 FROM {{{{tables.messages}}}} m
            WHERE {readable_mail_sql(dids_parameter="$1")}
              AND {mail_identity_sql(field="from_did", dids_parameter="$1")}
        )""",
            participant_dids(auth),
        )
    )
