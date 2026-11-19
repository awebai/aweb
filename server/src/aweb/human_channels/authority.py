"""Actor bindings a host locks on its own transaction; never inferred from wire data.

Hosts own their identity/custody/access authority and must not look up OSS
private tables. lock_native_actors rechecks the OSS actor projections on the
host's open transaction and performs no network I/O.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import UUID

from pgdbm import TransactionManager

from aweb.identity_binding import verified_projection

from .contract import ContractError

if TYPE_CHECKING:
    from asyncpg import Connection


@dataclass(frozen=True)
class NativeMessagingSubject:
    """Exact candidate selected by OSS, not an external platform account.

    A provider must independently establish the binding and current key; the
    candidate is lookup input, not proof of identity/custody/access.
    """

    principal: str
    signing_key_id: str
    actor_id: str | None
    team_id: str | None


async def lock_native_actors(
    db,
    transaction: Connection,
    expected: Sequence[NativeMessagingSubject],
) -> tuple[NativeMessagingSubject, ...]:
    """Lock/recheck exact OSS actor projections on the host's open transaction.

    All references need actor/team IDs. Locks are acquired in actor-ID order
    and last through the caller's outer commit/rollback. Return immutable,
    active/non-deleted bindings in input order, or refuse the entire operation.
    This neither opens nor commits a transaction and performs no network I/O.
    Global facts freeze only OSS projections, not AWID; the host still supplies
    independent registry, custody, ownership and action authorization evidence.
    """
    if not transaction.is_in_transaction():
        raise ContractError("invalid", "open actor-lock transaction")
    subjects = tuple(expected)
    if not subjects:
        raise ContractError("invalid", "actor bindings")
    actor_ids = []
    for subject in subjects:
        if not isinstance(subject, NativeMessagingSubject) or not all(
            isinstance(value, str) and value
            for value in (subject.actor_id, subject.team_id, subject.principal, subject.signing_key_id)
        ):
            raise ContractError("invalid", "actor binding")
        try:
            actor_ids.append(UUID(subject.actor_id))
        except ValueError as error:
            raise ContractError("invalid", "actor ID") from error
    manager = TransactionManager(transaction, db.get_manager("aweb"))
    rows = await manager.fetch_all(
        """SELECT agent_id, team_id, did_key, did_aw, did_aw_verified_key, status, deleted_at
           FROM {{tables.agents}} WHERE agent_id=ANY($1::uuid[])
           ORDER BY agent_id FOR UPDATE""",
        sorted(set(actor_ids)),
    )
    by_id = {row["agent_id"]: verified_projection(row) for row in rows}
    facts = []
    for subject, actor_id in zip(subjects, actor_ids):
        row = by_id.get(actor_id)
        if row is None or row["status"] != "active" or row["deleted_at"] is not None:
            raise ContractError("forbidden", "inactive actor")
        current = NativeMessagingSubject(
            row["did_aw"] or row["did_key"], row["did_key"], str(row["agent_id"]), row["team_id"]
        )
        if (current.principal, current.signing_key_id, current.team_id) != (
            subject.principal, subject.signing_key_id, subject.team_id
        ):
            raise ContractError("stale", "current actor binding")
        facts.append(current)
    return tuple(facts)
