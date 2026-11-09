"""logs' own owner acts (audit-substrate.md §B6): retention, erasure and legal holds.

Each act is the team owner's, verified and consumed in the transaction that
applies it, and recorded by the shared credential recorder as a
``post-governance-hook`` event that logs appends to its own chain in that same
transaction. A purge an act causes names that event (``logs.retention.set:<id>``,
``logs.erase:<id>``), so a reader resolves it from the chain to the signed act.

A widening act needs a current registered hook target, as every widening
governance act does, with one exception fixed here: a legal hold
(``SELF_RECORDED_ACTS``). A hold must take effect when the owner needs it, and
logs records it in its own chain atomically; it is still enqueued and owed to
every target (ruling ed36580d).

An active hold keeps retention and erasure from purging what it holds:
everything, or one actor's events. An actor is named by exactly its did:aw or
did:key, matched against the events' projected actor.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from aweb_naapp.hooks.owner_act import VerifiedOwnerAct
from aweb_naapp.hooks.owner_act_nonces import OwnerActVerifier
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp.runtime.credential_audit import CredentialAudit
from aweb_naapp.runtime.installation import InstallationFence
from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from aweb_logs import read_store
from aweb_logs.retention import HELD, lock_holds, purge, set_retention

# Fixed in reviewed code, never configuration: adding an act is a reviewed change.
SELF_RECORDED_ACTS = frozenset({"logs.legal_hold.set"})

GOVERNANCE_HOOK = "post-governance-hook"
_ACTOR_PREFIXES = ("did:aw:", "did:key:")


class GovernanceRefused(Exception):
    """The act names nothing logs can apply, or a hold forbids it. Nothing took
    effect and the act's nonce is unspent."""


class LogsGovernance:
    def __init__(
        self,
        db: AsyncDatabaseManager,
        *,
        fence: InstallationFence,
        verifier: OwnerActVerifier,
        recorder: CredentialAudit,
        logs_origin: str,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.db = db
        self.fence = fence
        self.verifier = verifier
        self.recorder = recorder
        self.logs_origin = logs_origin
        self.now = now

    async def set_retention(
        self,
        team_id: str,
        *,
        signing: bytes,
        signature: str,
        event_class: str,
        retention: str,
        retention_days: int | None = None,
    ) -> str:
        """Apply a ``logs.retention.set`` act; returns its governance event id.
        A retention shorter than the class had is narrowing; keeping events as
        long or longer is widening."""
        fields: dict[str, Any] = {"event_class": event_class, "retention": retention}
        if retention_days is not None:
            fields["retention_days"] = retention_days
        days = retention_days if retention == "days" else None

        async def effect(tx: TransactionManager, act: VerifiedOwnerAct) -> str:
            before = await tx.fetch_one(
                "SELECT retention_days FROM {{tables.retention_settings}}"
                " WHERE team_id = $1 AND event_class = $2 FOR UPDATE",
                team_id,
                event_class,
            )
            kept = None if before is None else before["retention_days"]
            shortened = days is not None and (kept is None or days < kept)
            event_id = await self._record(
                tx,
                act,
                {
                    "act": "logs.retention.shortened" if shortened else "logs.retention.lengthened",
                    "direction": "narrowing" if shortened else "widening",
                    **fields,
                },
            )
            await set_retention(tx, team_id, event_class, days=days, event_id=event_id)
            return event_id

        return await self._apply(team_id, signing, signature, fields, effect)

    async def erase(
        self,
        team_id: str,
        *,
        signing: bytes,
        signature: str,
        erase_scope: str,
        reason_code: str,
        actor_ref: str | None = None,
        chain_epoch: int | None = None,
        team_seq_first: int | None = None,
        team_seq_last: int | None = None,
    ) -> int:
        """Apply a ``logs.erase`` act: purge a range of the chain, or every event
        an actor produced, unless a hold holds any of them. logs' own governance
        entries are never erased. Returns how many events it purged."""
        fields: dict[str, Any] = {"erase_scope": erase_scope, "reason_code": reason_code}
        for name, value in (
            ("actor_ref", actor_ref),
            ("chain_epoch", chain_epoch),
            ("team_seq_first", team_seq_first),
            ("team_seq_last", team_seq_last),
        ):
            if value is not None:
                fields[name] = value
        if erase_scope == "actor":
            _require_actor(actor_ref)

        async def effect(tx: TransactionManager, act: VerifiedOwnerAct) -> int:
            await lock_holds(tx, team_id)
            # The actor of an event is known from its projection: bring them up to date.
            await read_store.project(tx, team_id)
            positions = await tx.fetch_all(
                "SELECT e.chain_epoch, e.team_seq, " + HELD + " AS held"
                " FROM {{tables.chain_events}} e"
                " LEFT JOIN {{tables.read_events}} r ON r.team_id = e.team_id"
                "   AND r.chain_epoch = e.chain_epoch AND r.team_seq = e.team_seq"
                " WHERE e.team_id = $1 AND e.purge_act IS NULL"
                " AND NOT (e.hook = $2 AND e.producer_origin = $3)"
                " AND CASE WHEN $4::text IS NOT NULL"
                "   THEN r.actor_did_aw = $4 OR r.actor_did_key = $4"
                "   ELSE e.chain_epoch = $5 AND e.team_seq BETWEEN $6 AND $7 END"
                " ORDER BY e.chain_epoch, e.team_seq",
                team_id,
                GOVERNANCE_HOOK,
                self.logs_origin,
                actor_ref if erase_scope == "actor" else None,
                chain_epoch,
                team_seq_first,
                team_seq_last,
            )
            if any(row["held"] for row in positions):
                raise GovernanceRefused("a legal hold holds events this erasure names")
            covered = [(row["chain_epoch"], row["team_seq"]) for row in positions]
            # An actor's erasure records its count, not its positions (the
            # catalog's erase_scope rule); each purged event's act names this
            # record, so verify reports exactly which events it covered.
            record = {"act": "logs.erased", "direction": "narrowing", **fields}
            record["erased_count"] = len(covered)
            event_id = await self._record(tx, act, record)
            return await purge(tx, team_id, covered, act=f"logs.erase:{event_id}")

        return await self._apply(team_id, signing, signature, fields, effect)

    async def set_hold(
        self,
        team_id: str,
        *,
        signing: bytes,
        signature: str,
        hold_id: str,
        hold_scope: str,
        reason_code: str,
        actor_ref: str | None = None,
    ) -> str:
        """Apply a ``logs.legal-hold.set`` act; returns its governance event id."""
        fields: dict[str, Any] = {
            "hold_id": hold_id,
            "hold_scope": hold_scope,
            "reason_code": reason_code,
        }
        if actor_ref is not None:
            fields["actor_ref"] = actor_ref
        if hold_scope == "actor":
            _require_actor(actor_ref)

        async def effect(tx: TransactionManager, act: VerifiedOwnerAct) -> str:
            await lock_holds(tx, team_id, exclusive=True)
            if await tx.fetch_value(
                "SELECT 1 FROM {{tables.legal_holds}} WHERE team_id = $1 AND hold_id = $2",
                team_id,
                hold_id,
            ):
                raise GovernanceRefused("this hold id was already set")
            event_id = await self._record(
                tx, act, {"act": "logs.legal_hold.set", "direction": "widening", **fields}
            )
            await tx.execute(
                "INSERT INTO {{tables.legal_holds}}"
                " (team_id, hold_id, hold_scope, actor_ref, set_event_id)"
                " VALUES ($1, $2, $3, $4, $5)",
                team_id,
                hold_id,
                hold_scope,
                actor_ref,
                event_id,
            )
            return event_id

        return await self._apply(team_id, signing, signature, fields, effect)

    async def release_hold(
        self, team_id: str, *, signing: bytes, signature: str, hold_id: str
    ) -> str:
        """Apply a ``logs.legal-hold.release`` act; returns its governance event id."""
        fields: dict[str, Any] = {"hold_id": hold_id}

        async def effect(tx: TransactionManager, act: VerifiedOwnerAct) -> str:
            await lock_holds(tx, team_id, exclusive=True)
            if not await tx.fetch_value(
                "SELECT 1 FROM {{tables.legal_holds}}"
                " WHERE team_id = $1 AND hold_id = $2 AND released_at IS NULL",
                team_id,
                hold_id,
            ):
                raise GovernanceRefused("no active hold has this id")
            event_id = await self._record(
                tx, act, {"act": "logs.legal_hold.released", "direction": "narrowing", **fields}
            )
            await tx.execute(
                "UPDATE {{tables.legal_holds}} SET released_at = NOW(), released_event_id = $3"
                " WHERE team_id = $1 AND hold_id = $2",
                team_id,
                hold_id,
                event_id,
            )
            return event_id

        return await self._apply(team_id, signing, signature, fields, effect)

    async def _apply[T](
        self,
        team_id: str,
        signing: bytes,
        signature: str,
        fields: dict[str, Any],
        effect: Callable[[TransactionManager, VerifiedOwnerAct], Awaitable[T]],
    ) -> T:
        admitted = (await self.fence.permit(team_id)).admitted
        expected = {
            "app_id": admitted.app_id,
            "installation_id": admitted.installation_id,
            **fields,
        }
        try:
            prepared = await self.verifier.prepare(signing, signature, team_id=team_id)
        except Refused:
            raise GovernanceRefused("the act is not the owner's") from None
        context = await self.recorder.prepare_owner_act(
            admitted, signing=signing, signature=signature
        )
        with self.recorder.prepared(context):
            async with self.db.transaction() as tx:
                await self.fence.check(tx, admitted)
                try:
                    act = await self.verifier.consume_in(tx, prepared, expected_subject=expected)
                except Refused:
                    raise GovernanceRefused("the act does not name this change") from None
                result = await effect(tx, act)
                await self.fence.check(tx, admitted)
        return result

    async def _record(
        self, tx: TransactionManager, act: VerifiedOwnerAct, payload: dict[str, Any]
    ) -> str:
        return str(await self.recorder.record_owner_act(tx, act, payload, occurred_at=self.now()))


def _require_actor(actor_ref: str | None) -> None:
    if actor_ref is None or not actor_ref.startswith(_ACTOR_PREFIXES):
        raise GovernanceRefused("an actor is named by its did:aw or did:key")
