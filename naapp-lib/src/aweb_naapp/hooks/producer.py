"""Producing hook events: enqueue in the effect's transaction, the
audit-critical gate, and the drain's resolver.

A server producer (core, or an app with an owner-activated production) calls
:meth:`HookProducer.enqueue` inside the transaction that applies the effect it
reports. The event is checked against the catalog, given its ``event_id`` once
and its ``producer.seq`` from a counter per (producer, team, hook), signed, and
stored on the outbox's ``hooks`` channel, so it commits with the effect or not
at all. The drain later materializes one delivery per registration owed the
event and hands each to :class:`aweb_naapp.hooks.transport.HookTransport`.

Registrations come from a :class:`Registrations` source: core resolves its own
bindings in process (S2); an app producer asks its team server (K3b). A view
older than :data:`VIEW_MAX_AGE` is never used: the gate refuses and the drain
leaves the event pending.

Inside a secrets dispatch, call the dispatch fence's ``prepare`` before
``enqueue``: the fence must take the transaction's first lock, and ``enqueue``
locks the producer's sequence row.

Rotating the producer key: drain the ``hooks`` channel first. Undelivered
events are signed with the old key, and a delivery is signed with the key
that signed its event, so deliveries left behind end rejected.
"""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol
from uuid import UUID

from awid.did import did_from_public_key
from nacl.signing import SigningKey
from pgdbm.core import TransactionManager

from aweb_naapp.hooks.catalog import Catalog, packaged_catalog
from aweb_naapp.hooks.envelope import CATALOG_ID, CATALOG_VERSION, sign, signing_bytes
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp.outbox import OutboxEvent, StoredEvent, Target, enqueue, mint_event_id
from aweb_naapp.outbox import next_sequence as _next_sequence

__all__ = [
    "HOOKS_CHANNEL",
    "OCCURRED_AT_SKEW",
    "VIEW_MAX_AGE",
    "HookProducer",
    "Registration",
    "RegistrationView",
    "Registrations",
    "ServerProducer",
    "hook_targets",
]

HOOKS_CHANNEL = "hooks"
# The resolution freshness bound: a view older than this is never used (§A4).
VIEW_MAX_AGE = timedelta(seconds=60)
# How far past this producer's clock an event may say it occurred. Small, so a
# registration still inside its active_from pad can never count as owed.
OCCURRED_AT_SKEW = timedelta(seconds=5)
_EVENT_TIME = "%Y-%m-%dT%H:%M:%S"

Clock = Callable[[], datetime]


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class Registration:
    """One active registration: where a hook's events are delivered, and from
    when. Events that occurred before ``active_from`` are never owed to it."""

    binding_id: str
    origin: str
    method: str
    path: str
    active_from: datetime


@dataclass(frozen=True)
class RegistrationView:
    """A team's active registrations for one hook, as read at ``as_of``.

    ``as_of`` is when this producer read the view, on its own clock: a source
    that copies a server's timestamp could make a view look fresh for longer,
    or stale at once, by the clock difference.
    """

    team_id: str
    hook: str
    as_of: datetime
    max_age: timedelta
    registrations: tuple[Registration, ...]

    def is_fresh(self, now: datetime) -> bool:
        """True while the view is no older than its own bound and VIEW_MAX_AGE."""
        return self.as_of <= now and now - self.as_of <= min(self.max_age, VIEW_MAX_AGE)

    def owed(self, occurred_at: datetime) -> tuple[Registration, ...]:
        """The registrations owed an event that occurred at ``occurred_at``."""
        return tuple(r for r in self.registrations if r.active_from <= occurred_at)


class Registrations(Protocol):
    async def view(self, team_id: str, hook: str) -> RegistrationView | None:
        """The team's current registrations for ``hook``, or None when no view
        can be had now. It may refresh over the network, so call it outside
        any transaction that holds an effect's locks."""
        ...


@dataclass(frozen=True)
class ServerProducer:
    """A server producer's identity in the envelope and its hook-event key.

    Build it with :meth:`core` or :meth:`app`. ``seed`` is the 32-byte Ed25519
    seed of the key registered for ``kid`` with the ``hook-event`` purpose.
    """

    kind: Literal["core", "app"]
    origin: str
    kid: str
    seed: bytes
    app_id: str | None = None
    installation_id: str | None = None
    generation: int | None = None

    @classmethod
    def core(cls, *, origin: str, kid: str, seed: bytes) -> ServerProducer:
        return cls("core", origin, kid, seed)

    @classmethod
    def app(
        cls,
        *,
        origin: str,
        app_id: str,
        installation_id: str,
        generation: int,
        kid: str,
        seed: bytes,
    ) -> ServerProducer:
        return cls("app", origin, kid, seed, app_id, installation_id, generation)

    def __repr__(self) -> str:
        return f"ServerProducer({self.name!r}, kid={self.kid!r})"

    @property
    def did_key(self) -> str:
        return did_from_public_key(bytes(SigningKey(self.seed).verify_key))

    @property
    def name(self) -> str:
        """The producer as a delivery credential names it."""
        return "core" if self.kind == "core" else f"app:{self.app_id}"

    def fields(self, seq: int) -> dict[str, Any]:
        fields: dict[str, Any] = {
            "kind": self.kind,
            "origin": self.origin,
            "kid": self.kid,
            "did_key": self.did_key,
            "seq": seq,
        }
        if self.kind == "app":
            fields.update(
                app_id=self.app_id,
                installation_id=self.installation_id,
                generation=self.generation,
            )
        return fields


class HookProducer:
    """Enqueues one server producer's hook events."""

    def __init__(
        self,
        producer: ServerProducer,
        *,
        catalog: Catalog | None = None,
        clock: Clock = _now,
    ) -> None:
        self.producer = producer
        self._catalog = catalog or packaged_catalog()
        self._clock = clock

    async def enqueue(
        self,
        tx: TransactionManager,
        *,
        hook: str,
        team_id: str,
        payload: Mapping[str, Any],
        actor: Mapping[str, Any],
        occurred_at: datetime,
        result_status: str,
        signed_trace_id: str | None = None,
        view: RegistrationView | None = None,
    ) -> UUID:
        """Store one event in ``tx``, the transaction that applies its effect,
        and return its ``event_id``.

        An audit-critical event (the catalog decides: every secret use, every
        widening governance act) is refused with ``audit_target_unavailable``
        unless ``view``, read before the transaction, is fresh and holds a
        registration owed the event. Nothing is written when it is refused,
        so the caller refuses its effect. Other events are never gated.

        ``signed_trace_id`` is a trace id the request carried under its
        signature; an absent or malformed one is replaced by a minted one.
        """
        self._catalog.validate(hook, payload)
        critical = self._catalog.is_audit_critical(hook, payload)
        now = self._clock()
        if occurred_at > now + OCCURRED_AT_SKEW:
            raise Refused("invalid_value", "occurred_at is in the future")
        if critical:
            self._gate(hook, team_id, occurred_at, now, view)
        event_id = mint_event_id()
        occurred = _event_time(occurred_at)
        envelope = {
            "v": 1,
            "type": "aweb.hook-event",
            "catalog": {"id": CATALOG_ID, "version": CATALOG_VERSION},
            "hook": hook,
            "event_id": str(event_id),
            "trace": _trace(signed_trace_id),
            "team_id": team_id,
            "producer": self.producer.fields(1),
            "actor": dict(actor),
            "occurred_at": occurred,
            "fired_at": max(occurred, _event_time(now)),
            "result_status": result_status,
            "payload": dict(payload),
        }
        # Check the whole event before the counter moves, so a refused event
        # never spends a seq: producer.seq stays gap-free even when the caller
        # catches the refusal and commits.
        signing_bytes(envelope)
        seq = await _next_sequence(tx, scope=f"{self.producer.name}:{hook}", team_id=team_id)
        envelope["producer"] = self.producer.fields(seq)
        signing, signature = sign(self.producer.seed, envelope)
        await enqueue(
            tx,
            OutboxEvent(
                event_id=event_id,
                team_id=team_id,
                kind=hook,
                occurred_at=occurred_at,
                payload=signing,
                signature=signature,
                critical=critical,
                producer={"seq": seq, "catalog_version": CATALOG_VERSION},
                channel=HOOKS_CHANNEL,
            ),
        )
        return event_id

    @staticmethod
    def _gate(
        hook: str,
        team_id: str,
        occurred_at: datetime,
        now: datetime,
        view: RegistrationView | None,
    ) -> None:
        if view is None:
            raise Refused("audit_target_unavailable", f"no registration view for {hook}")
        if view.team_id != team_id or view.hook != hook:
            raise Refused("audit_target_unavailable", f"the view is not {team_id}'s {hook}")
        if not view.is_fresh(now):
            raise Refused("audit_target_unavailable", f"the {hook} view is stale")
        if not view.owed(occurred_at):
            raise Refused("audit_target_unavailable", f"no registration is owed this {hook} event")


def hook_targets(
    registrations: Registrations, *, clock: Clock = _now
) -> Callable[[StoredEvent], Awaitable[Sequence[Target] | None]]:
    """The drain's resolver: one delivery per registration owed the event, or
    None, leaving the event pending, when no fresh view can be had."""

    async def resolve(event: StoredEvent) -> Sequence[Target] | None:
        view = await registrations.view(event.team_id, event.kind)
        if view is None or not view.is_fresh(clock()):
            return None
        return [
            Target(
                registration.binding_id,
                {
                    "binding_id": registration.binding_id,
                    "origin": registration.origin,
                    "method": registration.method,
                    "path": registration.path,
                },
            )
            for registration in view.owed(event.occurred_at)
        ]

    return resolve


def _event_time(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise Refused("invalid_value", "event times must be timezone-aware")
    moment = moment.astimezone(UTC)
    return f"{moment.strftime(_EVENT_TIME)}.{moment.microsecond // 1000:03d}Z"


def _trace(signed_trace_id: str | None) -> dict[str, str]:
    if (
        signed_trace_id is not None
        and len(signed_trace_id) == 32
        and all(c in "0123456789abcdef" for c in signed_trace_id)
        and signed_trace_id != "0" * 32
    ):
        return {"id": signed_trace_id, "origin": "signed_request"}
    minted = "0" * 32
    while minted == "0" * 32:
        minted = secrets.token_hex(16)
    return {"id": minted, "origin": "producer"}
