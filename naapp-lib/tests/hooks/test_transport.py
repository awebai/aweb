"""Delivering hook events through the egress guard, against a real TLS target
that verifies every delivery the way a consumer does, with real signatures and
real PostgreSQL.

The guard refuses loopback, so the target listens on this host's own
non-loopback address. Reaching it is a self-hosted operator's choice: the
transport is given that address's exact CIDR and the egress allows internal
destinations. A hosted deployment allows neither, and is refused before any
connection.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from pathlib import Path

import pytest
from aweb_naapp_testing.network import (
    DnsServer,
    Seen,
    TlsServer,
    local_address,
    make_certificates,
)
from pgdbm import AsyncDatabaseManager

from aweb_naapp.egress import (
    AddressPolicy,
    DnsResolver,
    Egress,
    InternalDestinations,
)
from aweb_naapp.hooks.delivery import ReceiveOptions, verify_delivery
from aweb_naapp.hooks.producer import (
    HOOKS_CHANNEL,
    HookProducer,
    Registration,
    RegistrationView,
    ServerProducer,
    hook_targets,
)
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp.hooks.transport import HookTransport
from aweb_naapp.outbox import (
    Acked,
    Cancelled,
    Conflict,
    Permanent,
    Retryable,
    RetryPolicy,
    StoredEvent,
    Target,
    apply_outbox_migrations,
    drain,
    outbox_status,
)

NAME = "logs.hooks.test"
TEAM = "backend:example.com"
SEED = bytes(range(32))
BINDING = "6f9619ff-8b86-4011-b42d-00c04fc964ff"
PATH = "/hooks/ingest"
SECRET_USE = {
    "action": "refused",
    "op_kind": "broker",
    "refusal_code": "grant_missing",
    "target_method": "POST",
    "target_host": "api.example.com",
    "target_port": 443,
    "target_path_template": "/v1/charges",
    "request_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
}
SYSTEM = {"authority_mode": "system", "attestations": []}
POLICY = RetryPolicy(stalled_after=timedelta(hours=1), base_seconds=0, rejected_after_attempts=3)
_CHILD = Path(__file__).with_name("hook_drain_child.py")


@dataclass
class Views:
    """The registration source the producer, drain and transport read."""

    current: RegistrationView | None = None

    async def view(self, team_id: str, hook: str) -> RegistrationView | None:
        return self.current


@dataclass
class Target_:
    """A real TLS hook target that verifies each delivery, then answers with
    the next scripted reply (the last one repeats)."""

    tls: TlsServer
    dns: DnsServer
    host: str
    ca_file: Path
    replies: list[tuple[int, dict | None]] = field(default_factory=lambda: [(200, None)])
    verified: list[str] = field(default_factory=list)
    refusals: list[str] = field(default_factory=list)

    @property
    def origin(self) -> str:
        return f"https://{NAME}:{self.tls.port}"

    def registration(self, binding_id: str = BINDING) -> Registration:
        return Registration(
            binding_id=binding_id,
            origin=self.origin,
            method="POST",
            path=PATH,
            active_from=datetime.now(UTC) - timedelta(minutes=5),
        )

    def view(self, *registrations: Registration, age: timedelta = timedelta()) -> RegistrationView:
        return RegistrationView(
            team_id=TEAM,
            hook="post-secret-use-hook",
            as_of=datetime.now(UTC) - age,
            max_age=timedelta(seconds=60),
            registrations=registrations or (self.registration(),),
        )

    def egress(self, policy: AddressPolicy | None = None) -> Egress:
        return Egress(
            addresses=policy or AddressPolicy(internal_destinations=InternalDestinations.ALLOWED),
            resolver=DnsResolver(nameservers=["127.0.0.1"], port=self.dns.port),
            user_agent="hooks-test/1",
            ca_file=self.ca_file,
        )

    async def answer(self, seen: Seen) -> tuple[int, bytes, list[tuple[str, str]]]:
        method, target, _ = seen.request_line.split(" ")
        try:
            received = verify_delivery(
                method,
                target,
                dict(seen.headers),
                seen.body,
                ReceiveOptions(audience=self.origin, binding_id=BINDING, now=datetime.now(UTC)),
            )
        except Refused as refused:
            self.refusals.append(refused.code)
            return 401, b'{"error": "unauthorized"}', []
        self.verified.append(received.envelope.event_id)
        status, body = self.replies[0] if len(self.replies) == 1 else self.replies.pop(0)
        if body is not None and "event_id" in body:
            body = {**body, "event_id": received.envelope.event_id}
        return status, json.dumps(body or {}).encode(), [("Content-Type", "application/json")]


@pytest.fixture
async def target(tmp_path: Path) -> AsyncIterator[Target_]:
    host = local_address()
    certificates = make_certificates(tmp_path, [NAME], [host])
    dns = DnsServer(records={(NAME, "A"): [host]})
    tls = TlsServer(certificates, host)
    hooked = Target_(tls, dns, host, certificates.ca_file)
    tls.respond = hooked.answer
    await dns.start()
    await tls.start()
    try:
        yield hooked
    finally:
        dns.close()
        await tls.close()


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="naapp_hook_transport")
    await apply_outbox_migrations(database)
    yield database


def producer() -> HookProducer:
    return HookProducer(
        ServerProducer.app(
            origin="https://secrets.example.com",
            app_id="secrets",
            installation_id="1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b",
            generation=2,
            kid="hook-2026-10",
            seed=SEED,
        )
    )


def transport(target: Target_, views: Views, **options) -> HookTransport:
    return HookTransport(
        seed=SEED,
        egress=options.pop("egress", None) or target.egress(),
        registrations=views,
        internal_cidr=options.pop("internal_cidr", ip_network(f"{target.host}/32")),
    )


async def enqueue_secret_use(db, views: Views) -> str:
    async with db.transaction() as tx:
        event_id = await producer().enqueue(
            tx,
            hook="post-secret-use-hook",
            team_id=TEAM,
            payload=SECRET_USE,
            actor=SYSTEM,
            occurred_at=datetime.now(UTC),
            result_status="denied",
            view=views.current,
        )
    return str(event_id)


async def stored_event(db) -> StoredEvent:
    row = await db.fetch_one(
        "SELECT event_id, team_id, kind, occurred_at, payload, signature, critical, producer,"
        " channel FROM {{tables.outbox_events}}"
    )
    return StoredEvent(
        event_id=row["event_id"],
        team_id=row["team_id"],
        kind=row["kind"],
        occurred_at=row["occurred_at"],
        payload=bytes(row["payload"]),
        signature=row["signature"],
        critical=row["critical"],
        producer=row["producer"],
        channel=row["channel"],
    )


def target_of(target: Target_) -> Target:
    return Target(
        BINDING,
        {"binding_id": BINDING, "origin": target.origin, "method": "POST", "path": PATH},
    )


async def deliver_once(db, target: Target_, views: Views):
    await enqueue_secret_use(db, views)
    return await transport(target, views).deliver(await stored_event(db), target_of(target))


# --- outcomes ---


async def test_an_appended_ack_is_delivered_with_its_receipt(db, target) -> None:
    views = Views(target.view())
    receipt = {"team_seq": 7, "event_hash": "ab" * 32}
    target.replies = [(200, {"event_id": "", "disposition": "appended", "receipt": receipt})]
    outcome = await deliver_once(db, target, views)
    assert isinstance(outcome, Acked)
    assert outcome.disposition == "delivered"
    assert json.loads(outcome.receipt or b"") == receipt
    assert target.refusals == []
    assert len(target.verified) == 1


async def test_a_duplicate_ack_is_a_duplicate(db, target) -> None:
    views = Views(target.view())
    target.replies = [(200, {"event_id": "", "disposition": "duplicate"})]
    outcome = await deliver_once(db, target, views)
    assert outcome == Acked("duplicate", None)


async def test_an_ack_for_another_event_is_not_taken(db, target) -> None:
    views = Views(target.view())

    async def other_event(seen: Seen):
        body = {"event_id": "0192f0c4-6f1e-7c3a-9a51-3d2b8e0f4c11", "disposition": "appended"}
        return 200, json.dumps(body).encode(), []

    target.tls.respond = other_event
    assert isinstance(await deliver_once(db, target, views), Permanent)


async def test_a_conflict_is_a_conflict(db, target) -> None:
    views = Views(target.view())
    target.replies = [(409, {"error": "event_conflict"})]
    assert await deliver_once(db, target, views) == Conflict()


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422])
async def test_an_authorization_or_schema_rejection_is_permanent(db, target, status) -> None:
    views = Views(target.view())
    target.replies = [(status, {"error": "no"})]
    assert isinstance(await deliver_once(db, target, views), Permanent)


@pytest.mark.parametrize("status", [408, 429, 500, 502, 503])
async def test_a_server_error_or_throttle_is_retried(db, target, status) -> None:
    views = Views(target.view())
    target.replies = [(status, None)]
    assert isinstance(await deliver_once(db, target, views), Retryable)


async def test_a_redirect_is_not_followed(db, target) -> None:
    views = Views(target.view())

    async def redirect(seen: Seen):
        return 302, b"", [("Location", "https://elsewhere.example/in")]

    target.tls.respond = redirect
    assert isinstance(await deliver_once(db, target, views), Permanent)
    assert len(target.tls.seen) == 1


async def test_a_closed_port_is_retried(db, target) -> None:
    views = Views(target.view())
    await enqueue_secret_use(db, views)
    closed = Target(
        BINDING,
        {
            "binding_id": BINDING,
            "origin": f"https://{NAME}:{target.tls.port}",
            "method": "POST",
            "path": PATH,
        },
    )
    await target.tls.close()
    outcome = await transport(target, views).deliver(await stored_event(db), closed)
    assert isinstance(outcome, Retryable)


# --- the binding is re-checked before each send ---


async def test_a_binding_gone_from_the_view_is_cancelled_and_nothing_is_sent(db, target) -> None:
    views = Views(target.view())
    await enqueue_secret_use(db, views)
    views.current = target.view(target.registration("0192f0c4-6f1e-7c3a-9a51-3d2b8e0f4c11"))
    outcome = await transport(target, views).deliver(await stored_event(db), target_of(target))
    assert isinstance(outcome, Cancelled)
    assert target.tls.seen == []


async def test_a_stale_view_retries_and_sends_nothing(db, target) -> None:
    views = Views(target.view())
    await enqueue_secret_use(db, views)
    views.current = target.view(age=timedelta(seconds=61))
    outcome = await transport(target, views).deliver(await stored_event(db), target_of(target))
    assert isinstance(outcome, Retryable)
    assert target.tls.seen == []


# --- egress ---


async def test_a_hosted_deployment_never_reaches_a_private_address(db, target) -> None:
    views = Views(target.view())
    hosted = target.egress(AddressPolicy())
    await enqueue_secret_use(db, views)
    outcome = await transport(target, views, egress=hosted, internal_cidr=None).deliver(
        await stored_event(db), target_of(target)
    )
    assert isinstance(outcome, Permanent)
    assert target.tls.seen == []


async def test_a_private_target_is_tried_as_public_then_reached_inside_the_operators_network(
    db, target
) -> None:
    views = Views(target.view())
    target.replies = [(200, {"event_id": "", "disposition": "appended"})]
    assert isinstance(await deliver_once(db, target, views), Acked)
    # Resolved twice: once for the public attempt the guard refused before
    # connecting, once more, afresh, for the internal attempt.
    assert target.dns.queries[(NAME, "A")] == 2
    assert len(target.tls.seen) == 1


async def test_a_private_target_outside_the_operators_network_is_refused(db, target) -> None:
    views = Views(target.view())
    await enqueue_secret_use(db, views)
    elsewhere = transport(target, views, internal_cidr=ip_network("10.231.0.0/16"))
    outcome = await elsewhere.deliver(await stored_event(db), target_of(target))
    assert outcome == Permanent("egress_refused:destination_address_denied")
    assert target.tls.seen == []
    assert target.dns.queries[(NAME, "A")] == 2


async def test_without_an_operator_network_the_first_refusal_is_final(db, target) -> None:
    views = Views(target.view())
    await enqueue_secret_use(db, views)
    allowed_but_unnamed = transport(target, views, internal_cidr=None)
    outcome = await allowed_but_unnamed.deliver(await stored_event(db), target_of(target))
    assert outcome == Permanent("egress_refused:destination_address_denied")
    assert target.tls.seen == []
    assert target.dns.queries[(NAME, "A")] == 1


async def test_a_refusal_other_than_a_denied_address_is_never_retried(db, target) -> None:
    views = Views(target.view())
    await enqueue_secret_use(db, views)
    origin = f"https://unknown.hooks.test:{target.tls.port}"
    views.current = target.view(
        Registration(
            binding_id=BINDING,
            origin=origin,
            method="POST",
            path=PATH,
            active_from=datetime.now(UTC) - timedelta(minutes=5),
        )
    )
    unknown = Target(
        BINDING, {"binding_id": BINDING, "origin": origin, "method": "POST", "path": PATH}
    )
    outcome = await transport(target, views).deliver(await stored_event(db), unknown)
    assert isinstance(outcome, Retryable)
    assert target.dns.queries[("unknown.hooks.test", "A")] == 1
    assert target.tls.seen == []


def test_an_internal_cidr_needs_an_operator_who_allows_internal_destinations(target) -> None:
    with pytest.raises(ValueError):
        transport(target, Views(), egress=target.egress(AddressPolicy()))


async def test_a_stored_endpoint_the_view_no_longer_lists_is_cancelled(db, target) -> None:
    views = Views(target.view())
    await enqueue_secret_use(db, views)
    elsewhere = Target(
        BINDING,
        {"binding_id": BINDING, "origin": target.origin, "method": "POST", "path": "/elsewhere"},
    )
    outcome = await transport(target, views).deliver(await stored_event(db), elsewhere)
    assert outcome == Cancelled("binding_changed")
    assert target.tls.seen == []


# --- the drain ---


async def test_a_drain_delivers_each_owed_event_once(db, target) -> None:
    views = Views(target.view())
    target.replies = [(200, {"event_id": "", "disposition": "appended"})]
    event_id = await enqueue_secret_use(db, views)
    result = await drain(
        db,
        channel=HOOKS_CHANNEL,
        resolver=hook_targets(views),
        transport=transport(target, views),
        policy=POLICY,
    )
    assert (result.materialized, result.delivered) == (1, 1)
    assert target.verified == [event_id]
    status = await outbox_status(db, HOOKS_CHANNEL)
    assert status.faults == []


async def test_a_stale_view_keeps_the_event_pending_until_a_fresh_one(db, target) -> None:
    views = Views(target.view())
    target.replies = [(200, {"event_id": "", "disposition": "appended"})]
    await enqueue_secret_use(db, views)
    views.current = target.view(age=timedelta(seconds=61))
    stale = await drain(
        db,
        channel=HOOKS_CHANNEL,
        resolver=hook_targets(views),
        transport=transport(target, views),
        policy=POLICY,
    )
    assert stale.materialized == 0
    assert (await outbox_status(db, HOOKS_CHANNEL)).unmaterialized[TEAM].count == 1
    views.current = target.view()
    fresh = await drain(
        db,
        channel=HOOKS_CHANNEL,
        resolver=hook_targets(views),
        transport=transport(target, views),
        policy=POLICY,
    )
    assert (fresh.materialized, fresh.delivered) == (1, 1)


async def test_revocation_between_materialization_and_send_is_a_surfaced_fault(db, target) -> None:
    views = Views(target.view())
    event_id = await enqueue_secret_use(db, views)

    revoking = hook_targets(views)

    async def materialize_then_revoke(event: StoredEvent):
        targets = await revoking(event)
        views.current = RegistrationView(
            team_id=TEAM,
            hook="post-secret-use-hook",
            as_of=datetime.now(UTC),
            max_age=timedelta(seconds=60),
            registrations=(),
        )
        return targets

    result = await drain(
        db,
        channel=HOOKS_CHANNEL,
        resolver=materialize_then_revoke,
        transport=transport(target, views),
        policy=POLICY,
    )
    assert (result.materialized, result.delivered) == (1, 0)
    assert target.tls.seen == []
    status = await outbox_status(db, HOOKS_CHANNEL)
    assert [str(fault) for fault in status.faults] == [event_id]


async def test_rejections_are_retried_then_end_rejected_and_surface_as_a_fault(db, target) -> None:
    views = Views(target.view())
    target.replies = [(422, {"error": "schema"})]
    event_id = await enqueue_secret_use(db, views)
    for _ in range(POLICY.rejected_after_attempts):
        await drain(
            db,
            channel=HOOKS_CHANNEL,
            resolver=hook_targets(views),
            transport=transport(target, views),
            policy=POLICY,
        )
    state = await db.fetch_value("SELECT state FROM {{tables.outbox_deliveries}}")
    assert state == "rejected"
    assert len(target.verified) == POLICY.rejected_after_attempts
    assert [str(f) for f in (await outbox_status(db, HOOKS_CHANNEL)).faults] == [event_id]


async def test_a_drain_killed_mid_send_delivers_on_the_next_drain(db, target, tmp_path) -> None:
    views = Views(target.view())
    hold = asyncio.Event()
    target.replies = [(200, {"event_id": "", "disposition": "appended"})]
    answer = target.answer

    async def hold_the_first(seen: Seen):
        if len(target.tls.seen) == 1:
            await hold.wait()
        return await answer(seen)

    target.tls.respond = hold_the_first
    event_id = await enqueue_secret_use(db, views)
    sending = tmp_path / "sending"
    child = subprocess.Popen(
        [
            sys.executable,
            str(_CHILD),
            db.config.get_dsn(),
            db.schema or "",
            str(sending),
            NAME,
            str(target.dns.port),
            str(target.ca_file),
            target.host,
            target.origin,
            SEED.hex(),
        ],
        env={**os.environ},
    )
    try:
        for _ in range(300):
            if len(target.tls.seen) == 1:
                break
            await asyncio.sleep(0.05)
        assert len(target.tls.seen) == 1, "the child never sent"
        child.send_signal(signal.SIGKILL)
        child.wait(timeout=30)
    finally:
        if child.poll() is None:
            child.kill()
        hold.set()
    # The killed child's backend may still hold the delivery's row lock; an
    # UPDATE waits for Postgres to end it, and makes the delivery due.
    await db.execute("UPDATE {{tables.outbox_deliveries}} SET next_attempt_at = NOW()")
    assert await db.fetch_value("SELECT state FROM {{tables.outbox_deliveries}}") == "pending"
    result = await drain(
        db,
        channel=HOOKS_CHANNEL,
        resolver=hook_targets(views),
        transport=transport(target, views),
        policy=POLICY,
    )
    assert result.delivered == 1
    assert await db.fetch_value("SELECT state FROM {{tables.outbox_deliveries}}") == "delivered"
    assert target.verified[-1] == event_id
