"""Core wiring for the shared hooks producer; independent of ``on_mutation``.

Call enqueue_mutation_hook with the transaction that changes core state. Core
reads S1 directly, so no registration cache can outlive a revocation here.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from ipaddress import IPv4Network, IPv6Network
from typing import Any

from aweb_naapp.egress import AddressPolicy, DnsResolver, Egress, InternalDestinations
from aweb_naapp.hooks.producer import (
    HOOKS_CHANNEL, VIEW_MAX_AGE, HookProducer, Registration, RegistrationView,
    ServerProducer, hook_targets,
)
from aweb_naapp.hooks.transport import HookTransport
from aweb_naapp.outbox import RetryPolicy, run_drain
from aweb_naapp.signing_key import read_signing_key_file
from awid.utc_timestamps import parse_utc_seconds

from aweb.config import HookProducerKey, get_hook_producer_keys, get_hook_signing_key_file
from aweb.hook_bindings import REGISTRATION
from aweb.hook_resolution import HookSelector, active_bindings

MUTATION_HOOK = "post-mutation-hook"
SYSTEM_ACTOR = {"authority_mode": "system", "attestations": []}


class CoreRegistrations:
    """An in-process S1 resolver usable with a manager or the effect's tx."""

    def __init__(self, db):
        self.db = db

    async def view(self, team_id: str, hook: str) -> RegistrationView:
        # Date this snapshot before the read, so time waiting for the database
        # never makes old observations appear newly fresh.
        as_of = datetime.now(UTC)
        bindings = await active_bindings(
            self.db, team_id=team_id, kind=REGISTRATION,
            selector=HookSelector("aweb.hooks", 1, hook),
        )
        return RegistrationView(team_id, hook, as_of, VIEW_MAX_AGE, tuple(
            Registration(str(b.binding_id), b.origin, b.method, b.path, b.active_from)
            for b in bindings
        ))


@dataclass(frozen=True)
class CoreHooks:
    producer: HookProducer
    key: HookProducerKey | None = None

    def require_valid_key(self, moment: datetime) -> None:
        if self.key is not None and (
            moment < parse_utc_seconds(self.key.valid_from)
            or (self.key.valid_until is not None and moment >= parse_utc_seconds(self.key.valid_until))
        ):
            raise RuntimeError("core hook signing key is outside its validity window")


@dataclass(frozen=True)
class MutationHookContext:
    hooks: CoreHooks | None
    actor: Mapping[str, Any]
    signed_trace_id: str | None = None


def load_core_hooks(origin: str) -> CoreHooks | None:
    """Load only the operator's dedicated hook key and match its published kid."""
    configured = get_hook_signing_key_file()
    if configured is None:
        return None
    kid, path = configured
    if not origin.startswith("https://"):
        raise ValueError("a configured core hook producer requires a public HTTPS origin")
    key = next((key for key in get_hook_producer_keys() if key.kid == kid), None)
    if key is None:
        raise ValueError("core hook signing kid is absent from AWEB_HOOK_PRODUCER_KEYS")
    signing_key = read_signing_key_file(Path(path))
    producer = ServerProducer.core(origin=origin, kid=kid, seed=bytes(signing_key))
    if producer.did_key != key.did_key:
        raise ValueError("core hook signing key does not match its published kid")
    hooks = CoreHooks(HookProducer(producer), key)
    hooks.require_valid_key(datetime.now(UTC))
    return hooks


def request_hook_context(request, identity=None) -> MutationHookContext:
    """Take trace and identity from authentication's verified context only.

    An embedding host without a hook-envelope identity uses system. It can
    supply its verified member identity through the existing auth seam.
    """
    actor = dict(SYSTEM_ACTOR)
    if identity is not None:
        actor = {"authority_mode": "team_cert", "attestations": [], "did_key": identity.did_key}
        for name in ("did_aw", "certificate_id", "alias"):
            if value := getattr(identity, name, None):
                actor[name] = value
        if identity.grant is not None:
            actor["authority_mode"] = "identity_grant"
            actor["grant_id"] = identity.grant.grant_id
    return MutationHookContext(
        getattr(request.app.state, "core_hooks", None), actor,
        getattr(request.state, "verified_hook_trace_id", None),
    )


async def enqueue_mutation_hook(
    tx, *, team_id: str, payload: Mapping[str, Any],
    hook_context: MutationHookContext | None = None, occurred_at: datetime | None = None,
):
    """Enqueue only for a fresh, eligible registration, in the effect's tx.

    Ordinary core mutations are never audit-gated when no target is owed the
    event. Once owed, failures writing the event roll back the effect as well.
    """
    occurred_at = occurred_at or datetime.now(UTC)
    view = await CoreRegistrations(tx).view(team_id, MUTATION_HOOK)
    if not view.is_fresh(datetime.now(UTC)) or not view.owed(occurred_at):
        return None
    if hook_context is None or hook_context.hooks is None:
        raise RuntimeError("an active mutation hook requires a configured core hook signing key")
    hooks = hook_context.hooks
    hooks.require_valid_key(datetime.now(UTC))
    hooks.require_valid_key(occurred_at)
    return await hooks.producer.enqueue(
        tx, hook=MUTATION_HOOK, team_id=team_id, payload=payload, actor=hook_context.actor,
        occurred_at=occurred_at, result_status="success", signed_trace_id=hook_context.signed_trace_id,
        view=view,
    )


def start_core_hooks(
    app, db, *, egress: Egress | None = None,
    internal_cidr: IPv4Network | IPv6Network | None = None,
) -> None:
    """Start the shared hooks drain after DB initialization in either lifespan."""
    hooks = load_core_hooks(app.state.public_origin)
    app.state.core_hooks = hooks
    if hooks is None:
        return
    registrations = CoreRegistrations(db)
    # The default policy is public destinations only. Internal delivery needs
    # both an injected deployment egress and its explicitly allowed network.
    egress = egress or Egress(
        addresses=AddressPolicy(internal_destinations=InternalDestinations.DISABLED),
        resolver=DnsResolver(), user_agent="aweb-hooks/1",
    )
    stop = asyncio.Event()
    app.state.core_hooks_stop = stop
    app.state.core_hooks_drain = asyncio.create_task(run_drain(
        db, channel=HOOKS_CHANNEL, resolver=hook_targets(registrations),
        transport=HookTransport(seed=hooks.producer.producer.seed, egress=egress, registrations=registrations, internal_cidr=internal_cidr),
        policy=RetryPolicy(stalled_after=timedelta(days=1)), stop=stop,
    ))


async def stop_core_hooks(app) -> None:
    task = getattr(app.state, "core_hooks_drain", None)
    if task is not None:
        app.state.core_hooks_stop.set()
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=35)
        except TimeoutError:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        app.state.core_hooks_drain = None
