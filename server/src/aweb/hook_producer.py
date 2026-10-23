"""Core wiring for the shared hooks producer; independent of ``on_mutation``.

Call enqueue_mutation_hook with the transaction that changes core state. Core
reads S1 directly, so no registration cache can outlive a revocation here.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Network, IPv6Network
from pathlib import Path
from typing import Any

from aweb_naapp.egress import AddressPolicy, DnsResolver, Egress, InternalDestinations
from aweb_naapp.hooks.catalog import packaged_catalog
from aweb_naapp.hooks.producer import (
    HOOKS_CHANNEL,
    VIEW_MAX_AGE,
    HookProducer,
    Registration,
    RegistrationView,
    ServerProducer,
    hook_targets,
)
from aweb_naapp.hooks.transport import HookTransport
from aweb_naapp.outbox import RetryPolicy, reserve_missing_production, run_drain
from aweb_naapp.signing_key import read_signing_key_file
from awid.utc_timestamps import parse_utc_seconds

from aweb.config import (
    HookProducerKey,
    get_hook_producer_keys,
    get_hook_signing_key_file,
    get_public_origin,
)
from aweb.hook_bindings import REGISTRATION
from aweb.hook_resolution import HookSelector, active_bindings
from aweb.service_errors import ConflictError

MUTATION_HOOK = "post-mutation-hook"
SYSTEM_ACTOR = {"authority_mode": "system", "attestations": []}
logger = logging.getLogger(__name__)


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


def signer_unavailable_reason(hooks: CoreHooks | None, moment: datetime) -> str | None:
    if hooks is None:
        return "key_unconfigured"
    try:
        hooks.require_valid_key(moment)
    except RuntimeError:
        return "key_out_of_window"
    return None


def require_core_hook_signer(hooks: CoreHooks | None) -> None:
    """Readiness for new mutation registrations, after owner verification."""
    if signer_unavailable_reason(hooks, datetime.now(UTC)) is not None:
        raise ConflictError("core_hook_producer_unconfigured")


class CoreHookDiagnostics:
    """Bounded local fault/warning state; never signed delivery evidence."""

    def __init__(self, warning_lead: timedelta = timedelta(days=7)):
        if warning_lead <= timedelta(0):
            raise ValueError("core hook warning lead must be positive")
        self.warning_lead = warning_lead
        self._fault_state = None
        self._warning_state = None

    def observe(
        self,
        hooks: CoreHooks | None,
        *,
        now: datetime | None = None,
        reason: str | None = None,
    ) -> None:
        now = now or datetime.now(UTC)
        reason = reason or signer_unavailable_reason(hooks, now)
        kid = hooks.producer.producer.kid if hooks else None
        deadline = hooks.key.valid_until if hooks and hooks.key else None
        state = (reason, kid, deadline) if reason else None
        fields = {
            "component": "core_hook_producer",
            "reason": reason,
            "kid": kid,
            "valid_until": deadline,
        }
        if state is not None and state != self._fault_state:
            logger.error(
                "Core hook signer unavailable; losses remain in local outbox accounting",
                extra=fields,
            )
        self._fault_state = state
        warning = None
        if (
            reason is None
            and deadline
            and now >= parse_utc_seconds(deadline) - self.warning_lead
        ):
            warning = (kid, deadline)
            if warning != self._warning_state:
                logger.warning(
                    "Core hook signing key approaches expiry",
                    extra={**fields, "reason": "key_expiring"},
                )
        self._warning_state = warning


_service_diagnostics = CoreHookDiagnostics()


def _warning_lead() -> timedelta:
    seconds = float(os.getenv("AWEB_HOOK_PRODUCER_WARNING_LEAD_SECONDS", "604800"))
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError(
            "AWEB_HOOK_PRODUCER_WARNING_LEAD_SECONDS must be positive and finite"
        )
    return timedelta(seconds=seconds)


@dataclass(frozen=True)
class MutationHookContext:
    hooks: CoreHooks | None
    actor: Mapping[str, Any]
    signed_trace_id: str | None = None
    origin: str | None = None
    diagnostics: CoreHookDiagnostics | None = None


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
    diagnostics = getattr(request.app.state, "core_hook_diagnostics", None)
    if diagnostics is None:
        diagnostics = CoreHookDiagnostics(_warning_lead())
        request.app.state.core_hook_diagnostics = diagnostics
    return MutationHookContext(
        getattr(request.app.state, "core_hooks", None),
        actor,
        getattr(request.state, "verified_hook_trace_id", None),
        getattr(request.app.state, "public_origin", None) or get_public_origin(),
        diagnostics,
    )


async def enqueue_mutation_hook(
    tx,
    *,
    team_id: str,
    payload: Mapping[str, Any],
    hook_context: MutationHookContext | None = None,
    occurred_at: datetime | None = None,
):
    """Enqueue only for a fresh, eligible registration, in the effect's tx.

    With a signer, the event and effect commit together. With no usable signer,
    reserve the owed firing's sequence and typed local loss in that same tx.
    Signer availability never gates a mutation; local write failures still do.
    """
    occurred_at = occurred_at or datetime.now(UTC)
    view = await CoreRegistrations(tx).view(team_id, MUTATION_HOOK)
    if not view.is_fresh(datetime.now(UTC)) or not view.owed(occurred_at):
        return None
    hooks = hook_context.hooks if hook_context else None
    reason = signer_unavailable_reason(
        hooks, datetime.now(UTC)
    ) or signer_unavailable_reason(hooks, occurred_at)
    diagnostics = (
        hook_context.diagnostics
        if hook_context and hook_context.diagnostics
        else _service_diagnostics
    )
    diagnostics.observe(hooks, reason=reason)
    if reason is not None:
        # Keep catalog validation even without a signer. This is local
        # accounting, never an unsigned OutboxEvent or recovery signature.
        packaged_catalog().validate(MUTATION_HOOK, payload)
        origin = (hook_context.origin if hook_context else None) or (
            hooks.producer.producer.origin if hooks else get_public_origin()
        )
        await reserve_missing_production(
            tx,
            scope=f"core:{MUTATION_HOOK}",
            team_id=team_id,
            origin=origin,
            kind=MUTATION_HOOK,
            channel=HOOKS_CHANNEL,
            occurred_at=occurred_at,
            reason=reason,
            binding_ids=[r.binding_id for r in view.owed(occurred_at)],
        )
        return None
    return await hooks.producer.enqueue(
        tx, hook=MUTATION_HOOK, team_id=team_id, payload=payload, actor=hook_context.actor,
        occurred_at=occurred_at, result_status="success", signed_trace_id=hook_context.signed_trace_id,
        view=view,
    )


def start_core_hooks(
    app,
    db,
    *,
    egress: Egress | None = None,
    internal_cidr: IPv4Network | IPv6Network | None = None,
) -> None:
    """Start the shared hooks drain after DB initialization in either lifespan."""
    hooks = load_core_hooks(app.state.public_origin)
    app.state.core_hooks = hooks
    diagnostics = CoreHookDiagnostics(_warning_lead())
    app.state.core_hook_diagnostics = diagnostics
    diagnostics.observe(hooks)
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
    app.state.core_hooks_drain = asyncio.create_task(
        run_drain(
            db,
            channel=HOOKS_CHANNEL,
            resolver=hook_targets(registrations),
            transport=HookTransport(
                seed=hooks.producer.producer.seed,
                egress=egress,
                registrations=registrations,
                internal_cidr=internal_cidr,
            ),
            policy=RetryPolicy(stalled_after=timedelta(days=1)),
            stop=stop,
            maintenance=lambda: diagnostics.observe(hooks),
        )
    )


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
