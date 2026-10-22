"""Runtime composition of the shared hook producer, resolver and guarded drain.

Effects remain caller-owned: obtain a producer for an authoritatively resolved
installation, fetch registration evidence before locks, and enqueue in the
transaction that records the effect. This module creates no effect transaction
and never emits from a completed HTTP response.
"""

from __future__ import annotations

from datetime import timedelta
from ipaddress import IPv4Network, IPv6Network
from typing import TYPE_CHECKING, TypedDict

from aweb_naapp.hooks.commitment import CommitmentKey, Purpose, load_commitment_key
from aweb_naapp.hooks.producer import HOOKS_CHANNEL, HookProducer, ServerProducer, hook_targets
from aweb_naapp.hooks.resolver import TeamServerRegistrations
from aweb_naapp.manifest import Manifest
from aweb_naapp.outbox import Resolver, RetryPolicy, Transport
from aweb_naapp.runtime.app_keys import AppKey, AppKeyError, load_app_key
from aweb_naapp.runtime.hook_resolver import HookResolver
from aweb_naapp.runtime.settings import NaappSettings

if TYPE_CHECKING:
    from aweb_naapp.egress import Egress

HOOK_EVENT = "hook-event"
MANIFEST_HOOK = "post-manifest-command-hook"


class DrainOptions(TypedDict):
    channel: str
    resolver: Resolver
    transport: Transport
    policy: RetryPolicy


class RuntimeHooks:
    """One process's configuration; installation identities come from the caller."""

    def __init__(
        self,
        *,
        manifest: Manifest,
        key: AppKey | None,
        registrations: TeamServerRegistrations | None,
        transport: Transport | None,
        policy: RetryPolicy,
        manifest_request_key: CommitmentKey | None,
    ) -> None:
        self.manifest = manifest
        self.key = key
        self.registrations = registrations
        self.transport = transport
        self.policy = policy
        self.manifest_request_key = manifest_request_key

    @classmethod
    def from_settings(
        cls,
        settings: NaappSettings,
        manifest: Manifest,
        *,
        resolver: HookResolver | None,
        egress: Egress | None,
        internal_cidr: IPv4Network | IPv6Network | None,
    ) -> RuntimeHooks:
        productions = (manifest.hooks or {}).get("productions", ())
        policy = RetryPolicy(
            stalled_after=timedelta(seconds=settings.hook_events_stalled_after_seconds),
            call_timeout_seconds=settings.hook_delivery_timeout_seconds,
        )
        if not productions:
            return cls(
                manifest=manifest,
                key=None,
                registrations=None,
                transport=None,
                policy=policy,
                manifest_request_key=None,
            )
        key = load_app_key(settings, manifest, HOOK_EVENT)
        if resolver is None:
            raise AppKeyError("hook production requires a declared hook-resolve key")
        commitment = None
        if any(production["hook"] == MANIFEST_HOOK for production in productions):
            if settings.manifest_request_key_file is None:
                raise AppKeyError("manifest hook production requires manifest_request_key_file")
            commitment = load_commitment_key(
                Purpose.MANIFEST_REQUEST, settings.manifest_request_key_file
            )
        registrations = TeamServerRegistrations(resolver)
        # These optional dependencies are needed only by a producing runtime.
        # A no-hooks runtime keeps its existing dependency/import boundary.
        from aweb_naapp.egress import AddressPolicy, DnsResolver, Egress
        from aweb_naapp.hooks.transport import HookTransport

        guard = (
            egress
            if egress is not None
            else Egress(
                addresses=AddressPolicy(),
                resolver=DnsResolver(),
                user_agent="aweb-naapp/hooks",
            )
        )
        transport = HookTransport(
            seed=bytes(key.signing_key),
            egress=guard,
            registrations=registrations,
            internal_cidr=internal_cidr,
        )
        return cls(
            manifest=manifest,
            key=key,
            registrations=registrations,
            transport=transport,
            policy=policy,
            manifest_request_key=commitment,
        )

    def producer(self, *, installation_id: str, generation: int) -> HookProducer:
        """Use verified grant/fence identity, never caller headers or a new allocator.

        The producer enqueues in the caller's transaction. Its sequence and
        immutable signing bytes are owned by the existing shared outbox.
        """
        if self.key is None:
            raise AppKeyError("manifest declares no hook production")
        return HookProducer(
            ServerProducer.app(
                origin=self.manifest.document["app"]["origin"],
                app_id=self.manifest.app_id,
                installation_id=installation_id,
                generation=generation,
                kid=self.key.kid,
                seed=bytes(self.key.signing_key),
            )
        )

    def drain_options(self) -> DrainOptions:
        if self.registrations is None or self.transport is None:
            raise AppKeyError("manifest declares no hook production")
        return DrainOptions(
            channel=HOOKS_CHANNEL,
            resolver=hook_targets(self.registrations),
            transport=self.transport,
            policy=self.policy,
        )
