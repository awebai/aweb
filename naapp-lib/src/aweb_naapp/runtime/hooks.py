"""Runtime composition of the shared hook producer, resolver and guarded drain.

Effects remain caller-owned: obtain a producer for an authoritatively resolved
installation, fetch registration evidence before locks, and enqueue in the
transaction that records the effect. This module creates no effect transaction
and never emits from a completed HTTP response.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta
from ipaddress import IPv4Network, IPv6Network
from typing import TYPE_CHECKING, Any, TypedDict
from uuid import UUID

from aweb_naapp.hooks.catalog import packaged_catalog
from aweb_naapp.hooks.commitment import CommitmentKey, Purpose, load_commitment_key
from aweb_naapp.hooks.producer import HOOKS_CHANNEL, HookProducer, ServerProducer, hook_targets
from aweb_naapp.hooks.resolver import TeamServerRegistrations
from aweb_naapp.manifest import Manifest
from aweb_naapp.outbox import Resolver, RetryPolicy, Transport
from aweb_naapp.runtime.app_keys import AppKey, AppKeyError, load_app_key
from aweb_naapp.runtime.hook_resolver import HookResolver
from aweb_naapp.runtime.manifest_hooks import ManifestEvidence
from aweb_naapp.runtime.settings import NaappSettings

if TYPE_CHECKING:
    from pgdbm.core import TransactionManager

    from aweb_naapp.egress import Egress

HOOK_EVENT = "hook-event"
MANIFEST_HOOK = "post-manifest-command-hook"


def _app_productions(manifest: Manifest) -> tuple[dict[str, Any], ...]:
    """Only implemented catalog entries can configure this app producer.

    The manifest reader preserves unknown catalogs, versions and hook names.
    They remain inert rather than requiring keys or configuring a drain.
    """
    catalog = packaged_catalog()
    return tuple(
        production
        for production in (manifest.hooks or {}).get("productions", ())
        if production["catalog"] == (catalog.id, catalog.version)
        and production["hook"] in catalog.hooks
        and "app" in catalog.hooks[production["hook"]].producer_kinds
    )


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
        tool_effects: dict[str, str] | None = None,
    ) -> None:
        self.manifest = manifest
        self.productions = _app_productions(manifest)
        self.key = key
        self.registrations = registrations
        self.transport = transport
        self.policy = policy
        self.manifest_request_key = manifest_request_key
        self.tool_effects = dict(tool_effects or {})
        tools = manifest.tools_by_name()
        declared = {p["hook"] for p in self.productions}
        for tool, hook in self.tool_effects.items():
            if (
                tool not in tools
                or hook not in {"post-secret-use-hook", "post-governance-hook"}
                or hook not in declared
            ):
                raise AppKeyError(
                    "hook_tool_effects must name a declared tool and specific production"
                )

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
        productions = _app_productions(manifest)
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
                tool_effects=settings.hook_tool_effects,
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
            tool_effects=settings.hook_tool_effects,
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

    async def record_manifest(
        self,
        tx: TransactionManager,
        evidence: ManifestEvidence,
        *,
        http_status: int,
        refused: bool = False,
        resource_refs: Sequence[str] = (),
        result_ref: str | None = None,
    ) -> UUID | None:
        if self.manifest_request_key is None or evidence.tool.name in self.tool_effects:
            return None
        raw_tool = self.manifest.tools_by_name()[evidence.tool.name]
        mutation = raw_tool.get("mutation", False)
        production = next(p for p in self.productions if p["hook"] == MANIFEST_HOOK)
        if not refused and not mutation and evidence.tool.name not in production["reads"]:
            return None
        payload: dict[str, Any] = {
            "app_id": self.manifest.app_id,
            "tool": evidence.tool.name,
            "operation_kind": "refusal" if refused else "mutation" if mutation else "read",
            "request_sha256": evidence.commitment,
            "http_status": http_status,
        }
        if resource_refs:
            payload["resource_refs"] = list(resource_refs)
        if result_ref is not None:
            payload["result_ref"] = result_ref
        return await self.producer(
            installation_id=evidence.context.installation_id,
            generation=evidence.context.generation,
        ).enqueue(
            tx,
            hook=MANIFEST_HOOK,
            team_id=evidence.context.team_id,
            payload=payload,
            actor=evidence.actor,
            occurred_at=evidence.occurred_at,
            result_status="denied" if refused else "success" if http_status < 400 else "failed",
            signed_trace_id=evidence.trace_id,
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
