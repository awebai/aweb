"""Admitting a hook delivery to the log (audit-substrate.md §B2).

Admission is an ordered list of steps, each failing closed with its own
status and code: transport, binding, provenance, schema, dedup, append. The
pipeline reuses the hook kit, runtime resolver and team-auth publication
predicate; it implements no second verifier or discovery client.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import httpx
from aweb_naapp.hooks.catalog import Catalog, PayloadRefused
from aweb_naapp.hooks.delivery import (
    AUTH_SCHEME,
    SIGNED_PAYLOAD_HEADER,
    ReceiveOptions,
    verify_delivery,
)
from aweb_naapp.hooks.envelope import TEAM_ID_PATTERN, Envelope, verify_signature
from aweb_naapp.hooks.strictjson import (
    Refused,
    decode_base64url,
    encode_base64url,
    parse_canonical_object,
)
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.hook_resolver import (
    HookBindingRequired,
    HookResolutionUnavailable,
    OwnHookBinding,
)
from aweb_naapp.runtime.team_auth import raw_request_target, require_active_certificate
from awid.log import canonical_server_origin
from awid.registry import RegistryClient, RegistryError
from awid.team_certificate import decode_team_certificate
from awid.team_ids import parse_team_id
from fastapi import HTTPException, Request

from aweb_logs.ledger import Conflicted, LogsSigner, OriginMismatch, append

# How far an event's occurred_at may lead logs' clock: the delivery
# credential's own replay window.
CLOCK_SKEW = timedelta(seconds=300)
_EVENT_TIME = "%Y-%m-%dT%H:%M:%S.%fZ"


class IngestRefused(Exception):
    """A delivery logs does not admit: the HTTP status it answers and a stable code."""

    def __init__(self, status: int, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.status = status
        self.code = code
        self.detail = detail


def check_schema(event: Envelope, catalog: Catalog, *, received_at: datetime) -> None:
    """Step 4: the event's catalog is the one logs reads, its payload is within
    its hook's allowlist, and it did not occur after logs received it."""
    named = event.fields["catalog"]
    if (named["id"], named["version"]) != (catalog.id, catalog.version):
        raise IngestRefused(422, "unknown_catalog", f"{named['id']} v{named['version']}")
    try:
        catalog.validate(event.hook, event.fields["payload"])
    except PayloadRefused as refused:
        raise IngestRefused(422, f"schema_{refused.code}", refused.field or "") from None
    occurred_at = datetime.strptime(event.fields["occurred_at"], _EVENT_TIME).replace(tzinfo=UTC)
    if occurred_at > received_at + CLOCK_SKEW:
        raise IngestRefused(422, "occurred_after_receipt", event.fields["occurred_at"])


@dataclass(frozen=True)
class ClientQuota:
    """How much one member's client events may add to the log per minute."""

    events_per_minute: int
    bytes_per_minute: int


async def charge_client_quota(
    tx: Any, quota: ClientQuota, *, team_id: str, member: str, size: int, now: datetime
) -> None:
    """Count one client event of ``size`` bytes against its member's minute, in
    the admission's transaction; past either limit it is refused (429) and,
    with the transaction, nothing is counted."""
    window = now.astimezone(UTC).replace(second=0, microsecond=0)
    row = await tx.fetch_one(
        """
        INSERT INTO {{tables.client_ingest_usage}} (team_id, member, window_start, events, bytes)
        VALUES ($1, $2, $3, 1, $4)
        ON CONFLICT (team_id, member, window_start)
        DO UPDATE SET events = {{tables.client_ingest_usage}}.events + 1,
                      bytes = {{tables.client_ingest_usage}}.bytes + EXCLUDED.bytes
        RETURNING events, bytes
        """,
        team_id,
        member,
        window,
        size,
    )
    if row["events"] > quota.events_per_minute or row["bytes"] > quota.bytes_per_minute:
        raise IngestRefused(429, "client_quota_exceeded", f"member {member}")


class Ingestor:
    """One process's admission pipeline, on its runtime's one hook resolver.

    Untrusted delivery metadata selects a team and binding, never a URL or
    authority. The kit verifies it; own_bindings then establishes that the
    signed binding is this installation's active registration. For client
    certificates the controller key is read fresh, in addition to B1's shared
    publication/revocation check.
    """

    def __init__(
        self, runtime: NaappRuntime, signer: LogsSigner, catalog: Catalog, quota: ClientQuota,
        *, registry: RegistryClient,
    ) -> None:
        self.runtime = runtime
        self.signer = signer
        self.catalog = catalog
        self.quota = quota
        self.registry = registry
        self.resolver = runtime.hook_resolver()

    async def admit(self, request: Request, *, received_at: datetime) -> dict[str, Any]:
        body = await request.body()
        headers = dict(request.headers)
        team_key_did = ""
        try:
            # Every team uses one route. Select the signed binding as a hint;
            # only the resolver below can establish that it is ours. Authenticate
            # the hint before permitting a client hint to cause registry I/O.
            auth = request.headers.get("Authorization", "")
            if not auth.startswith(AUTH_SCHEME):
                raise Refused("wrong_scheme")
            parts = auth[len(AUTH_SCHEME):].split(" ")
            if len(parts) != 2:
                raise Refused("wrong_scheme")
            signed = decode_base64url(request.headers.get(SIGNED_PAYLOAD_HEADER, ""), "signed payload")
            hint = parse_canonical_object(signed)
            verify_signature(parts[0], signed, parts[1])
            binding_id = hint.get("binding_id")
            if not isinstance(binding_id, str) or str(UUID(binding_id)) != binding_id:
                raise Refused("invalid_value", "binding_id")
            team_id = hint.get("team_id")
            if not isinstance(team_id, str) or not TEAM_ID_PATTERN.fullmatch(team_id):
                raise Refused("invalid_value", "team_id")
            producer = hint.get("producer")
            if isinstance(producer, str) and producer.startswith("client:"):
                team_key_did = await self._current_team_key(team_id)
            received = verify_delivery(
                request.method, raw_request_target(request), headers, body,
                ReceiveOptions(
                    audience=self.runtime.settings.public_origin, binding_id=binding_id,
                    now=received_at, team_key_did=team_key_did,
                ),
            )
        except Refused as refused:
            raise IngestRefused(401, f"transport_{refused.code}") from refused
        except (ValueError, TypeError) as exc:
            raise IngestRefused(401, "transport_invalid_value") from exc

        event = received.envelope
        occurred_at = datetime.strptime(event.fields["occurred_at"], _EVENT_TIME).replace(tzinfo=UTC)
        binding = await self._binding(event, UUID(binding_id), occurred_at, request)
        evidence = await self._provenance(event, occurred_at, headers, team_key_did)
        evidence["binding_ids"].insert(0, str(binding.binding_id))
        check_schema(event, self.catalog, received_at=received_at)
        # Retain exactly the bytes verified by the kit, not a reserialization.
        content = parse_canonical_object(body)
        signing = decode_base64url(content["hook_event"], "hook_event")

        async def charge(tx: Any) -> None:
            await charge_client_quota(
                tx, self.quota, team_id=event.team_id,
                member=event.fields["producer"]["certificate_id"], size=len(body), now=received_at,
            )

        try:
            result = await append(
                self.runtime.db(), self.signer, event=event, signing_bytes=signing,
                signature=content["signature"], key_evidence=evidence, received_at=received_at,
                before_append=charge if event.producer_kind == "client" else None,
            )
        except OriginMismatch as exc:
            raise IngestRefused(503, "chain_origin_mismatch") from exc
        if isinstance(result, Conflicted):
            raise IngestRefused(409, "event_conflict")
        return {
            "event_id": event.event_id,
            "disposition": "duplicate" if result.duplicate else "appended",
            "receipt": {"signing_bytes": encode_base64url(result.receipt[0]), "signature": result.receipt[1]},
        }

    async def _current_team_key(self, team_id: str) -> str:
        domain, name = parse_team_id(team_id)
        try:
            team = await self.registry.get_team_fresh(domain, name)
        except (RegistryError, httpx.HTTPError, TimeoutError, ValueError) as exc:
            raise IngestRefused(503, "client_authority_unavailable") from exc
        if team is None or not team.team_did_key:
            raise IngestRefused(401, "transport_certificate_invalid")
        return team.team_did_key

    async def _binding(
        self, event: Envelope, binding_id: UUID, occurred_at: datetime, request: Request
    ) -> OwnHookBinding:
        try:
            resolution = await self.resolver.own_bindings(event.team_id, binding_id=binding_id)
        except (HookBindingRequired, HookResolutionUnavailable) as exc:
            raise IngestRefused(503, "binding_authority_unavailable") from exc
        for binding in resolution.items:
            if (
                binding.kind == "registration" and binding.state == "active"
                and (binding.catalog_id, binding.catalog_version, binding.hook)
                == (event.fields["catalog"]["id"], event.fields["catalog"]["version"], event.hook)
                and binding.active_from is not None and binding.active_from <= occurred_at
                and binding.origin == self.runtime.settings.public_origin
                and binding.method == request.method and binding.path == raw_request_target(request)
            ):
                return binding
        raise IngestRefused(403, "binding_required")

    async def _provenance(
        self, event: Envelope, occurred_at: datetime, headers: dict[str, str], team_key_did: str,
    ) -> dict[str, Any]:
        producer = event.fields["producer"]
        evidence: dict[str, Any] = {
            "kid": event.producer_kid, "did_key": event.producer_did_key,
            "purposes": [], "installation_id": None, "generation": None, "binding_ids": [],
        }
        if event.producer_kind == "client":
            try:
                facts = await require_active_certificate(
                    self.runtime.team_cache(), team_id=event.team_id,
                    certificate_id=producer["certificate_id"],
                )
            except HTTPException as exc:
                status = 401 if exc.status_code == 401 else 503
                code = "provenance_client_certificate" if status == 401 else "client_authority_unavailable"
                raise IngestRefused(status, code) from exc
            if facts.team_did_key != team_key_did:
                raise IngestRefused(503, "client_authority_changed")
            evidence.update(
                kid="member", certificate=decode_team_certificate(headers["x-awid-team-certificate"]),
                team_did_key=team_key_did,
            )
            return evidence
        try:
            if event.producer_kind == "core":
                resolution = await self.resolver.core_producer_keys(event.team_id)
                if producer["origin"] == canonical_server_origin(resolution.server_url):
                    for core_key in resolution.items:
                        if (
                            core_key.kid == event.producer_kid and core_key.did_key == event.producer_did_key
                            and core_key.valid_from <= occurred_at
                            and (core_key.valid_until is None or occurred_at < core_key.valid_until)
                        ):
                            return {**evidence, "purposes": ["hook-event"], "server_url": resolution.server_url}
                raise IngestRefused(403, "provenance_core_key")
            productions = await self.resolver.productions(
                event.team_id, event.fields["catalog"]["id"], event.fields["catalog"]["version"], event.hook,
            )
        except HookBindingRequired as exc:
            raise IngestRefused(403, "provenance_app_production") from exc
        except HookResolutionUnavailable as exc:
            raise IngestRefused(503, "provenance_authority_unavailable") from exc
        for production in productions.items:
            if (
                (production.app_id, production.origin, production.installation_id, production.generation)
                == (producer["app_id"], producer["origin"], producer["installation_id"], producer["generation"])
                and production.active_from is not None and production.active_from <= occurred_at
            ):
                for production_key in production.keys:
                    if (
                        production_key.kid == event.producer_kid and production_key.did_key == event.producer_did_key
                        and "hook-event" in production_key.purposes
                    ):
                        return {
                            **evidence, "purposes": list(production_key.purposes),
                            "installation_id": production.installation_id, "generation": production.generation,
                            "binding_ids": [str(production.binding_id)],
                        }
        raise IngestRefused(403, "provenance_app_production")
