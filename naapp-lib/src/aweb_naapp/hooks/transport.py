"""Delivering hook events: one signed ``hook-delivery`` request per binding,
through the shared egress guard.

Before each send the transport re-reads the producer's registration view: a
binding that is gone is ``Cancelled`` and nothing is sent, and a stale view is
retried, so a revocation stops deliveries within the freshness bound. Each
request is signed afresh (``aweb_naapp.hooks.delivery.sign_delivery``) and sent
to the endpoint stored with the delivery, the owner-activated binding's origin
and path, never anywhere else.

Egress is the guard's: HTTPS only, redirects returned and never followed. A
destination inside the deployment's network is reachable only when a
self-hosted operator both allows internal destinations on its egress and names
the network here; a hosted deployment does neither, whatever an owner
configures.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from ipaddress import IPv4Network, IPv6Network
from typing import Any
from urllib.parse import urlsplit

from aweb_naapp.egress import (
    Egress,
    EgressNotSent,
    EgressOutcomeUnknown,
    EgressRefused,
    HeaderRules,
    InternalDestinations,
    parse_destination,
)
from aweb_naapp.hooks.delivery import SIGNED_PAYLOAD_HEADER, sign_delivery
from aweb_naapp.hooks.producer import Registrations
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp.outbox import (
    Acked,
    Cancelled,
    Conflict,
    Outcome,
    Permanent,
    Retryable,
    StoredEvent,
    Target,
)

__all__ = ["HookTransport"]

# The delivery credential is set through the guard's injection, the only way
# an Authorization header reaches the wire. The caller's own header is the
# fixed Content-Type, which is never a credential.
_RULES = HeaderRules(
    injected=("authorization", SIGNED_PAYLOAD_HEADER.lower()),
    amz_allowed=(),
    is_credential=lambda value: False,
)
# Retried with backoff: the target may recover or its registry view refresh.
_RETRIED_STATUSES = frozenset({408, 425, 429})
_ACK_DISPOSITIONS = {"appended": "delivered", "duplicate": "duplicate"}


def _now() -> datetime:
    return datetime.now(UTC)


class HookTransport:
    """The outbox transport for the ``hooks`` channel.

    ``seed`` is the producer's key, the one that signs its events.
    ``internal_cidr`` names the deployment network a self-hosted operator lets
    hooks reach; it requires an egress that allows internal destinations.
    """

    def __init__(
        self,
        *,
        seed: bytes,
        egress: Egress,
        registrations: Registrations,
        internal_cidr: IPv4Network | IPv6Network | None = None,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        if (
            internal_cidr is not None
            and egress.addresses.internal_destinations is not InternalDestinations.ALLOWED
        ):
            raise ValueError("an internal hook network needs an egress that allows it")
        self._seed = seed
        self._egress = egress
        self._registrations = registrations
        self._internal_cidr = internal_cidr
        self._clock = clock

    async def deliver(self, event: StoredEvent, target: Target) -> Outcome:
        view = await self._registrations.view(event.team_id, event.kind)
        if view is None or not view.is_fresh(self._clock()):
            return Retryable("registrations_unavailable")
        if all(r.binding_id != target.id for r in view.registrations):
            return Cancelled("binding_revoked")
        if event.signature is None:
            return Permanent("unsigned_event")

        origin, method, path = target.meta["origin"], target.meta["method"], target.meta["path"]
        url = origin + path
        try:
            delivery = sign_delivery(
                self._seed,
                method,
                url,
                target.id,
                event.payload,
                event.signature,
                None,
                datetime.now(UTC),
            )
            destination = parse_destination(
                self._destination(origin, method, path),
                internal_destinations=self._egress.addresses.internal_destinations,
            )
        except (Refused, EgressRefused) as refused:
            return Permanent(f"unsendable:{getattr(refused, 'code', 'refused')}")

        authorization = delivery.headers["Authorization"]
        signed_payload = delivery.headers[SIGNED_PAYLOAD_HEADER]
        try:
            response = await self._egress.send(
                delivery.method,
                url,
                destination,
                header_rules=_RULES,
                headers=[("Content-Type", "application/json")],
                injected=[
                    ("Authorization", authorization),
                    (SIGNED_PAYLOAD_HEADER, signed_payload),
                ],
                body=delivery.body,
            )
        except EgressRefused as refused:
            return Permanent(f"egress_refused:{refused.code}")
        except EgressNotSent:
            return Retryable("not_sent")
        except EgressOutcomeUnknown:
            return Retryable("outcome_unknown")
        return _classify(response.status, response.body, str(event.event_id))

    def _destination(self, origin: str, method: str, path: str) -> dict[str, Any]:
        parts = urlsplit(origin)
        entry: dict[str, Any] = {
            "host": parts.hostname,
            "port": parts.port or 443,
            "path": path,
            "methods": [method],
        }
        if self._internal_cidr is not None:
            entry.update(network="internal", cidr=str(self._internal_cidr))
        return entry


def _classify(status: int, body: bytes, event_id: str) -> Outcome:
    if 200 <= status < 300:
        return _ack(body, event_id)
    if status == 409:
        return Conflict()
    if status >= 500 or status in _RETRIED_STATUSES:
        return Retryable(f"http_{status}")
    # A redirect is never followed, and an authorization or schema rejection
    # may come from a stale registry view: the outbox retries these a bounded
    # number of times, then ends the delivery rejected.
    return Permanent(f"http_{status}")


def _ack(body: bytes, event_id: str) -> Outcome:
    try:
        ack = json.loads(body)
    except ValueError:
        return Permanent("invalid_ack")
    if not isinstance(ack, dict) or ack.get("event_id") != event_id:
        return Permanent("invalid_ack")
    disposition = _ACK_DISPOSITIONS.get(ack.get("disposition"))  # type: ignore[arg-type]
    if disposition is None:
        return Permanent("invalid_ack")
    # The receipt is kept as the target gave it, re-serialized with sorted keys.
    receipt = ack.get("receipt")
    return Acked(
        disposition,  # type: ignore[arg-type]
        None if receipt is None else json.dumps(receipt, sort_keys=True).encode(),
    )
