"""Delivering hook events: one signed ``hook-delivery`` request per binding,
through the shared egress guard.

Before each send the transport re-reads the producer's registration view: a
binding that is gone, or whose endpoint is no longer the one stored with the
delivery, is ``Cancelled`` and nothing is sent, and a stale view is retried,
so a revocation stops deliveries within the freshness bound. Each
request is signed afresh (``aweb_naapp.hooks.delivery.sign_delivery``) and sent
to the endpoint stored with the delivery, the owner-activated binding's origin
and path, never anywhere else.

Egress is the guard's: HTTPS only, redirects returned and never followed.
Every binding is first sent as a public destination. Whether its address is
internal is a fact about the operator's network, not about the binding, so
when the guard refuses that attempt because the name resolves to a denied
address, and only then, a self-hosted operator who both allows internal
destinations on its egress and names the network here gets exactly one more
attempt: the same request as an internal destination, which the guard resolves
afresh and accepts only if every address is inside that network. The guard
refuses before connecting, so the first attempt sent nothing. A hosted
deployment does neither, so its first refusal is final, whatever an owner
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
    Destination,
    Egress,
    EgressNotSent,
    EgressOutcomeUnknown,
    EgressRefused,
    HeaderRules,
    InternalDestinations,
    Response,
    parse_destination,
)
from aweb_naapp.hooks.delivery import SIGNED_PAYLOAD_HEADER, Delivery, sign_delivery
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
    ``key_valid_from`` and ``key_valid_until`` carry its published signing
    window when one exists. An unavailable signer leaves delivery pending.
    ``internal_cidr`` names the deployment network a self-hosted operator lets
    hooks reach, as well as the public internet; it requires an egress that
    allows internal destinations.
    """

    def __init__(
        self,
        *,
        seed: bytes,
        egress: Egress,
        registrations: Registrations,
        internal_cidr: IPv4Network | IPv6Network | None = None,
        key_valid_from: datetime | None = None,
        key_valid_until: datetime | None = None,
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
        self._key_valid_from = key_valid_from
        self._key_valid_until = key_valid_until
        self._clock = clock

    async def deliver(self, event: StoredEvent, target: Target) -> Outcome:
        view = await self._registrations.view(event.team_id, event.kind)
        if view is None or not view.is_fresh(self._clock()):
            return Retryable("registrations_unavailable")
        current = next((r for r in view.registrations if r.binding_id == target.id), None)
        if current is None:
            return Cancelled("binding_revoked")
        if (current.origin, current.method, current.path) != (
            target.meta["origin"],
            target.meta["method"],
            target.meta["path"],
        ):
            return Cancelled("binding_changed")
        if event.signature is None:
            return Permanent("unsigned_event")

        origin, method, path = target.meta["origin"], target.meta["method"], target.meta["path"]
        url = origin + path
        try:
            # Resolution can await across expiry. Check at the signing
            # boundary and use that same instant for the fresh credential.
            timestamp = self._clock()
            if (
                self._key_valid_from is not None and timestamp < self._key_valid_from
            ) or (
                self._key_valid_until is not None and timestamp >= self._key_valid_until
            ):
                return Retryable("signing_key_out_of_window")
            delivery = sign_delivery(
                self._seed,
                method,
                url,
                target.id,
                event.payload,
                event.signature,
                None,
                timestamp,
            )
            public = self._parse(self._destination(origin, method, path))
        except (Refused, EgressRefused) as refused:
            return Permanent(f"unsendable:{getattr(refused, 'code', 'refused')}")

        try:
            response = await self._send(delivery, url, public)
        except EgressRefused as refused:
            if refused.code != "destination_address_denied" or self._internal_cidr is None:
                return Permanent(f"egress_refused:{refused.code}")
            # The one retry: the same request, inside the operator's network.
            try:
                internal = self._parse(
                    {
                        **self._destination(origin, method, path),
                        "network": "internal",
                        "cidr": str(self._internal_cidr),
                    }
                )
                response = await self._send(delivery, url, internal)
            except EgressRefused as refused_inside:
                return Permanent(f"egress_refused:{refused_inside.code}")
            except EgressNotSent:
                return Retryable("not_sent")
            except EgressOutcomeUnknown:
                return Retryable("outcome_unknown")
        except EgressNotSent:
            return Retryable("not_sent")
        except EgressOutcomeUnknown:
            return Retryable("outcome_unknown")
        return _classify(response.status, response.body, str(event.event_id))

    async def _send(self, delivery: Delivery, url: str, destination: Destination) -> Response:
        return await self._egress.send(
            delivery.method,
            url,
            destination,
            header_rules=_RULES,
            headers=[("Content-Type", "application/json")],
            injected=[
                ("Authorization", delivery.headers["Authorization"]),
                (SIGNED_PAYLOAD_HEADER, delivery.headers[SIGNED_PAYLOAD_HEADER]),
            ],
            body=delivery.body,
        )

    def _parse(self, entry: dict[str, Any]) -> Destination:
        return parse_destination(
            entry, internal_destinations=self._egress.addresses.internal_destinations
        )

    @staticmethod
    def _destination(origin: str, method: str, path: str) -> dict[str, Any]:
        parts = urlsplit(origin)
        return {
            "host": parts.hostname,
            "port": parts.port or 443,
            "path": path,
            "methods": [method],
        }


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
