"""Evidence that a team key was set by the team's namespace controller.

AWID keeps the exact bytes the namespace controller signed to rotate a team's
key (``rotate_team_key``, in either the covering-v2 or the legacy controller
form) and serves them with the signer and signature. A relying server that has
pinned a team key accepts a different key only with such an act, signed by the
controller its own DNS lookup names, and newer than the act behind its pin.
Nothing here trusts the registry beyond the bytes it returns.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from awid.external_authority import TXTOutcomeResolver, discover_registry_authority
from awid.federation_errors import FederationAuthorityError
from awid.id_tree_requests import CONTROLLER_REQUEST_TYPE
from awid.signing import verify_did_key_signature
from awid.team_ids import parse_team_id

logger = logging.getLogger(__name__)

ROTATE_TEAM_KEY_OPERATION = "rotate_team_key"
MAX_SIGNED_PAYLOAD_BYTES = 16384


class TeamKeyActError(Exception):
    """A team-key act that does not establish the key.

    ``reason`` is one of: malformed, wrong_operation, team_mismatch,
    key_mismatch, bad_signature, not_newer, controller_unavailable,
    signer_not_controller, no_act.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass(frozen=True)
class TeamKeyAct:
    domain: str
    name: str
    team_did_key: str
    signer_did_key: str
    signed_at: datetime


def _decode_payload(value: Any) -> bytes:
    if not isinstance(value, str) or not value or len(value) > MAX_SIGNED_PAYLOAD_BYTES * 2:
        raise TeamKeyActError("malformed", "signed_payload")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as exc:
        raise TeamKeyActError("malformed", "signed_payload") from exc
    if len(raw) > MAX_SIGNED_PAYLOAD_BYTES:
        raise TeamKeyActError("malformed", "signed_payload")
    return raw


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise TeamKeyActError("malformed", "timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TeamKeyActError("malformed", "timestamp") from exc
    if parsed.tzinfo is None:
        raise TeamKeyActError("malformed", "timestamp")
    return parsed


def verify_team_key_act(record: Any, *, domain: str, name: str, team_did_key: str) -> TeamKeyAct:
    """Check that ``record`` is a ``rotate_team_key`` act for exactly this team
    and key, signed by its stated signer. Who the signer must be is the
    caller's DNS question (``verify_team_key_change``)."""
    if not isinstance(record, Mapping):
        raise TeamKeyActError("malformed", "record")
    signer = record.get("signer_did_key")
    signature = record.get("signature")
    if not isinstance(signer, str) or not isinstance(signature, str):
        raise TeamKeyActError("malformed", "signer or signature")
    raw = _decode_payload(record.get("signed_payload"))
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise TeamKeyActError("malformed", "signed_payload") from exc
    if not isinstance(payload, dict):
        raise TeamKeyActError("malformed", "signed_payload")
    if "v" in payload and (payload.get("v") != 2 or payload.get("type") != CONTROLLER_REQUEST_TYPE):
        raise TeamKeyActError("malformed", "envelope version")
    signed_at = _parse_timestamp(payload.get("timestamp"))
    if payload.get("operation") != ROTATE_TEAM_KEY_OPERATION:
        raise TeamKeyActError("wrong_operation")
    if payload.get("domain") != domain or payload.get("name") != name:
        raise TeamKeyActError("team_mismatch")
    if payload.get("new_team_did_key") != team_did_key:
        raise TeamKeyActError("key_mismatch")
    try:
        verify_did_key_signature(did_key=signer, payload=raw, signature_b64=signature)
    except ValueError as exc:
        raise TeamKeyActError("bad_signature") from exc
    return TeamKeyAct(domain=domain, name=name, team_did_key=team_did_key, signer_did_key=signer, signed_at=signed_at)


async def dns_namespace_controller(domain: str, resolver: TXTOutcomeResolver) -> str:
    """The namespace controller ``_awid.<domain>`` (or the nearest ancestor
    record) names. Raises ``controller_unavailable`` when DNS names none."""
    try:
        authority = await discover_registry_authority(domain, resolver)
    except FederationAuthorityError as exc:
        raise TeamKeyActError("controller_unavailable", f"DNS lookup for {domain} failed") from exc
    if authority.selection != "dns" or not authority.controller_did:
        raise TeamKeyActError("controller_unavailable", f"no _awid record for {domain}")
    return authority.controller_did


async def verify_team_key_change(
    record: Any,
    *,
    domain: str,
    name: str,
    team_did_key: str,
    pinned_at: datetime | None,
    resolver: TXTOutcomeResolver,
) -> TeamKeyAct:
    """The act that moves a pinned team key to ``team_did_key``: a valid
    ``rotate_team_key`` act, newer than ``pinned_at`` (the act behind the
    current pin, if any), signed by the controller DNS names for ``domain``."""
    act = verify_team_key_act(record, domain=domain, name=name, team_did_key=team_did_key)
    if pinned_at is not None and act.signed_at <= pinned_at:
        raise TeamKeyActError("not_newer")
    controller = await dns_namespace_controller(domain, resolver)
    if act.signer_did_key != controller:
        raise TeamKeyActError("signer_not_controller")
    return act


@dataclass(frozen=True)
class TeamKeyPin:
    """The team key a relying server holds, and the signing time of the act
    that set it (None for a key pinned on first sight)."""

    team_did_key: str
    act_at: datetime | None


class TeamKeyPinStore(Protocol):
    """Where a relying server keeps its team-key pins."""

    async def pin(self, team_id: str) -> TeamKeyPin | None:
        """The current pin, or None for a team never seen."""

    async def first_sight(self, team_id: str, team_did_key: str) -> TeamKeyPin:
        """Record ``team_did_key`` as the pin of a team never seen, and return
        the pin now held (another writer's, if it got there first)."""

    async def move(self, team_id: str, *, expected: TeamKeyPin, new: TeamKeyPin) -> bool:
        """Replace ``expected`` with ``new``; False when the pin is no longer ``expected``."""


class MemoryTeamKeyPins:
    """Pins held for the life of the process."""

    def __init__(self) -> None:
        self._pins: dict[str, TeamKeyPin] = {}

    async def pin(self, team_id: str) -> TeamKeyPin | None:
        return self._pins.get(team_id)

    async def first_sight(self, team_id: str, team_did_key: str) -> TeamKeyPin:
        return self._pins.setdefault(team_id, TeamKeyPin(team_did_key, None))

    async def move(self, team_id: str, *, expected: TeamKeyPin, new: TeamKeyPin) -> bool:
        if self._pins.get(team_id) != expected:
            return False
        self._pins[team_id] = new
        return True


class TeamKeyUnverified(Exception):
    """The registry names a key for a pinned team that no valid act establishes."""

    def __init__(self, team_id: str, reason: str) -> None:
        super().__init__(f"{team_id}: {reason}")
        self.team_id = team_id
        self.reason = reason


async def pinned_team_key(
    team_id: str,
    served_key: str,
    *,
    pins: TeamKeyPinStore,
    fetch_act: Callable[[], Awaitable[Any]],
    resolver: TXTOutcomeResolver,
    enforce: bool,
) -> str:
    """``served_key`` when it is the team's pinned key, or when the namespace
    controller's act (``fetch_act()``, None when the registry has none) moves
    the pin to it. Otherwise the mismatch is logged as
    ``team_key_pin_mismatch`` and, with ``enforce``, refused with
    TeamKeyUnverified; without it (the staged measuring mode) ``served_key``
    is returned and the pin stays. A team never seen is pinned to
    ``served_key``. Registry read errors from ``fetch_act`` propagate."""
    pin = await pins.pin(team_id)
    if pin is None:
        pin = await pins.first_sight(team_id, served_key)
    if pin.team_did_key == served_key:
        return served_key
    domain, name = parse_team_id(team_id)
    try:
        record = await fetch_act()
        if record is None:
            raise TeamKeyActError("no_act")
        act = await verify_team_key_change(
            record, domain=domain, name=name, team_did_key=served_key, pinned_at=pin.act_at, resolver=resolver,
        )
    except TeamKeyActError as exc:
        return _mismatch(team_id, pin.team_did_key, served_key, exc.reason, enforce=enforce)
    if not await pins.move(team_id, expected=pin, new=TeamKeyPin(served_key, act.signed_at)):
        current = await pins.pin(team_id)
        if current is None or current.team_did_key != served_key:
            pinned = current.team_did_key if current is not None else pin.team_did_key
            return _mismatch(team_id, pinned, served_key, "pin_moved", enforce=enforce)
        return served_key
    logger.warning(
        "team key pin for %s moved from %s to %s by the namespace controller act signed %s by %s",
        team_id, pin.team_did_key, served_key, act.signed_at.isoformat(), act.signer_did_key,
    )
    return served_key


def _mismatch(team_id: str, pinned: str, served: str, reason: str, *, enforce: bool) -> str:
    """Log the one ``team_key_pin_mismatch`` line; refuse when enforcing,
    else serve the registry's key and leave the pin."""
    logger.warning(
        "team_key_pin_mismatch team=%s pinned=%s served=%s reason=%s enforced=%s",
        team_id, pinned, served, reason, "true" if enforce else "false",
    )
    if enforce:
        raise TeamKeyUnverified(team_id, reason)
    return served
