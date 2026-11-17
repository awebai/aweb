"""Evidence that a team key was set by the team's namespace controller.

AWID keeps the exact bytes the namespace controller signed to rotate a team's
key (``rotate_team_key``, in either the covering-v2 or the legacy controller
form) and serves them with the signer and signature. A relying server that has
pinned a team key accepts a different key only with such an act, signed by the
controller its own DNS lookup names, and newer than the act behind its pin.
Exact DNS keeps controller authority independent of the registry. Inherited
authority uses the ID tree's registry witness; that registry names the child
controller and can move the pin by lying about delegation.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import time

import httpx
from starlette.exceptions import HTTPException
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from awid.external_authority import TXTOutcomeResolver, discover_registry_authority
from awid.id_certificates import IDCertificateError, IDChainEvidence, namespace_controller_from_evidence
from awid.registry_types import RegistryError
from awid.federation_errors import FederationAuthorityError
from awid.id_tree_requests import CONTROLLER_REQUEST_TYPE
from awid.signing import verify_did_key_signature
from awid.team_ids import parse_team_id

logger = logging.getLogger(__name__)

ROTATE_TEAM_KEY_OPERATION = "rotate_team_key"
MAX_SIGNED_PAYLOAD_BYTES = 16384
CREATION_ACT_HEADER = "X-AWEB-Team-Key-Act"
CREATION_ACT_TYPE = "aweb.team-key-act"


def creation_act_payload(*, domain: str, name: str, team_did_key: str, body: bytes, timestamp: str) -> bytes:
    """A public commitment to creation, without the private request body."""
    from awid.signing import canonical_json_bytes
    return canonical_json_bytes({"v": 1, "type": CREATION_ACT_TYPE, "operation": "create_team",
        "domain": domain, "name": name, "team_did_key": team_did_key,
        "timestamp": timestamp, "body_sha256": hashlib.sha256(body).hexdigest()})


def creation_act_header(payload: bytes, signature: str) -> str:
    return json.dumps({"signed_payload": base64.urlsafe_b64encode(payload).rstrip(b"=").decode(),
                       "signature": signature}, separators=(",", ":"))


def checked_creation_act(header: str, *, signer: str, domain: str, name: str, team_did_key: str, body: bytes) -> dict:
    if len(header) > MAX_SIGNED_PAYLOAD_BYTES:
        raise TeamKeyActError("malformed", "creation header too large")
    try:
        value = json.loads(header)
        if type(value) is not dict or set(value) != {"signed_payload", "signature"}:
            raise ValueError("creation header fields")
        record = {**value, "signer_did_key": signer}
        act = verify_team_key_act(record, domain=domain, name=name, team_did_key=team_did_key)
        raw = _decode_payload(value["signed_payload"])
        payload = json.loads(raw)
        expected = creation_act_payload(domain=domain, name=name, team_did_key=team_did_key,
                                        body=body, timestamp=payload["timestamp"])
        if raw != expected or act.signer_did_key != signer:
            raise ValueError("creation request mismatch")
        return record
    except (ValueError, TypeError, KeyError) as exc:
        raise TeamKeyActError("malformed", "creation request mismatch") from exc



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
    creation = payload.get("operation") == "create_team"
    if creation:
        if (set(payload) != {"v", "type", "operation", "domain", "name", "team_did_key", "timestamp", "body_sha256"}
                or type(payload.get("v")) is not int or payload.get("v") != 1 or payload.get("type") != CREATION_ACT_TYPE
                or not isinstance(payload.get("body_sha256"), str) or len(payload["body_sha256"]) != 64
                or any(c not in "0123456789abcdef" for c in payload["body_sha256"])):
            raise TeamKeyActError("malformed", "creation payload")
    elif "v" in payload and (payload.get("v") != 2 or payload.get("type") != CONTROLLER_REQUEST_TYPE):
        raise TeamKeyActError("malformed", "envelope version")
    signed_at = _parse_timestamp(payload.get("timestamp"))
    if not creation and payload.get("operation") != ROTATE_TEAM_KEY_OPERATION:
        raise TeamKeyActError("wrong_operation")
    if payload.get("domain") != domain or payload.get("name") != name:
        raise TeamKeyActError("team_mismatch")
    if payload.get("team_did_key" if creation else "new_team_did_key") != team_did_key:
        raise TeamKeyActError("key_mismatch")
    try:
        verify_did_key_signature(did_key=signer, payload=raw, signature_b64=signature)
    except ValueError as exc:
        raise TeamKeyActError("bad_signature") from exc
    return TeamKeyAct(domain=domain, name=name, team_did_key=team_did_key, signer_did_key=signer, signed_at=signed_at)


async def dns_namespace_controller(
    domain: str, resolver: TXTOutcomeResolver,
    fetch_namespace_evidence: Callable[[str], Awaitable[IDChainEvidence]] | None = None,
) -> str:
    """The namespace controller ``_awid.<domain>`` (or the nearest ancestor
    record) names. Raises ``controller_unavailable`` when DNS names none."""
    try:
        authority = await discover_registry_authority(domain, resolver)
    except FederationAuthorityError as exc:
        raise TeamKeyActError("controller_unavailable", f"DNS lookup for {domain} failed") from exc
    if authority.selection != "dns" or not authority.controller_did:
        raise TeamKeyActError("controller_unavailable", f"no _awid record for {domain}")
    if authority.inherited:
        if fetch_namespace_evidence is None:
            raise TeamKeyActError("controller_unavailable", "delegation evidence required")
        try:
            evidence = await fetch_namespace_evidence(domain)
            return namespace_controller_from_evidence(evidence, domain)
        except IDCertificateError as exc:
            raise TeamKeyActError("controller_unavailable", "delegation evidence unavailable") from exc
    return authority.controller_did


async def verify_team_key_change(
    record: Any,
    *,
    domain: str,
    name: str,
    team_did_key: str,
    pinned_at: datetime | None,
    resolver: TXTOutcomeResolver,
    fetch_namespace_evidence: Callable[[str], Awaitable[IDChainEvidence]] | None = None,
) -> TeamKeyAct:
    """The act that moves a pinned team key to ``team_did_key``: a valid
    ``rotate_team_key`` act, newer than ``pinned_at`` (the act behind the
    current pin, if any), signed by the controller DNS names for ``domain``."""
    act = verify_team_key_act(record, domain=domain, name=name, team_did_key=team_did_key)
    if pinned_at is not None and act.signed_at <= pinned_at:
        raise TeamKeyActError("not_newer")
    controller = await dns_namespace_controller(domain, resolver, fetch_namespace_evidence)
    if act.signer_did_key != controller:
        raise TeamKeyActError("signer_not_controller")
    return act


@dataclass(frozen=True)
class TeamKeyPin:
    """The team key a relying server holds, and the signing time of the act
    that set it (None for a key pinned on first sight)."""

    team_did_key: str
    act_at: datetime | None
    act_key: str | None = None


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


class TeamKeyMemo:
    """Each team's last served key and the key ``pinned_team_key`` answered
    for it, for ``seconds``: the registry key's own freshness bound, so the
    memo adds no window the registry cache does not already allow. A request
    under the same served key reads neither the pin nor the act again, also
    while the answer is the pinned key rather than the served one."""

    def __init__(self, seconds: float = 60, clock: Callable[[], float] = time.monotonic) -> None:
        self._seconds = seconds
        self._clock = clock
        self._entries: dict[str, tuple[str, str, float, TeamKeyPin | None]] = {}

    def get(self, team_id: str, served_key: str) -> str | None:
        entry = self._entries.get(team_id)
        if entry is None or entry[0] != served_key or self._clock() >= entry[2]:
            return None
        return entry[1]

    def put(self, team_id: str, served_key: str, answer: str, *,
            seconds: float | None = None, proof: TeamKeyPin | None = None) -> None:
        ttl = self._seconds if seconds is None else min(self._seconds, max(0, seconds))
        self._entries[team_id] = (served_key, answer, self._clock() + ttl, proof)

    def proof(self, team_id: str, served_key: str) -> TeamKeyPin | None:
        return self._entries[team_id][3] if self.get(team_id, served_key) is not None else None


class TeamKeyUnverified(Exception):
    """The registry names a key for a pinned team that no valid act establishes."""

    def __init__(self, team_id: str, reason: str) -> None:
        super().__init__(f"{team_id}: {reason}")
        self.team_id = team_id
        self.reason = reason


async def pinned_team_key(
    team_id: str, served_key: str, *, pins: TeamKeyPinStore,
    fetch_act: Callable[[], Awaitable[Any]], resolver: TXTOutcomeResolver, enforce: bool,
    fetch_namespace_evidence: Callable[[str], Awaitable[IDChainEvidence]] | None = None,
    memo: TeamKeyMemo | None = None,
) -> str:
    """Resolve a pin, sharing the ID tree's evidence path and freshness ceiling.

    First admission remains TOFU for released creators without acts. A valid
    creation/current-key act seeds its floor, including on unchanged-key reads.
    Measuring moves retain the floor AND which key its proof actually named.
    """
    if memo is not None:
        remembered = memo.get(team_id, served_key)
        if remembered is not None:
            return remembered
    deadline = None
    proof = None

    async def namespace(domain):
        nonlocal deadline
        evidence = await fetch_namespace_evidence(domain)
        if evidence.age_seconds is not None:
            deadline = time.monotonic() + max(0, 60 - evidence.age_seconds)
        return evidence

    def witnessed(value):
        nonlocal proof
        proof = value

    answer = await _resolve_pin(team_id, served_key, pins=pins, fetch_act=fetch_act,
        resolver=resolver, enforce=enforce,
        fetch_namespace_evidence=namespace if fetch_namespace_evidence is not None else None,
        witnessed=witnessed)
    if memo is not None:
        memo.put(team_id, served_key, answer, proof=proof,
                 seconds=None if deadline is None else max(0, deadline - time.monotonic()))
    return answer


async def _resolve_pin(team_id, served_key, *, pins, fetch_act, resolver, enforce,
                       fetch_namespace_evidence, witnessed):
    pin = await pins.pin(team_id)
    if pin is None:
        pin = await pins.first_sight(team_id, served_key)
    baseline = pin.team_did_key == served_key
    if baseline and pin.act_at is not None and pin.act_key == served_key:
        witnessed(pin)
        return served_key
    domain, name = parse_team_id(team_id)
    try:
        try:
            record = await fetch_act()
        except (RegistryError, httpx.HTTPError, OSError, HTTPException) as exc:
            status = getattr(exc, "status_code", None)
            if not baseline or (status is not None and status < 500 and status != 429):
                raise
            # Baseline enrichment adds no outage dependency to an unchanged
            # admitted key. The very same error still refuses a key change.
            logger.warning("team_key_pin_baseline_unavailable team=%s reason=act_unavailable error=%s status=%s",
                           team_id, type(exc).__name__, status)
            return served_key
        if record is None:
            raise TeamKeyActError("no_act")
        act = await verify_team_key_change(record, domain=domain, name=name, team_did_key=served_key,
            pinned_at=None if baseline else pin.act_at, resolver=resolver,
            fetch_namespace_evidence=fetch_namespace_evidence)
        if baseline and pin.act_at is not None and act.signed_at < pin.act_at:
            raise TeamKeyActError("not_newer")
    except TeamKeyActError as exc:
        if exc.reason == "key_mismatch":
            logger.warning("team_key_pin_kept team=%s pinned=%s served=%s reason=%s",
                           team_id, pin.team_did_key, served_key, exc.reason)
            return pin.team_did_key
        if baseline and pin.act_at is None:
            # Released creation did not sign a public key act. Do not change
            # its admission contract; report it as unready for enforcement.
            logger.log(logging.DEBUG if exc.reason == "no_act" else logging.WARNING,
                       "team_key_pin_baseline_unavailable team=%s reason=%s", team_id, exc.reason)
            return served_key
        _mismatch(team_id, pin.team_did_key, served_key, exc.reason, enforce=enforce)
        return await _move_without_act(team_id, pins, pin, served_key, exc.reason)
    new = TeamKeyPin(served_key, act.signed_at, served_key)
    if not await pins.move(team_id, expected=pin, new=new):
        current = await pins.pin(team_id)
        if current is None and baseline:
            # The server admits its row later, after the member is verified.
            # Carry the checked proof into that admission transaction.
            witnessed(new)
            return served_key
        if current is not None and current.team_did_key == served_key:
            if current.act_key == served_key:
                witnessed(current)
            return served_key
        pinned = current or pin
        _mismatch(team_id, pinned.team_did_key, served_key, "pin_moved", enforce=enforce)
        return await _move_without_act(team_id, pins, pinned, served_key, "pin_moved")
    witnessed(new)
    logger.warning("team key pin for %s moved from %s to %s by the namespace controller act signed %s by %s",
                   team_id, pin.team_did_key, served_key, act.signed_at.isoformat(), act.signer_did_key)
    return served_key


def _mismatch(team_id: str, pinned: str, served: str, reason: str, *, enforce: bool) -> None:
    """Log the one ``team_key_pin_mismatch`` line; refuse when enforcing."""
    logger.warning(
        "team_key_pin_mismatch team=%s pinned=%s served=%s reason=%s enforced=%s",
        team_id, pinned, served, reason, "true" if enforce else "false",
    )
    if enforce:
        raise TeamKeyUnverified(team_id, reason)


async def _move_without_act(team_id: str, pins: TeamKeyPinStore, pin: TeamKeyPin, served: str, reason: str) -> str:
    """Before enforcement, the tolerated ``served`` key becomes the pin, so the
    key a member was verified under is the team's current key on this server.
    The time of the last accepted act is kept: no act moved it."""
    if await pins.move(team_id, expected=pin, new=TeamKeyPin(served, pin.act_at, pin.act_key)):
        logger.warning(
            "team_key_pin_moved_without_act team=%s from=%s to=%s reason=%s",
            team_id, pin.team_did_key, served, reason,
        )
    return served
