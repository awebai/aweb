"""The ``aweb.hook-event/1`` envelope: its signing bytes, signature and checks.

This is the Python reading of the contract in ``docs/hook-events.md``; the Go
authority in ``cli/go/hookevent`` pins the bytes, and both pass the same
public vector. ``verify`` proves self-consistency: the envelope is well
formed, belongs to the expected team, and was signed by the key it names as
its producer. Authority comes from resolving the producer's registered key
through the team's server, or from a client's team certificate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from awid.did import did_from_public_key, public_key_from_did
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from aweb_naapp.hooks.strictjson import (
    Refused,
    canonical,
    decode_base64url,
    decode_signature,
    encode_signature,
    parse_canonical_object,
)

__all__ = ["PREFIX", "Envelope", "Refused", "sign", "signing_bytes", "verify"]

PREFIX = b"aweb.hook-event/1\n"
CATALOG_ID = "aweb.hooks"
CATALOG_VERSION = 1

# Each v1 hook's firing class and the producer kinds that may sign it. The
# tests check this table against the catalog vector.
HOOKS: dict[str, tuple[str, tuple[str, ...]]] = {
    "post-secret-use-hook": ("server", ("app",)),
    "post-governance-hook": ("server", ("app",)),
    "post-manifest-command-hook": ("server", ("app",)),
    "post-mutation-hook": ("server", ("core",)),
    "post-command-hook": ("client", ("client",)),
}

UUID_PATTERN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_TRACE_ID = re.compile(r"[0-9a-f]{32}")
TEAM_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}:[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?")
_ORIGIN = re.compile(r"https://[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?")
_KID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_DID_KEY = re.compile(r"did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}")
_DID_AW = re.compile(r"did:aw:[1-9A-HJ-NP-Za-km-z]{20,32}")
_APP_ID = re.compile(r"[a-z][a-z0-9-]{0,62}")
_CERTIFICATE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_ALIAS = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}")

_EVENT_TIME = "%Y-%m-%dT%H:%M:%S.%fZ"
_MAX_ATTESTATIONS = 4
_MAX_ATTESTATION_BYTES = 8192
_AUTHORITY_MODES = (
    "team_cert",
    "identity_grant",
    "app_key",
    "link_capability",
    "owner_act",
    "system",
)
_RESULT_STATUSES = ("success", "denied", "failed", "outcome_unknown")
_TOP_FIELDS = (
    "v", "type", "catalog", "hook", "event_id", "trace", "team_id", "producer",
    "actor", "occurred_at", "fired_at", "result_status", "payload",
)  # fmt: skip


@dataclass(frozen=True)
class Envelope:
    """A verified hook event."""

    fields: dict[str, Any]
    hook: str
    event_id: str
    team_id: str
    producer_kind: str
    producer_did_key: str
    producer_kid: str
    # The producer as a delivery credential names it: "core", "app:<app_id>"
    # or "client:<certificate_id>".
    producer: str


def signing_bytes(envelope: dict[str, Any]) -> bytes:
    """Validate an envelope and return the prefix followed by its canonical JSON."""
    encoded = canonical(envelope)
    _check_envelope(parse_canonical_object(encoded))
    return PREFIX + encoded


def sign(seed: bytes, envelope: dict[str, Any]) -> tuple[bytes, str]:
    """Return an envelope's signing bytes and detached signature. ``seed`` is
    the producer's Ed25519 seed; its key must be the envelope's producer key."""
    signing = signing_bytes(envelope)
    key = SigningKey(seed)
    if envelope["producer"]["did_key"] != did_from_public_key(bytes(key.verify_key)):
        raise Refused("signer_mismatch", "the key is not the producer's did_key")
    return signing, encode_signature(key.sign(signing).signature)


def verify(signing: bytes, signature: str, *, team_id: str) -> Envelope:
    """Check signing bytes and a signature in the contract's order and return
    the envelope, or raise the first refusal. ``team_id`` is required."""
    if not team_id:
        raise Refused("verifier_misconfigured", "an expected team is required")
    envelope = open_envelope(signing)
    if envelope.team_id != team_id:
        raise Refused("team_mismatch", f"event team {envelope.team_id}, expected {team_id}")
    verify_signature(envelope.producer_did_key, signing, signature)
    return envelope


def open_envelope(signing: bytes) -> Envelope:
    """Every check but the expected team and the signature."""
    if not signing.startswith(PREFIX):
        raise Refused("wrong_prefix", "signing bytes do not start with the envelope prefix")
    return _check_envelope(parse_canonical_object(signing[len(PREFIX) :]))


def verify_signature(did_key: str, message: bytes, signature: str) -> None:
    try:
        public_key = public_key_from_did(did_key)
    except ValueError:
        raise Refused("bad_signature", "did:key does not decode") from None
    raw = decode_signature(signature)
    try:
        VerifyKey(public_key).verify(message, raw)
    except BadSignatureError:
        raise Refused("bad_signature", "signature does not verify") from None


def _check_envelope(f: dict[str, Any]) -> Envelope:
    check_keys(f, "", _TOP_FIELDS)
    if not _is_int(f["v"]) or f["v"] != 1:
        raise Refused("invalid_value", "v")
    if f["type"] != "aweb.hook-event":
        raise Refused("invalid_value", "type")

    catalog = _object(f, "catalog")
    check_keys(catalog, "catalog.", ("id", "version"))
    if (
        catalog["id"] != CATALOG_ID
        or not _is_int(catalog["version"])
        or catalog["version"] != CATALOG_VERSION
    ):
        raise Refused("unknown_catalog", f"{catalog['id']} version {catalog['version']}")
    hook = f["hook"]
    if not isinstance(hook, str) or hook not in HOOKS:
        raise Refused("unknown_hook", str(hook))

    _match(f, "event_id", UUID_PATTERN)
    trace = _object(f, "trace")
    check_keys(trace, "trace.", ("id", "origin"))
    trace_id = trace["id"]
    if not isinstance(trace_id, str) or not _TRACE_ID.fullmatch(trace_id) or trace_id == "0" * 32:
        raise Refused("invalid_value", "trace.id")
    _one_of(trace, "origin", "trace.", ("signed_request", "producer"))
    _match(f, "team_id", TEAM_ID_PATTERN)

    producer = _object(f, "producer")
    kind, producer_name, kid = _check_producer(producer)
    actor = _object(f, "actor")
    _check_actor(actor)

    for name in ("occurred_at", "fired_at"):
        exact_time(f, name, _EVENT_TIME, milliseconds=True)
    if f["fired_at"] < f["occurred_at"]:
        raise Refused("invalid_value", "fired_at precedes occurred_at")
    _one_of(f, "result_status", "", _RESULT_STATUSES)
    _check_payload_shape(f["payload"])

    if kind not in HOOKS[hook][1]:
        raise Refused("producer_not_allowed", f"{kind} may not sign {hook}")
    if kind == "client" and (
        actor.get("did_key") != producer["did_key"]
        or actor.get("certificate_id") != producer["certificate_id"]
    ):
        raise Refused("actor_not_signer", "a client event's actor is its signer")
    return Envelope(
        fields=f,
        hook=hook,
        event_id=f["event_id"],
        team_id=f["team_id"],
        producer_kind=kind,
        producer_did_key=producer["did_key"],
        producer_kid=kid,
        producer=producer_name,
    )


def _check_producer(p: dict[str, Any]) -> tuple[str, str, str]:
    kind = p.get("kind")
    if kind == "core":
        check_keys(p, "producer.", ("kind", "origin", "kid", "did_key", "seq"))
        name = "core"
    elif kind == "app":
        check_keys(
            p,
            "producer.",
            ("kind", "origin", "app_id", "installation_id", "generation", "kid", "did_key", "seq"),
        )
        _match(p, "app_id", _APP_ID)
        _match(p, "installation_id", UUID_PATTERN)
        _positive(p, "generation")
        name = "app:" + p["app_id"]
    elif kind == "client":
        check_keys(p, "producer.", ("kind", "did_key", "certificate_id"))
        _match(p, "certificate_id", _CERTIFICATE_ID)
        name = "client:" + p["certificate_id"]
    else:
        raise Refused("invalid_value", "producer.kind")
    kid = ""
    if kind != "client":
        _match(p, "origin", _ORIGIN)
        _match(p, "kid", _KID)
        _positive(p, "seq")
        kid = p["kid"]
    _ed25519_did_key(p, "did_key", "producer.")
    return kind, name, kid


def _check_actor(a: dict[str, Any]) -> None:
    identity = ("did_key", "did_aw", "certificate_id", "alias", "grant_id")
    check_keys(a, "actor.", ("authority_mode", "attestations"), identity)
    _one_of(a, "authority_mode", "actor.", _AUTHORITY_MODES)
    mode = a["authority_mode"]
    if mode == "system":
        for name in identity:
            if name in a:
                raise Refused("invalid_value", f"actor.{name}: a system actor has no identity")
    elif "did_key" not in a:
        raise Refused("missing_field", "actor.did_key")
    if (mode == "identity_grant") != ("grant_id" in a):
        raise Refused("invalid_value", "actor.grant_id belongs to identity_grant authority only")
    checks = {
        "alias": _ALIAS,
        "certificate_id": _CERTIFICATE_ID,
        "did_aw": _DID_AW,
        "did_key": _DID_KEY,
        "grant_id": UUID_PATTERN,
    }
    for name in sorted(checks):
        if name in a:
            _match(a, name, checks[name], "actor.")
    if "did_key" in a:
        _ed25519_did_key(a, "did_key", "actor.")
    attestations = a["attestations"]
    if not isinstance(attestations, list) or len(attestations) > _MAX_ATTESTATIONS:
        raise Refused("invalid_value", "actor.attestations")
    for item in attestations:
        if not isinstance(item, str) or not item or len(item) > _MAX_ATTESTATION_BYTES:
            raise Refused("invalid_value", "actor.attestations")
        decode_base64url(item, "actor.attestations")


def _check_payload_shape(value: Any) -> None:
    """The shape every catalog payload shares: a flat object of strings,
    integers, booleans and lists of strings. The catalog reader checks the
    allowlist itself."""
    if not isinstance(value, dict):
        raise Refused("invalid_value", "payload is not an object")
    for name in sorted(value):
        item = value[name]
        if isinstance(item, list):
            if not all(isinstance(entry, str) for entry in item):
                raise Refused("invalid_value", f"payload.{name}")
        elif not isinstance(item, (str, int, bool)):
            raise Refused("invalid_value", f"payload.{name}")


def check_keys(
    obj: dict[str, Any], prefix: str, required: tuple[str, ...], optional: tuple[str, ...] = ()
) -> None:
    allowed = set(required) | set(optional)
    for name in sorted(obj):
        if name not in allowed:
            raise Refused("unknown_field", f"{prefix}{name}")
    for name in sorted(required):
        if name not in obj:
            raise Refused("missing_field", f"{prefix}{name}")


def _object(f: dict[str, Any], name: str) -> dict[str, Any]:
    value = f[name]
    if not isinstance(value, dict):
        raise Refused("invalid_value", f"{name} is not an object")
    return value


def _match(f: dict[str, Any], name: str, pattern: re.Pattern[str], prefix: str = "") -> None:
    value = f[name]
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise Refused("invalid_value", f"{prefix}{name}")


def _one_of(f: dict[str, Any], name: str, prefix: str, options: tuple[str, ...]) -> None:
    value = f[name]
    if not isinstance(value, str) or value not in options:
        raise Refused("invalid_value", f"{prefix}{name}")


def _positive(f: dict[str, Any], name: str) -> None:
    value = f[name]
    if not _is_int(value) or value < 1:
        raise Refused("invalid_value", name)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _ed25519_did_key(f: dict[str, Any], name: str, prefix: str) -> None:
    _match(f, name, _DID_KEY, prefix)
    try:
        public_key_from_did(f[name])
    except ValueError:
        raise Refused("invalid_value", f"{prefix}{name} is not an Ed25519 did:key") from None


def exact_time(f: dict[str, Any], name: str, layout: str, *, milliseconds: bool = False) -> None:
    """Accept a time only in its one canonical spelling under ``layout``."""
    value = f[name]
    if not isinstance(value, str):
        raise Refused("invalid_value", name)
    try:
        parsed = datetime.strptime(value, layout)
    except ValueError:
        raise Refused("invalid_value", name) from None
    spelled = parsed.strftime(layout)
    if milliseconds:
        spelled = spelled[:-4] + "Z"
    if spelled != value:
        raise Refused("invalid_value", name)
