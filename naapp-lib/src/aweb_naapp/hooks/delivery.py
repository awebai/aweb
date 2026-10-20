"""The ``AWEB-Hook DIDKey`` delivery credential that carries one event to one binding.

This is the Python reading of the contract in ``docs/hook-events.md``; the Go
authority in ``cli/go/hookevent`` pins the bytes, and both pass the same
public vector. A client delivery is authorized here by its team certificate,
signed by the team's current controller key and naming the event's producer;
the certificate's revocation status is the shared team-auth verifier's to
check. A server delivery is self-consistent here, and its authority comes from
resolving the producer's registered key and active production through the
team's server.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from awid.did import did_from_public_key
from awid.team_certificate import (
    TeamCertificateError,
    decode_team_certificate,
    verify_team_certificate_signature,
)
from nacl.signing import SigningKey

from aweb_naapp.hooks.envelope import (
    TEAM_ID_PATTERN,
    UUID_PATTERN,
    Envelope,
    check_keys,
    exact_time,
    open_envelope,
    verify,
    verify_signature,
)
from aweb_naapp.hooks.strictjson import (
    Refused,
    canonical,
    decode_base64url,
    encode_base64url,
    encode_signature,
    parse_canonical_object,
)

AUTH_SCHEME = "AWEB-Hook DIDKey "
SIGNED_PAYLOAD_HEADER = "X-AWEB-Signed-Payload"
CERTIFICATE_HEADER = "X-AWID-Team-Certificate"
REPLAY_WINDOW = timedelta(seconds=300)

_DELIVERY_TIME = "%Y-%m-%dT%H:%M:%SZ"
_PAYLOAD_FIELDS = (
    "v", "auth", "aud", "method", "path", "body_sha256", "team_id", "binding_id",
    "event_id", "producer", "kid", "did_key", "timestamp",
)  # fmt: skip


@dataclass(frozen=True)
class Delivery:
    """One signed hook delivery request."""

    method: str
    path: str
    headers: dict[str, str]
    body: bytes
    # The canonical payload the Authorization signature covers.
    signed_payload: bytes


@dataclass(frozen=True)
class ReceiveOptions:
    """What the target knows independently of the request: its public origin,
    the binding the delivery must name, the team's current controller key
    (read fresh from the registry, for a client's certificate) and its clock.
    ``audience`` and ``binding_id`` are required."""

    audience: str
    binding_id: str
    now: datetime
    team_key_did: str = ""


@dataclass(frozen=True)
class Received:
    """A delivery that passed every check, with its verified event."""

    payload: dict[str, Any]
    envelope: Envelope


def sign_delivery(
    seed: bytes,
    method: str,
    target: str,
    binding_id: str,
    signing: bytes,
    signature: str,
    certificate_header: str | None,
    timestamp: datetime,
) -> Delivery:
    """Build the request that delivers one signed event to one binding.

    ``target`` is the binding's origin and raw path. A client producer passes
    its encoded team certificate, which must name the event's producer key and
    certificate; a server producer passes None.
    """
    envelope = open_envelope(signing)
    verify_signature(envelope.producer_did_key, signing, signature)
    key = SigningKey(seed)
    did_key = did_from_public_key(bytes(key.verify_key))
    if did_key != envelope.producer_did_key:
        raise Refused("signer_mismatch", "the key is not the event's producer key")
    if envelope.producer_kind == "client":
        if not certificate_header:
            raise Refused("certificate_missing", "a client delivery carries its team certificate")
        _certificate_names_producer(_decode_certificate(certificate_header), envelope)
    elif certificate_header is not None:
        raise Refused("invalid_value", "only a client delivery carries a team certificate")
    parts = urlsplit(target)
    if parts.scheme != "https" or not parts.netloc:
        raise Refused("invalid_value", "target must be an https URL")
    if not UUID_PATTERN.fullmatch(binding_id):
        raise Refused("invalid_value", "binding_id")

    body = canonical({"hook_event": encode_base64url(signing), "signature": signature})
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    payload = canonical(
        {
            "v": 1,
            "auth": "hook-delivery",
            "aud": f"https://{parts.netloc}",
            "method": method.upper(),
            "path": path,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "team_id": envelope.team_id,
            "binding_id": binding_id,
            "event_id": envelope.event_id,
            "producer": envelope.producer,
            "kid": _credential_kid(envelope),
            "did_key": did_key,
            "timestamp": _utc(timestamp, "the delivery timestamp").strftime(_DELIVERY_TIME),
        }
    )
    headers = {
        "Authorization": AUTH_SCHEME
        + did_key
        + " "
        + encode_signature(key.sign(payload).signature),
        SIGNED_PAYLOAD_HEADER: encode_base64url(payload),
        "Content-Type": "application/json",
    }
    if certificate_header:
        headers[CERTIFICATE_HEADER] = certificate_header
    return Delivery(method.upper(), path, headers, body, payload)


def verify_delivery(
    method: str, path: str, headers: dict[str, str], body: bytes, options: ReceiveOptions
) -> Received:
    """Check a hook delivery in the contract's order and return the verified
    event, or raise the first refusal."""
    if not options.audience or not options.binding_id:
        raise Refused("verifier_misconfigured", "an audience and a binding are required")
    _utc(options.now, "the receiver's clock")
    authorization = _header(headers, "Authorization")
    if not authorization.startswith(AUTH_SCHEME):
        raise Refused("wrong_scheme", "not an AWEB-Hook credential")
    parts = authorization[len(AUTH_SCHEME) :].split(" ")
    if len(parts) != 2:
        raise Refused("wrong_scheme", "malformed AWEB-Hook credential")
    header_did_key, auth_signature = parts

    signed_payload = decode_base64url(_header(headers, SIGNED_PAYLOAD_HEADER), "the signed payload")
    payload = parse_canonical_object(signed_payload)
    verify_signature(header_did_key, signed_payload, auth_signature)
    if payload.get("auth") != "hook-delivery":
        raise Refused("wrong_auth", str(payload.get("auth")))
    check_keys(payload, "", _PAYLOAD_FIELDS)
    if payload["did_key"] != header_did_key:
        raise Refused("signer_mismatch", "payload did_key differs from the header")
    if payload["v"] != 1 or isinstance(payload["v"], bool):
        raise Refused("invalid_value", "v")
    team_id = payload["team_id"]
    if not isinstance(team_id, str) or not TEAM_ID_PATTERN.fullmatch(team_id):
        raise Refused("invalid_value", "team_id")
    if payload["aud"] != options.audience:
        raise Refused("audience_mismatch", str(payload["aud"]))
    if payload["method"] != method.upper() or payload["path"] != path:
        raise Refused("request_mismatch", f"signed for {payload['method']} {payload['path']}")
    if payload["body_sha256"] != hashlib.sha256(body).hexdigest():
        raise Refused("body_mismatch", "body_sha256")
    exact_time(payload, "timestamp", _DELIVERY_TIME)
    signed_at = datetime.strptime(payload["timestamp"], _DELIVERY_TIME)
    if abs(_utc(options.now, "the receiver's clock") - signed_at) > REPLAY_WINDOW:
        raise Refused("timestamp_outside_window", payload["timestamp"])
    if payload["binding_id"] != options.binding_id:
        raise Refused("binding_mismatch", str(payload["binding_id"]))

    try:
        body_object = parse_canonical_object(body)
        check_keys(body_object, "body.", ("hook_event", "signature"))
        event_text = body_object["hook_event"]
        if not isinstance(event_text, str):
            raise Refused("invalid_value", "hook_event")
        signing = decode_base64url(event_text, "hook_event")
    except Refused as refused:
        raise Refused("invalid_body", str(refused)) from None
    envelope = verify(signing, str(body_object["signature"]), team_id=team_id)
    if payload["event_id"] != envelope.event_id:
        raise Refused("event_mismatch", f"credential names {payload['event_id']}")
    if (
        payload["producer"] != envelope.producer
        or payload["did_key"] != envelope.producer_did_key
        or payload["kid"] != _credential_kid(envelope)
    ):
        raise Refused("producer_mismatch", "the credential's signer is not the event's producer")
    if envelope.producer_kind == "client":
        _verify_client_certificate(
            _header(headers, CERTIFICATE_HEADER), envelope, options.team_key_did
        )
    return Received(payload=payload, envelope=envelope)


def _verify_client_certificate(encoded: str, envelope: Envelope, team_key_did: str) -> None:
    if not encoded:
        raise Refused("certificate_missing", "a client delivery carries its team certificate")
    if not team_key_did:
        raise Refused("verifier_misconfigured", "a client delivery needs the team's current key")
    certificate = _decode_certificate(encoded)
    _certificate_names_producer(certificate, envelope)
    if certificate.get("team_did_key") != team_key_did:
        raise Refused("certificate_invalid", "not issued under the team's current key")
    try:
        verify_team_certificate_signature(certificate, team_key_did)
    except TeamCertificateError as exc:
        if exc.reason == "invalid_team_key":
            raise Refused("verifier_misconfigured", "the team key does not decode") from None
        raise Refused("certificate_invalid", exc.reason) from None


def _decode_certificate(encoded: str) -> dict[str, Any]:
    try:
        return decode_team_certificate(encoded)
    except TeamCertificateError as exc:
        raise Refused("certificate_invalid", exc.reason) from None


def _certificate_names_producer(certificate: dict[str, Any], envelope: Envelope) -> None:
    producer = envelope.fields["producer"]
    if (
        certificate.get("team_id") != envelope.team_id
        or certificate.get("member_did_key") != envelope.producer_did_key
        or certificate.get("certificate_id") != producer["certificate_id"]
    ):
        raise Refused("certificate_mismatch", "the certificate does not name this producer")


def _credential_kid(envelope: Envelope) -> str:
    """The server producer's registered kid, or "member" for a client producer,
    whose key is its member key."""
    return "member" if envelope.producer_kind == "client" else envelope.producer_kid


def _header(headers: dict[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return ""


def _utc(moment: datetime, what: str) -> datetime:
    """A timezone-aware moment as naive UTC. A naive moment is refused: its
    offset is unknown, so it cannot be compared with a signed UTC time."""
    if moment is None or moment.tzinfo is None:
        raise Refused("verifier_misconfigured", f"{what} must be timezone-aware")
    return moment.astimezone(UTC).replace(tzinfo=None)
