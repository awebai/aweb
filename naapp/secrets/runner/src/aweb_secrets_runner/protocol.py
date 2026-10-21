"""Client-side S0 framing. Interoperability is checked against the public vectors."""

import base64
import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import base58
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .errors import Refused
from .journal import Journal

MAX_BODY = 1024 * 1024
SAFE_INT = 2**53 - 1
ID = r"[A-Za-z0-9_-]{22,}"
HASH = r"[0-9a-f]{64}"
ASSIGNMENT_FIELDS = {
    "v",
    "type",
    "origin",
    "service_kid",
    "runner_id",
    "dispatch_id",
    "job_id",
    "job_digest",
    "params_sha256",
    "credentials_sha256",
    "issued_at",
    "expires_at",
}


def _values(value: Any) -> None:
    if value is None or type(value) is bool:
        return
    if type(value) is int and abs(value) <= SAFE_INT:
        return
    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
        return
    if isinstance(value, list):
        for item in value:
            _values(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("non-string key")
            _values(key)
            _values(item)
        return
    raise ValueError("nonportable JSON value")


def canonical(value: Any) -> bytes:
    _values(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def parse_json(raw: bytes) -> Any:
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    _values(value)
    return value


def encode64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode64(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise ValueError("base64url")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if encode64(raw) != value:
        raise ValueError("noncanonical base64url")
    return raw


def public_did(key: Ed25519PublicKey) -> str:
    return "did:key:z" + base58.b58encode(b"\xed\x01" + key.public_bytes_raw()).decode()


def public_key(did: str) -> Ed25519PublicKey:
    if not did.startswith("did:key:z"):
        raise ValueError("key type")
    raw = base58.b58decode(did[9:])
    if len(raw) != 34 or raw[:2] != b"\xed\x01":
        raise ValueError("key type")
    key = Ed25519PublicKey.from_public_bytes(raw[2:])
    if public_did(key) != did:
        raise ValueError("key encoding")
    return key


def origin_is_valid(origin: str) -> bool:
    try:
        parts = urlsplit(origin)
        return (
            parts.scheme == "https"
            and bool(parts.hostname)
            and parts.username is None
            and parts.password is None
            and not parts.path
            and not parts.query
            and not parts.fragment
            and parts.port != 0
            and origin.isascii()
            and not any(c.isspace() for c in origin)
        )
    except ValueError:
        return False


def timestamp(value: str) -> datetime:
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
        raise ValueError("timestamp")
    return datetime.fromisoformat(value)


def _utc(now: datetime) -> datetime:
    if now.tzinfo is None:
        raise ValueError("timezone required")
    return now.astimezone(UTC)


def sign_request(
    key: Ed25519PrivateKey,
    *,
    origin: str,
    runner_id: str,
    method: str,
    path: str,
    body: bytes,
    now: datetime,
    nonce: bytes | None = None,
) -> str:
    nonce = secrets.token_bytes(16) if nonce is None else nonce
    if (
        not origin_is_valid(origin)
        or not re.fullmatch("rnr_" + ID, runner_id)
        or not re.fullmatch(r"[A-Z]+", method)
        or not path.startswith("/")
        or "#" in path
        or len(nonce) != 16
        or not path.isascii()
        or any(c.isspace() for c in path)
    ):
        raise Refused("runner_request_invalid")
    payload = canonical(
        {
            "v": 1,
            "type": "aweb.secrets.runner-request",
            "origin": origin,
            "runner_id": runner_id,
            "kid": public_did(key.public_key()),
            "method": method,
            "path": path,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "timestamp": _utc(now).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "nonce": encode64(nonce),
        }
    )
    header = (
        encode64(payload) + "." + encode64(key.sign(b"aweb.secrets.runner-request/1\n" + payload))
    )
    if len(header) > 4096:
        raise Refused("runner_request_invalid")
    return header


@dataclass(frozen=True)
class VerifiedAssignment:
    """Store verified bytes; return fresh projections so callers cannot mutate the pin."""

    _body: bytes

    @property
    def document(self) -> dict[str, Any]:
        return json.loads(self._body)  # type: ignore[no-any-return]

    @property
    def dispatch_id(self) -> str:
        return str(self.document["assignment"]["dispatch_id"])


def verify_assignment(
    raw: bytes,
    *,
    origin: str,
    runner_id: str,
    service_kid: str,
    now: datetime,
    journal: Journal,
) -> VerifiedAssignment:
    try:
        if len(raw) > MAX_BODY:
            raise ValueError("size")
        doc = parse_json(raw)
        if not isinstance(doc, dict) or set(doc) != {
            "assignment",
            "signature",
            "params",
            "credentials",
        }:
            raise ValueError("body")
        assignment = doc["assignment"]
        if not isinstance(assignment, dict) or set(assignment) != ASSIGNMENT_FIELDS:
            raise ValueError("payload")
        if type(assignment["v"]) is not int or assignment["v"] != 1:
            raise ValueError("version")
        if assignment["type"] != "aweb.secrets.runner-assignment":
            raise ValueError("type")
        if any(not isinstance(assignment[k], str) for k in ASSIGNMENT_FIELDS - {"v"}):
            raise ValueError("fields")
        if (
            not re.fullmatch("rnr_" + ID, assignment["runner_id"])
            or not re.fullmatch("dsp_" + ID, assignment["dispatch_id"])
            or not assignment["job_id"]
            or not origin_is_valid(assignment["origin"])
            or any(
                not re.fullmatch(HASH, assignment[k])
                for k in ("job_digest", "params_sha256", "credentials_sha256")
            )
            or not isinstance(doc["params"], dict)
            or not isinstance(doc["credentials"], list)
        ):
            raise ValueError("fields")
        issued = timestamp(assignment["issued_at"])
        expires = timestamp(assignment["expires_at"])
        for credential in doc["credentials"]:
            if (
                not isinstance(credential, dict)
                or set(credential) != {"secret_ref", "sealed"}
                or not isinstance(credential["secret_ref"], str)
                or not credential["secret_ref"]
            ):
                raise ValueError("credential")
            decode64(credential["sealed"])
        signature = decode64(doc["signature"])
        public_key(assignment["service_kid"])
        if assignment["service_kid"] != service_kid:
            raise ValueError("unpinned key")
        public_key(service_kid).verify(
            signature, b"aweb.secrets.runner-assignment/1\n" + canonical(assignment)
        )
    except (ValueError, TypeError, KeyError, RecursionError, InvalidSignature):
        raise Refused("assignment_invalid") from None
    if assignment["runner_id"] != runner_id or assignment["origin"] != origin:
        raise Refused("assignment_wrong_runner")
    for field in ("params", "credentials"):
        if hashlib.sha256(canonical(doc[field])).hexdigest() != assignment[field + "_sha256"]:
            raise Refused("assignment_binding_mismatch")
    now = _utc(now)
    if (
        not 0 < (expires - issued).total_seconds() <= 300
        or now >= expires
        or (issued - now).total_seconds() > 120
    ):
        raise Refused("assignment_expired")
    journal.accept(assignment["dispatch_id"], expires_at=expires.timestamp(), now=now.timestamp())
    return VerifiedAssignment(canonical(doc))


def decrypt_credential(sealed: str, key: X25519PrivateKey, dispatch_id: str) -> bytes:
    try:
        suite = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.CHACHA20_POLY1305)
        return suite.decrypt(decode64(sealed), key, dispatch_id.encode("utf-8"))
    except (ValueError, InvalidTag):
        raise Refused("credential_invalid") from None
