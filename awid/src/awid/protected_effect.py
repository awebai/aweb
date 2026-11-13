"""Detached protected-effect attestations; pure codecs, no key or URL discovery.

A proof authorizes release of a retained local effect. It is never evidence
that another service applied that effect. Existing artifact signatures and
consumer nonce/current-state/deadline checks remain mandatory.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from uuid import UUID

from awid.did import public_key_from_did
from awid.log import canonical_server_origin
from awid.signing import canonical_json_bytes, sign_message, verify_did_key_signature
from awid.team_ids import build_team_id, parse_team_id

HEADER = "X-AWEB-Protected-Effect"
PREFIX = b"aweb.protected-effect/1\n"
MAX_HEADER_BYTES = 65536
SAFE_INTEGER = 2**53 - 1
_FIELDS = frozenset(
    {
        "v",
        "type",
        "service_id",
        "team_id",
        "history_id",
        "generation",
        "controller_did_key",
        "operation",
        "variant",
        "operation_id",
        "artifact_type",
        "artifact_sha256",
        "consumer",
        "issued_at",
        "expires_at",
    }
)
_BINDING_FIELDS = frozenset(
    {"mode", "service_id", "service_did_key", "history_id", "generation"}
)
_DIGEST = re.compile(r"[0-9a-f]{64}")
_TOKEN = re.compile(r"[a-z][a-z0-9._-]{0,127}")
_TIME = "%Y-%m-%dT%H:%M:%SZ"


class EffectRefused(ValueError):
    def __init__(self, code="protected_controller_required"):
        self.code = code
        super().__init__(code)


def _require(condition):
    if not condition:
        raise EffectRefused()


def _uuid(value):
    _require(isinstance(value, str) and str(UUID(value)) == value)


def _portable(value, depth=0):
    _require(depth <= 8)
    if isinstance(value, dict):
        _require(all(isinstance(k, str) for k in value))
        for k, v in value.items():
            _portable(k, depth + 1)
            _portable(v, depth + 1)
    elif isinstance(value, list):
        for v in value:
            _portable(v, depth + 1)
    elif isinstance(value, str):
        _require(all(0x20 <= ord(c) <= 0x7E for c in value))
    else:
        _require(type(value) is int and abs(value) <= SAFE_INTEGER)


def _object(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result)
            result[key] = value
        return result

    try:
        _require(len(raw) <= MAX_HEADER_BYTES)
        value = json.loads(raw, object_pairs_hook=pairs)
        _portable(value)
        _require(type(value) is dict and canonical_json_bytes(value) == raw)
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise EffectRefused() from None


def _unbase(value, *, url=False):
    _require(
        isinstance(value, str)
        and bool(re.fullmatch(r"[A-Za-z0-9_-]+" if url else r"[A-Za-z0-9+/]+", value))
    )
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_" if url else None,
            validate=True,
        )
        _require(_base(raw, url=url) == value)
        return raw
    except ValueError:
        raise EffectRefused() from None


def _base(value, *, url=False):
    return (
        (base64.urlsafe_b64encode(value) if url else base64.b64encode(value))
        .rstrip(b"=")
        .decode("ascii")
    )


def validate_binding(value):
    """Only an explicit current-registry legacy projection means unprotected."""
    try:
        _require(type(value) is dict)
        if value == {"mode": "legacy"}:
            return dict(value)
        _require(set(value) == _BINDING_FIELDS and value["mode"] == "protected")
        _require(
            isinstance(value["service_id"], str)
            and bool(_TOKEN.fullmatch(value["service_id"]))
        )
        public_key_from_did(value["service_did_key"])
        _uuid(value["history_id"])
        _require(
            type(value["generation"]) is int and 0 < value["generation"] <= SAFE_INTEGER
        )
        return dict(value)
    except (ValueError, TypeError, KeyError):
        raise EffectRefused("protected_state_unavailable") from None


def artifact_digest(signing: bytes, signature: str) -> str:
    """SHA256(prefix + uint64-BE byte length + exact signing bytes + Ed25519 sig)."""
    _require(type(signing) is bytes)
    decoded = _unbase(signature.rstrip("="))
    _require(len(decoded) == 64)
    return hashlib.sha256(
        b"aweb.protected-artifact/1\n"
        + len(signing).to_bytes(8, "big")
        + signing
        + decoded
    ).hexdigest()


def http_consumer(*, audience, method, path, body, controller_envelope=b""):
    result = {
        "kind": "http",
        "audience": audience,
        "method": method,
        "path": path,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "controller_envelope_sha256": hashlib.sha256(controller_envelope).hexdigest(),
    }
    _consumer(result)
    return result


def _consumer(value):
    _require(type(value) is dict)
    if value.get("kind") == "http":
        _require(
            set(value)
            == {
                "kind",
                "audience",
                "method",
                "path",
                "body_sha256",
                "controller_envelope_sha256",
            }
        )
        _require(value["method"] in {"POST", "PUT", "PATCH", "DELETE"})
        _require(
            isinstance(value["path"], str)
            and value["path"].startswith("/")
            and "#" not in value["path"]
        )
        for k in ("body_sha256", "controller_envelope_sha256"):
            _require(isinstance(value[k], str) and bool(_DIGEST.fullmatch(value[k])))
    else:
        _require(
            set(value) == {"kind", "audience", "scope"} and value["kind"] == "artifact"
        )
        _require(
            isinstance(value["scope"], str) and bool(_TOKEN.fullmatch(value["scope"]))
        )
    _require(canonical_server_origin(value["audience"]) == value["audience"])
    _portable(value)


def _fields(fields):
    try:
        _require(type(fields) is dict and set(fields) == _FIELDS)
        _portable(fields)
        _require(
            type(fields["v"]) is int
            and fields["v"] == 1
            and fields["type"] == "aweb.protected-effect"
        )
        _require(build_team_id(*parse_team_id(fields["team_id"])) == fields["team_id"])
        _uuid(fields["history_id"])
        _uuid(fields["operation_id"])
        _require(
            type(fields["generation"]) is int
            and 0 < fields["generation"] <= SAFE_INTEGER
        )
        public_key_from_did(fields["controller_did_key"])
        for k in ("service_id", "operation", "variant", "artifact_type"):
            _require(isinstance(fields[k], str) and bool(_TOKEN.fullmatch(fields[k])))
        _require(bool(_DIGEST.fullmatch(fields["artifact_sha256"])))
        _consumer(fields["consumer"])
        start, end = (_time(fields[k]) for k in ("issued_at", "expires_at"))
        _require(start < end)
    except (ValueError, TypeError, KeyError):
        raise EffectRefused() from None


def _time(value):
    _require(
        isinstance(value, str)
        and bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value))
    )
    return datetime.strptime(value, _TIME).replace(tzinfo=timezone.utc)


def issue_proof(fields, service_signing_key):
    """Pure encoding/signature primitive, called only by a trusted typed adapter."""
    _fields(fields)
    raw = canonical_json_bytes(fields)
    return {
        "payload": _base(raw, url=True),
        "signature": sign_message(service_signing_key, PREFIX + raw),
    }


def verify_proof(
    proof,
    *,
    binding,
    team_id,
    controller_did_key,
    operations,
    artifact_type,
    artifact,
    artifact_signature,
    consumer,
    now,
):
    try:
        binding = validate_binding(binding)
        _require(binding["mode"] == "protected")
        _require(type(proof) is dict and set(proof) == {"payload", "signature"})
        raw = _unbase(proof["payload"], url=True)
        fields = _object(raw)
        _fields(fields)
        _require(len(_unbase(proof["signature"])) == 64)
        verify_did_key_signature(
            did_key=binding["service_did_key"],
            payload=PREFIX + raw,
            signature_b64=proof["signature"],
        )
        for k in ("service_id", "history_id", "generation"):
            _require(fields[k] == binding[k])
        _require(
            fields["team_id"] == team_id
            and fields["controller_did_key"] == controller_did_key
        )
        _require((fields["operation"], fields["variant"]) in operations)
        _require(
            fields["artifact_type"] == artifact_type
            and fields["artifact_sha256"]
            == artifact_digest(artifact, artifact_signature)
        )
        _require(fields["consumer"] == consumer)
        _require(
            _time(fields["issued_at"]) <= now + timedelta(seconds=60)
            and now < _time(fields["expires_at"])
        )
        return fields
    except (ValueError, TypeError, KeyError, OverflowError):
        raise EffectRefused() from None


def encode_proofs(proofs):
    """One bounded header, allowing a namespace cascade to bind multiple teams."""
    _require(isinstance(proofs, list) and 0 < len(proofs) <= 64)
    raw = _base(canonical_json_bytes({"v": 1, "proofs": proofs}), url=True)
    _require(len(raw) <= MAX_HEADER_BYTES)
    return raw


def decode_proofs(header):
    try:
        _require(isinstance(header, str) and len(header) <= MAX_HEADER_BYTES)
        value = _object(_unbase(header, url=True))
        _require(
            set(value) == {"v", "proofs"}
            and type(value["v"]) is int
            and value["v"] == 1
        )
        _require(isinstance(value["proofs"], list) and 0 < len(value["proofs"]) <= 64)
        teams = set()
        for proof in value["proofs"]:
            _require(type(proof) is dict and set(proof) == {"payload", "signature"})
            fields = _object(_unbase(proof["payload"], url=True))
            _fields(fields)
            _require(fields["team_id"] not in teams)
            teams.add(fields["team_id"])
        return value["proofs"]
    except (ValueError, TypeError, KeyError):
        raise EffectRefused() from None
