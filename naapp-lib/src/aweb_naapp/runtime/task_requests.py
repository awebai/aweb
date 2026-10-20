"""App task requests: the member's task authorization, the app-request
transport credential and task answer digests (docs/app-task-requests.md).

A member signs one ``aweb.app-task-authorization/1`` for one task; the app
carries it with its own ``app-request`` credential; the task service verifies
both. This module builds and checks those bytes as the contract's
conformance vectors freeze them. Certificate authority (AWID team key and
revocation) is the team-auth verifier's, not this module's.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from awid.did import did_from_public_key, public_key_from_did
from awid.log import require_canonical_server_origin
from awid.signing import canonical_json_bytes, sign_message
from awid.team_ids import parse_team_id
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

AUTHORIZATION_PREFIX = b"aweb.app-task-authorization/1\n"
AUTHORIZATION_TYPE = "aweb.app-task-authorization"
STAGE_RECEIPT_PREFIX = b"aweb.app-answer-stage/1\n"
STAGE_RECEIPT_TYPE = "aweb.app-answer-stage"
MAX_STAGE_RECEIPT_SECONDS = 300
MAX_LIFETIME_SECONDS = 86400
MAX_ISSUED_AT_SKEW_SECONDS = 60
SAFE_INTEGER = 2**53 - 1
MAX_ELIGIBLE = 16

_REFERENCE = re.compile(r"[A-Za-z0-9._-]{1,128}")
_OPAQUE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_PRINCIPAL_DID = re.compile(r"did:(aw|key):[A-Za-z0-9._:%-]{1,256}")
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}")
_PREFIXED_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_NONCE = re.compile(r"[0-9a-f]{32}")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_ROLE_NAME = re.compile(r"[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+")
_CHOICE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}")
# Unicode bidi controls, marks included, the same set manifest role labels refuse.
_BIDI_CONTROLS = frozenset(
    chr(code) for code in (0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A))
)

_PAYLOAD_FIELDS = frozenset(
    {
        "v",
        "type",
        "aud",
        "app_origin",
        "team_id",
        "app_id",
        "installation_id",
        "installation_generation",
        "external_request_id",
        "actor_did_key",
        "certificate_id",
        "target_dids",
        "task_body_sha256",
        "action_id",
        "proposal_rev",
        "proposal_sha256",
        "issued_at",
        "expires_at",
        "nonce",
    }
)
_TASK_FIELDS = frozenset({"title", "description", "assignee_did", "app_request"})
_APP_REQUEST_FIELDS = frozenset(
    {
        "external_request_id",
        "resource_ref",
        "action_ref",
        "proposal_rev",
        "proposal_sha256",
        "choices",
        "eligible_dids",
        "role",
    }
)


class TaskRequestRefused(ValueError):
    """A task request part failed; ``code`` is the contract's error code."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(f"{code}: {reason}")
        self.code = code


def _refuse(code: str, reason: str) -> TaskRequestRefused:
    return TaskRequestRefused(code, reason)


# ---------------------------------------------------------------- strict JSON


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _refuse("schema_invalid", "duplicate object key")
        result[key] = value
    return result


def _no_number(text: str) -> Any:
    raise _refuse("schema_invalid", f"number {text!r} has no canonical form")


def parse_json(raw: bytes) -> Any:
    """Parse a request body, refusing duplicate keys, floats and non-finite numbers."""
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_no_duplicates,
            parse_float=_no_number,
            parse_constant=_no_number,
        )
    except TaskRequestRefused:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise _refuse("schema_invalid", "body is not JSON") from exc


# ---------------------------------------------------------------- field checks


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_safe_int(value: object, minimum: int) -> bool:
    return _is_int(value) and minimum <= value <= SAFE_INTEGER  # type: ignore[operator]


def _matches(pattern: re.Pattern[str], value: object) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _clean_text(value: object, maximum: int) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        return False
    return not any(unicodedata.category(c) == "Cc" or c in _BIDI_CONTROLS for c in value)


def _timestamp(value: object) -> datetime | None:
    if not _matches(_TIMESTAMP, value):
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _canonical_origin(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        require_canonical_server_origin(value)
    except ValueError:
        return False
    return True


def _principal_set(value: object) -> bool:
    """1-16 distinct principal DIDs in sorted order: one spelling per set."""
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ELIGIBLE:
        return False
    if not all(_matches(_PRINCIPAL_DID, did) for did in value):
        return False
    return value == sorted(set(value))


def _proposal_pair(rev: object, digest: object) -> bool:
    if rev is None and digest is None:
        return True
    return _is_safe_int(rev, 0) and _matches(_PREFIXED_DIGEST, digest)


# ---------------------------------------------------------------- task body


def validate_task(task: object) -> None:
    """Check a task body against docs/app-task-requests.md §3."""
    if not isinstance(task, Mapping) or set(task) != _TASK_FIELDS:
        raise _refuse("schema_invalid", "task fields")
    if not _clean_text(task["title"], 200):
        raise _refuse("schema_invalid", "title")
    if task["description"] is not None and not _clean_text(task["description"], 2000):
        raise _refuse("schema_invalid", "description")
    if not _matches(_PRINCIPAL_DID, task["assignee_did"]):
        raise _refuse("schema_invalid", "assignee_did")
    request = task["app_request"]
    if not isinstance(request, Mapping) or set(request) != _APP_REQUEST_FIELDS:
        raise _refuse("schema_invalid", "app_request fields")
    for field in ("external_request_id", "resource_ref", "action_ref"):
        if not _matches(_REFERENCE, request[field]):
            raise _refuse("schema_invalid", field)
    if not _proposal_pair(request["proposal_rev"], request["proposal_sha256"]):
        raise _refuse("schema_invalid", "proposal")
    eligible = request["eligible_dids"]
    if request["proposal_rev"] is None:
        if eligible is not None:
            raise _refuse("schema_invalid", "eligible_dids on a request without a proposal")
    elif not _principal_set(eligible) or task["assignee_did"] not in eligible:
        raise _refuse("schema_invalid", "eligible_dids")
    role = request["role"]
    if request["proposal_rev"] is None:
        if role is not None:
            raise _refuse("schema_invalid", "role on a request without a proposal")
    elif role is not None and not (_matches(_ROLE_NAME, role) and len(role.encode("utf-8")) <= 128):
        raise _refuse("schema_invalid", "role")
    choices = request["choices"]
    if choices is not None:
        if not isinstance(choices, list) or not 1 <= len(choices) <= 10:
            raise _refuse("schema_invalid", "choices")
        if len(set(choices)) != len(choices) or not all(_matches(_CHOICE, c) for c in choices):
            raise _refuse("schema_invalid", "choices")


def task_body_sha256(task: Mapping[str, Any]) -> str:
    """Bare hex SHA-256 of the canonical task body, the value the member signs."""
    validate_task(task)
    return hashlib.sha256(canonical_json_bytes(dict(task))).hexdigest()


# ---------------------------------------------------------------- task authorization


def task_authorization_signing_bytes(payload: Mapping[str, Any]) -> bytes:
    return AUTHORIZATION_PREFIX + canonical_json_bytes(dict(payload))


def sign_task_authorization(payload: Mapping[str, Any], signing_key: SigningKey) -> str:
    """The member's signature: base64url without padding over the signing bytes."""
    _check_payload(payload)
    signature = signing_key.sign(task_authorization_signing_bytes(payload)).signature
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


def _check_payload(payload: object) -> tuple[datetime, datetime]:
    def bad(reason: str) -> TaskRequestRefused:
        return _refuse("signature_invalid", reason)

    if not isinstance(payload, Mapping) or set(payload) != _PAYLOAD_FIELDS:
        raise bad("payload fields")
    if not (_is_int(payload["v"]) and payload["v"] == 1) or payload["type"] != AUTHORIZATION_TYPE:
        raise bad("v or type")
    if not (_canonical_origin(payload["aud"]) and _canonical_origin(payload["app_origin"])):
        raise bad("aud or app_origin")
    try:
        parse_team_id(payload["team_id"])
    except (TypeError, ValueError, AttributeError) as exc:
        raise bad("team_id") from exc
    for field in ("app_id", "installation_id", "certificate_id"):
        if not _matches(_OPAQUE_ID, payload[field]):
            raise bad(field)
    if not _is_safe_int(payload["installation_generation"], 1):
        raise bad("installation_generation")
    for field in ("external_request_id", "action_id"):
        if not _matches(_REFERENCE, payload[field]):
            raise bad(field)
    actor = payload["actor_did_key"]
    try:
        if not isinstance(actor, str) or did_from_public_key(public_key_from_did(actor)) != actor:
            raise bad("actor_did_key")
    except ValueError as exc:
        raise bad("actor_did_key") from exc
    if not _principal_set(payload["target_dids"]):
        raise bad("target_dids")
    if not _matches(_HEX_DIGEST, payload["task_body_sha256"]):
        raise bad("task_body_sha256")
    if not _proposal_pair(payload["proposal_rev"], payload["proposal_sha256"]):
        raise bad("proposal")
    if not _matches(_NONCE, payload["nonce"]):
        raise bad("nonce")
    issued, expires = _timestamp(payload["issued_at"]), _timestamp(payload["expires_at"])
    if issued is None or expires is None:
        raise bad("timestamps")
    lifetime = (expires - issued).total_seconds()
    if not 0 < lifetime <= MAX_LIFETIME_SECONDS:
        raise bad("lifetime")
    return issued, expires


def _signature_bytes(signature: object) -> bytes:
    if not isinstance(signature, str) or not re.fullmatch(r"[A-Za-z0-9_-]{86}", signature):
        raise _refuse("signature_invalid", "signature encoding")
    raw = base64.urlsafe_b64decode(signature + "==")
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != signature:
        raise _refuse("signature_invalid", "signature encoding")
    return raw


def verify_task_authorization(
    payload: Mapping[str, Any],
    signature: str,
    *,
    expected: Mapping[str, Any],
    now: datetime,
) -> None:
    """Verify shape and signature, then bindings, then time (§3 steps 3, 5 and 6).

    ``expected`` holds the values the payload must equal: the task service's
    audience, the transport's team, app, installation and generation, the
    installed app origin, and the body's task digest, target, request id, action
    and proposal. Raises TaskRequestRefused with the contract's code.
    """
    issued, expires = _check_payload(payload)
    raw = _signature_bytes(signature)
    key = VerifyKey(public_key_from_did(payload["actor_did_key"]))
    try:
        key.verify(task_authorization_signing_bytes(payload), raw)
    except BadSignatureError as exc:
        raise _refuse("signature_invalid", "signature does not verify") from exc
    for field, value in expected.items():
        if payload.get(field) != value or (_is_int(value) and not _is_int(payload.get(field))):
            raise _refuse("target_mismatch", field)
    # Time is checked last, so a caller that accepts an expired authorization
    # for a matching replay knows every other check passed.
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if (
        issued - now.astimezone(UTC)
    ).total_seconds() > MAX_ISSUED_AT_SKEW_SECONDS or now >= expires:
        raise _refuse("authorization_expired", "outside the validity window")


# ---------------------------------------------------------------- stage receipt

_STAGE_FIELDS = frozenset(
    {
        "v",
        "type",
        "team_id",
        "app_id",
        "installation_id",
        "installation_generation",
        "kid",
        "did_key",
        "task_id",
        "question_rev",
        "answer_key",
        "answer_sha256",
        "answerer_did",
        "issued_at",
        "expires_at",
        "nonce",
    }
)


def stage_receipt_signing_bytes(payload: Mapping[str, Any]) -> bytes:
    return STAGE_RECEIPT_PREFIX + canonical_json_bytes(dict(payload))


def _check_stage_payload(payload: object) -> tuple[datetime, datetime]:
    def bad(reason: str) -> TaskRequestRefused:
        return _refuse("signature_invalid", reason)

    if not isinstance(payload, Mapping) or set(payload) != _STAGE_FIELDS:
        raise bad("payload fields")
    if not (_is_int(payload["v"]) and payload["v"] == 1) or payload["type"] != STAGE_RECEIPT_TYPE:
        raise bad("v or type")
    try:
        parse_team_id(payload["team_id"])
    except (TypeError, ValueError, AttributeError) as exc:
        raise bad("team_id") from exc
    for field in ("app_id", "installation_id", "kid", "task_id"):
        if not _matches(_OPAQUE_ID, payload[field]):
            raise bad(field)
    if not _is_safe_int(payload["installation_generation"], 1):
        raise bad("installation_generation")
    if not _is_safe_int(payload["question_rev"], 1):
        raise bad("question_rev")
    if not _matches(_REFERENCE, payload["answer_key"]):
        raise bad("answer_key")
    if not _matches(_HEX_DIGEST, payload["answer_sha256"]):
        raise bad("answer_sha256")
    if not _matches(_PRINCIPAL_DID, payload["answerer_did"]):
        raise bad("answerer_did")
    key = payload["did_key"]
    try:
        if not isinstance(key, str) or did_from_public_key(public_key_from_did(key)) != key:
            raise bad("did_key")
    except ValueError as exc:
        raise bad("did_key") from exc
    if not _matches(_NONCE, payload["nonce"]):
        raise bad("nonce")
    issued, expires = _timestamp(payload["issued_at"]), _timestamp(payload["expires_at"])
    if issued is None or expires is None:
        raise bad("timestamps")
    if not 0 < (expires - issued).total_seconds() <= MAX_STAGE_RECEIPT_SECONDS:
        raise bad("lifetime")
    return issued, expires


def sign_stage_receipt(payload: Mapping[str, Any], signing_key: SigningKey) -> str:
    """The app's signature over a stage receipt, base64url without padding."""
    _check_stage_payload(payload)
    signature = signing_key.sign(stage_receipt_signing_bytes(payload)).signature
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


def verify_stage_receipt(
    payload: Mapping[str, Any],
    signature: str,
    *,
    expected: Mapping[str, Any],
    now: datetime,
) -> None:
    """Verify an app's stage receipt: shape and signature, then bindings, then time.

    ``expected`` holds what the receipt must equal: the creating installation
    and its current generation, the task and its current question, the answer
    key and digest, and the verified answerer. Whether ``did_key`` is registered
    for the installation's app-request purpose, and whether the nonce was
    already used, are the task service's checks.
    """
    issued, expires = _check_stage_payload(payload)
    raw = _signature_bytes(signature)
    try:
        VerifyKey(public_key_from_did(payload["did_key"])).verify(
            stage_receipt_signing_bytes(payload), raw
        )
    except BadSignatureError as exc:
        raise _refuse("signature_invalid", "signature does not verify") from exc
    for field, value in expected.items():
        if payload.get(field) != value or (_is_int(value) and not _is_int(payload.get(field))):
            raise _refuse("target_mismatch", field)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if (
        issued - now.astimezone(UTC)
    ).total_seconds() > MAX_ISSUED_AT_SKEW_SECONDS or now >= expires:
        raise _refuse("authorization_expired", "outside the validity window")


# ---------------------------------------------------------------- app-request credential


def app_request_credential(
    *,
    signing_key: SigningKey,
    aud: str,
    method: str,
    path: str,
    team_id: str,
    app_id: str,
    kid: str,
    installation_id: str,
    installation_generation: int,
    body: bytes,
    timestamp: str,
) -> dict[str, str]:
    """Headers for one request under the app credential family's app-request purpose."""
    did_key = did_from_public_key(bytes(signing_key.verify_key))
    payload = {
        "v": 1,
        "auth": "app-request",
        "aud": aud,
        "method": method.upper(),
        "path": path,
        "team_id": team_id,
        "app_id": app_id,
        "kid": kid,
        "did_key": did_key,
        "installation_id": installation_id,
        "installation_generation": installation_generation,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "timestamp": timestamp,
    }
    canonical = canonical_json_bytes(payload)
    signature = sign_message(bytes(signing_key), canonical)
    return {
        "Authorization": f"AWEB-App-Request DIDKey {did_key} {signature}",
        "X-AWEB-App-ID": app_id,
        "X-AWEB-App-Key-ID": kid,
        "X-AWEB-Team-ID": team_id,
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(canonical).rstrip(b"=").decode("ascii"),
    }


# ---------------------------------------------------------------- answers


def answer_sha256(body_md: str) -> str:
    """The answer commitment: bare hex SHA-256 of the answer text's UTF-8 bytes."""
    return hashlib.sha256(body_md.encode("utf-8")).hexdigest()
