"""Server half of docs/secrets-runner-protocol.md, in its verification order.

Parsing and cryptographic checks are side-effect free. The caller locks the
active runner, verifies with its registered key and then consumes the nonce
in the same transaction as any effect. No caller may treat a parsed request
as authorization.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from aweb_naapp.hooks.strictjson import (
    Refused as EncodingRefused,
)
from aweb_naapp.hooks.strictjson import (
    decode_base64url,
    encode_base64url,
)
from aweb_naapp.runtime.approvals.request import RequestNotCanonical, parse_request_json
from awid.did import did_from_public_key, public_key_from_did
from awid.signing import canonical_json_bytes
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from pgdbm import TransactionManager

REQUEST_TYPE = "aweb.secrets.runner-request"
ASSIGNMENT_TYPE = "aweb.secrets.runner-assignment"
REQUEST_FIELDS = frozenset(
    {
        "v",
        "type",
        "origin",
        "runner_id",
        "kid",
        "method",
        "path",
        "body_sha256",
        "timestamp",
        "nonce",
    }
)
RUNNER_ID = re.compile(r"rnr_[A-Za-z0-9_-]{22,}")
DISPATCH_ID = re.compile(r"dsp_[A-Za-z0-9_-]{22,}")
HEX64 = re.compile(r"[0-9a-f]{64}")
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
SKEW = timedelta(seconds=120)


class RunnerRefused(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def canonical(value: Any) -> bytes:
    """The protocol's Unicode scalar / safe integer JSON value domain."""

    def check(v: Any) -> None:
        if v is None or isinstance(v, bool):
            return
        if isinstance(v, str):
            v.encode("utf-8")
        elif type(v) is int and abs(v) <= 2**53 - 1:
            return
        elif isinstance(v, dict) and all(isinstance(k, str) for k in v):
            for key, item in v.items():
                check(key)
                check(item)
        elif isinstance(v, list):
            for item in v:
                check(item)
        else:
            raise ValueError("not a protocol JSON value")

    check(value)
    return canonical_json_bytes(value)


def utc_seconds(value: str) -> datetime:
    if not isinstance(value, str) or not TIMESTAMP.fullmatch(value):
        raise ValueError("not a UTC second timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def format_time(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("time must be aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class ParsedRequest:
    payload: dict[str, Any]
    raw: bytes
    signature: bytes
    timestamp: datetime

    @property
    def runner_id(self) -> str:
        return str(self.payload["runner_id"])

    @property
    def nonce(self) -> str:
        return str(self.payload["nonce"])

    @property
    def expires_at(self) -> datetime:
        return self.timestamp + SKEW


@dataclass(frozen=True)
class VerifiedRequest(ParsedRequest):
    """Verified through time/binding, awaiting durable nonce consumption."""


def parse_request(header: str) -> ParsedRequest:
    """Step 1 only; this type is not proof of a registered runner."""
    try:
        if not isinstance(header, str) or len(header.encode("utf-8")) > 4096:
            raise ValueError("header size")
        parts = header.split(".")
        if len(parts) != 2:
            raise ValueError("header parts")
        raw, signature = (decode_base64url(p, "request") for p in parts)
        payload = parse_request_json(raw)
        if canonical(payload) != raw or set(payload) != REQUEST_FIELDS:
            raise ValueError("shape")
        if type(payload["v"]) is not int or payload["v"] != 1 or payload["type"] != REQUEST_TYPE:
            raise ValueError("version")
        if not all(isinstance(payload[f], str) for f in REQUEST_FIELDS - {"v"}):
            raise ValueError("field type")
        if not RUNNER_ID.fullmatch(payload["runner_id"]):
            raise ValueError("runner id")
        if len(decode_base64url(payload["nonce"], "nonce")) != 16 or not HEX64.fullmatch(
            payload["body_sha256"]
        ):
            raise ValueError("nonce or digest")
        return ParsedRequest(payload, raw, signature, utc_seconds(payload["timestamp"]))
    except (ValueError, UnicodeError, RecursionError, RequestNotCanonical, EncodingRefused):
        raise RunnerRefused("runner_request_invalid") from None


def verify_request(
    parsed: ParsedRequest,
    *,
    registered_kid: str | None,
    origin: str,
    method: str,
    path: str,
    body: bytes,
    now: datetime,
) -> VerifiedRequest:
    """Steps 2–5; the caller must still consume step 6 inside the effect transaction."""
    p = parsed.payload
    if registered_kid is None or p["kid"] != registered_kid:
        raise RunnerRefused("runner_unknown")
    try:
        VerifyKey(public_key_from_did(registered_kid)).verify(
            (REQUEST_TYPE + "/1\n").encode() + parsed.raw,
            parsed.signature,
        )
    except (BadSignatureError, ValueError, TypeError):
        raise RunnerRefused("runner_request_invalid") from None
    if (
        p["origin"] != origin
        or p["method"] != method
        or p["path"] != path
        or p["body_sha256"] != hashlib.sha256(body).hexdigest()
    ):
        raise RunnerRefused("runner_request_binding_mismatch")
    if now.tzinfo is None:
        raise ValueError("clock must be aware")
    if abs(now - parsed.timestamp) > SKEW:
        raise RunnerRefused("runner_request_stale")
    return VerifiedRequest(parsed.payload, parsed.raw, parsed.signature, parsed.timestamp)


async def consume_request(
    tx: TransactionManager,
    verified: VerifiedRequest,
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> None:
    """Consume in the effect transaction; never accept an unverified parsed header."""
    from aweb_naapp.nonces import consume_nonce

    if not isinstance(verified, VerifiedRequest):
        raise TypeError("consume requires a verified runner request")
    if abs(clock() - verified.timestamp) > SKEW:
        raise RunnerRefused("runner_request_stale")
    inserted = await consume_nonce(
        tx,
        scope="runner:" + verified.runner_id,
        nonce=verified.nonce,
        expires_at=verified.expires_at,
    )
    # A conflict may wait for a concurrent request. Time still precedes replay.
    if abs(clock() - verified.timestamp) > SKEW:
        raise RunnerRefused("runner_request_stale")
    if not inserted:
        raise RunnerRefused("runner_request_replayed")


async def prune_request_nonces(tx: TransactionManager, *, now: datetime) -> int:
    """Keep an extra skew interval before pruning on a service instance's clock."""
    from aweb_naapp.nonces import prune_nonces

    return await prune_nonces(tx, now=now - SKEW)


def sign_assignment(
    *,
    key: SigningKey,
    origin: str,
    runner_id: str,
    dispatch_id: str,
    job_id: str,
    job_digest: str,
    params: dict[str, Any],
    credentials: list[dict[str, str]],
    issued_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    """Bind the exact ordered credential slots and parameters to this dispatch."""
    if not RUNNER_ID.fullmatch(runner_id) or not DISPATCH_ID.fullmatch(dispatch_id):
        raise ValueError("invalid assignment identifiers")
    if not job_id or not HEX64.fullmatch(job_digest):
        raise ValueError("invalid job")
    issued_at = utc_seconds(format_time(issued_at))
    expires_at = utc_seconds(format_time(expires_at))
    if not timedelta(0) < expires_at - issued_at <= timedelta(seconds=300):
        raise ValueError("assignment lifetime must be 1 to 300 seconds")
    for item in credentials:
        if set(item) != {"secret_ref", "sealed"} or not all(
            isinstance(v, str) for v in item.values()
        ):
            raise ValueError("invalid credential slot")
        decode_base64url(item["sealed"], "credential")
    payload = {
        "v": 1,
        "type": ASSIGNMENT_TYPE,
        "origin": origin,
        "service_kid": did_from_public_key(bytes(key.verify_key)),
        "runner_id": runner_id,
        "dispatch_id": dispatch_id,
        "job_id": job_id,
        "job_digest": job_digest,
        "params_sha256": hashlib.sha256(canonical(params)).hexdigest(),
        "credentials_sha256": hashlib.sha256(canonical(credentials)).hexdigest(),
        "issued_at": format_time(issued_at),
        "expires_at": format_time(expires_at),
    }
    signature = key.sign((ASSIGNMENT_TYPE + "/1\n").encode() + canonical(payload)).signature
    result = {
        "assignment": payload,
        "signature": encode_base64url(signature),
        "params": params,
        "credentials": credentials,
    }
    if len(canonical(result)) > 1024 * 1024:
        raise ValueError("assignment exceeds 1 MiB")
    return result
