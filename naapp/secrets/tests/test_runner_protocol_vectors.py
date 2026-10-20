"""The runner protocol vector (docs/secrets-runner-protocol.md), case by case.

The checks below follow the contract's verification orders step for step, so
every refusal case must stop at the step that names its code, and every
positive case must reproduce its signing bytes and signature from the seeds.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from awid.did import did_from_public_key, public_key_from_did
from awid.signing import canonical_json_bytes
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

VECTOR = json.loads(
    (Path(__file__).parents[3] / "docs" / "vectors" / "secrets-runner-protocol-v1.json").read_text()
)

REQUEST_TYPE = "aweb.secrets.runner-request"
ASSIGNMENT_TYPE = "aweb.secrets.runner-assignment"
REQUEST_FIELDS = {
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
BODY_FIELDS = {"assignment", "signature", "params", "credentials"}
SKEW = timedelta(seconds=120)
HEX64 = re.compile(r"[0-9a-f]{64}")
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
SUITE = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.CHACHA20_POLY1305)


class Refused(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def from_b64u(value: str, code: str) -> bytes:
    try:
        data = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as exc:
        raise Refused(code) from exc
    if b64u(data) != value:
        raise Refused(code)
    return data


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError("duplicate key")
    return dict(pairs)


def _no_float(text: str) -> Any:
    raise ValueError("float")


def strict_json(raw: bytes | str, code: str) -> Any:
    """Parse JSON, refusing duplicate keys, floats and non-finite numbers."""
    try:
        return json.loads(
            raw, object_pairs_hook=_no_duplicates, parse_float=_no_float, parse_constant=_no_float
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise Refused(code) from exc


def canonical_object(raw: bytes, code: str) -> dict[str, Any]:
    value = strict_json(raw, code)
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise Refused(code)
    return value


def at(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def timestamp(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not TIMESTAMP.fullmatch(value):
        raise Refused(code)
    try:
        return at(value)
    except ValueError as exc:
        raise Refused(code) from exc


def verify(did_key: str, prefix: str, payload_bytes: bytes, signature: bytes, code: str) -> None:
    try:
        VerifyKey(public_key_from_did(did_key)).verify(
            f"{prefix}/1\n".encode() + payload_bytes, signature
        )
    except (BadSignatureError, ValueError) as exc:
        raise Refused(code) from exc


def verify_request(case: dict[str, Any]) -> dict[str, Any]:
    deployment = case["deployment"]
    received = case["received"]
    header = case["header"]
    code = "runner_request_invalid"
    parts = header.split(".")
    if len(header.encode()) > 4096 or len(parts) != 2:
        raise Refused(code)
    payload_bytes = from_b64u(parts[0], code)
    signature = from_b64u(parts[1], code)
    payload = canonical_object(payload_bytes, code)
    if set(payload) != REQUEST_FIELDS or payload["v"] != 1 or payload["type"] != REQUEST_TYPE:
        raise Refused(code)
    if not all(isinstance(payload[f], str) for f in REQUEST_FIELDS - {"v"}):
        raise Refused(code)
    if len(from_b64u(payload["nonce"], code)) != 16 or not HEX64.fullmatch(payload["body_sha256"]):
        raise Refused(code)
    sent_at = timestamp(payload["timestamp"], code)

    if deployment["runners"].get(payload["runner_id"]) != payload["kid"]:
        raise Refused("runner_unknown")
    verify(payload["kid"], REQUEST_TYPE, payload_bytes, signature, code)

    body = from_b64u(received["body_b64url"], code)
    if (
        payload["origin"] != deployment["origin"]
        or payload["method"] != received["method"]
        or payload["path"] != received["path"]
        or payload["body_sha256"] != hashlib.sha256(body).hexdigest()
    ):
        raise Refused("runner_request_binding_mismatch")
    if abs(at(case["now"]) - sent_at) > SKEW:
        raise Refused("runner_request_stale")
    if [payload["runner_id"], payload["nonce"]] in deployment["seen_nonces"]:
        raise Refused("runner_request_replayed")
    return payload


def verify_assignment(case: dict[str, Any]) -> dict[str, Any]:
    runner = case["runner"]
    code = "assignment_invalid"
    body = strict_json(case["body_json"], code)
    if not isinstance(body, dict) or set(body) != BODY_FIELDS:
        raise Refused(code)
    if not isinstance(body["assignment"], dict) or not isinstance(body["params"], dict):
        raise Refused(code)
    if not isinstance(body["credentials"], list):
        raise Refused(code)
    payload = body["assignment"]
    payload_bytes = canonical_json_bytes(payload)
    if set(payload) != ASSIGNMENT_FIELDS or payload["v"] != 1 or payload["type"] != ASSIGNMENT_TYPE:
        raise Refused(code)
    if not all(isinstance(payload[f], str) for f in ASSIGNMENT_FIELDS - {"v"}):
        raise Refused(code)
    if not all(
        HEX64.fullmatch(payload[f]) for f in ("job_digest", "params_sha256", "credentials_sha256")
    ):
        raise Refused(code)
    issued_at = timestamp(payload["issued_at"], code)
    expires_at = timestamp(payload["expires_at"], code)
    signature = from_b64u(body["signature"], code)

    if payload["service_kid"] != runner["service_kid"]:
        raise Refused(code)
    verify(payload["service_kid"], ASSIGNMENT_TYPE, payload_bytes, signature, code)

    if payload["runner_id"] != runner["runner_id"] or payload["origin"] != runner["origin"]:
        raise Refused("assignment_wrong_runner")
    if (
        payload["params_sha256"] != hashlib.sha256(canonical_json_bytes(body["params"])).hexdigest()
        or payload["credentials_sha256"]
        != hashlib.sha256(canonical_json_bytes(body["credentials"])).hexdigest()
    ):
        raise Refused("assignment_binding_mismatch")
    now = at(case["now"])
    if not issued_at < expires_at or now >= expires_at or issued_at - now > SKEW:
        raise Refused("assignment_expired")
    if payload["dispatch_id"] in runner["journal"]:
        raise Refused("assignment_replayed")
    return payload


@pytest.mark.parametrize("case", VECTOR["requests"], ids=lambda case: case["name"])
def test_request_cases(case):
    expected = case["expected"]
    if "error" in expected:
        with pytest.raises(Refused) as refused:
            verify_request(case)
        assert refused.value.code == expected["error"]
        return
    payload = verify_request(case)
    assert canonical_json_bytes(payload) == from_b64u(case["header"].split(".")[0], "x")


@pytest.mark.parametrize("case", VECTOR["assignments"], ids=lambda case: case["name"])
def test_assignment_cases(case):
    expected = case["expected"]
    if "error" in expected:
        with pytest.raises(Refused) as refused:
            verify_assignment(case)
        assert refused.value.code == expected["error"]
        return
    assert verify_assignment(case)["dispatch_id"] == expected["dispatch_id"]


def _seed(name: str) -> bytes:
    return bytes.fromhex(VECTOR["keys"][name]["seed_hex"])


@pytest.mark.parametrize("name", ["runner", "service"])
def test_signing_keys_match_their_did_keys(name):
    key = SigningKey(_seed(name))
    assert did_from_public_key(bytes(key.verify_key)) == VECTOR["keys"][name]["did_key"]


def test_positive_signatures_reproduce_from_the_seeds():
    for case in VECTOR["signed"]:
        prefix = f"{case['type']}/1\n".encode()
        signing_bytes = prefix + canonical_json_bytes(case["payload"])
        assert b64u(signing_bytes) == case["signing_bytes_b64url"]
        signature = SigningKey(_seed(case["key"])).sign(signing_bytes).signature
        assert b64u(signature) == case["signature"]


def test_the_encryption_key_matches_its_public_half():
    keys = VECTOR["keys"]["runner_encryption"]
    private = X25519PrivateKey.from_private_bytes(bytes.fromhex(keys["private_hex"]))
    assert b64u(private.public_key().public_bytes_raw()) == keys["public_b64url"]


@pytest.mark.parametrize("case", VECTOR["sealed_credentials"], ids=lambda case: case["name"])
def test_sealed_credential_cases(case):
    private = X25519PrivateKey.from_private_bytes(
        bytes.fromhex(VECTOR["keys"][case["recipient"]]["private_hex"])
    )
    sealed = from_b64u(case["sealed"], "sealed_invalid")
    info = case["info"].encode()
    if "error" in case["expected"]:
        with pytest.raises(InvalidTag):
            SUITE.decrypt(sealed, private, info)
        return
    assert SUITE.decrypt(sealed, private, info) == case["expected"]["plaintext"].encode()


def test_every_refusal_code_of_the_contract_has_a_case():
    request_codes = {c["expected"].get("error") for c in VECTOR["requests"]} - {None}
    assignment_codes = {c["expected"].get("error") for c in VECTOR["assignments"]} - {None}
    assert request_codes == {
        "runner_request_invalid",
        "runner_unknown",
        "runner_request_binding_mismatch",
        "runner_request_stale",
        "runner_request_replayed",
    }
    assert assignment_codes == {
        "assignment_invalid",
        "assignment_wrong_runner",
        "assignment_binding_mismatch",
        "assignment_expired",
        "assignment_replayed",
    }
