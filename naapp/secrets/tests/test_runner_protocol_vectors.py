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
CREDENTIAL_FIELDS = {"secret_ref", "sealed"}
MAX_ASSIGNMENT_BODY_BYTES = 1024 * 1024
SAFE_INTEGER = 2**53 - 1
SKEW = timedelta(seconds=120)
MAX_ASSIGNMENT_LIFETIME = timedelta(seconds=300)
# At least 16 CSPRNG bytes in unpadded base64url after the kind prefix.
RUNNER_ID = re.compile(r"rnr_[A-Za-z0-9_-]{22,}")
DISPATCH_ID = re.compile(r"dsp_[A-Za-z0-9_-]{22,}")
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


def _check_values(value: Any, code: str) -> None:
    """Strings are Unicode scalar values; integers are within the safe range."""
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise Refused(code) from exc
    elif isinstance(value, bool) or value is None:
        return
    elif isinstance(value, int):
        if abs(value) > SAFE_INTEGER:
            raise Refused(code)
    elif isinstance(value, dict):
        for key, item in value.items():
            _check_values(key, code)
            _check_values(item, code)
    elif isinstance(value, list):
        for item in value:
            _check_values(item, code)


def canonical_bytes(value: Any, code: str) -> bytes:
    _check_values(value, code)
    return canonical_json_bytes(value)


def canonical_object(raw: bytes, code: str) -> dict[str, Any]:
    value = strict_json(raw, code)
    if not isinstance(value, dict) or canonical_bytes(value, code) != raw:
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
    if not RUNNER_ID.fullmatch(payload["runner_id"]):
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
    if len(case["body_json"].encode("utf-8", "surrogatepass")) > MAX_ASSIGNMENT_BODY_BYTES:
        raise Refused(code)
    body = strict_json(case["body_json"], code)
    if not isinstance(body, dict) or set(body) != BODY_FIELDS:
        raise Refused(code)
    if not isinstance(body["assignment"], dict) or not isinstance(body["params"], dict):
        raise Refused(code)
    if not isinstance(body["credentials"], list):
        raise Refused(code)
    payload = body["assignment"]
    payload_bytes = canonical_bytes(payload, code)
    params_bytes = canonical_bytes(body["params"], code)
    credentials_bytes = canonical_bytes(body["credentials"], code)
    for item in body["credentials"]:
        if not isinstance(item, dict) or set(item) != CREDENTIAL_FIELDS:
            raise Refused(code)
        if not isinstance(item["secret_ref"], str) or not isinstance(item["sealed"], str):
            raise Refused(code)
        from_b64u(item["sealed"], code)
    if set(payload) != ASSIGNMENT_FIELDS or payload["v"] != 1 or payload["type"] != ASSIGNMENT_TYPE:
        raise Refused(code)
    if not all(isinstance(payload[f], str) for f in ASSIGNMENT_FIELDS - {"v"}):
        raise Refused(code)
    if not all(
        HEX64.fullmatch(payload[f]) for f in ("job_digest", "params_sha256", "credentials_sha256")
    ):
        raise Refused(code)
    if not RUNNER_ID.fullmatch(payload["runner_id"]) or not DISPATCH_ID.fullmatch(
        payload["dispatch_id"]
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
        payload["params_sha256"] != hashlib.sha256(params_bytes).hexdigest()
        or payload["credentials_sha256"] != hashlib.sha256(credentials_bytes).hexdigest()
    ):
        raise Refused("assignment_binding_mismatch")
    now = at(case["now"])
    if (
        not issued_at < expires_at
        or expires_at - issued_at > MAX_ASSIGNMENT_LIFETIME
        or now >= expires_at
        or issued_at - now > SKEW
    ):
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


def test_an_oversized_claim_response_is_refused():
    valid = next(c for c in VECTOR["assignments"] if c["name"] == "valid")
    padding = ', "padding": "' + "x" * MAX_ASSIGNMENT_BODY_BYTES + '"'
    padded = valid["body_json"].replace('"database": "orders"', '"database": "orders"' + padding)
    assert padded != valid["body_json"]
    with pytest.raises(Refused) as refused:
        verify_assignment(dict(valid, body_json=padded))
    assert refused.value.code == "assignment_invalid"


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


# This is a contract reference reader, not a mounted route or release authority.
HTTP_VECTOR = json.loads(
    (Path(__file__).parents[3] / "docs" / "vectors" / "secrets-runner-http-v1.json").read_text()
)
RESULT_FIELDS = {"exit_code", "stdout", "stderr", "truncated", "result_withheld", "redaction_count"}
FIELD_FAMILIES = {
    "bearer": {"value"},
    "basic": {"username", "password"},
    "oauth2-client-credentials": {"client_id", "client_secret"},
    "aws-sigv4": {"access_key_id", "secret_access_key", "session_token"},
}


def _http_body_result(case):
    raw = case["body_json"].encode("utf-8")
    limit = case["output_max_bytes"]
    is_result = case["endpoint"] == "result"
    if len(raw) > (6 * limit + 1024 if is_result else 4096):
        return {"status": 413, "code": "runner_request_too_large"}
    code = "runner_result_invalid" if is_result else "runner_request_invalid"
    try:
        body = strict_json(raw, code)
        _check_values(body, code)
        if not isinstance(body, dict) or set(body) != (RESULT_FIELDS if is_result else set()):
            raise Refused(code)
        if is_result:
            if type(body["exit_code"]) is not int or type(body["redaction_count"]) is not int:
                raise Refused(code)
            if body["redaction_count"] < 0:
                raise Refused(code)
            if any(type(body[key]) is not bool for key in ("truncated", "result_withheld")):
                raise Refused(code)
            if any(not isinstance(body[key], str) for key in ("stdout", "stderr")):
                raise Refused(code)
            if sum(len(body[key].encode("utf-8")) for key in ("stdout", "stderr")) > limit:
                raise Refused(code)
            if body["result_withheld"] and (body["stdout"] or body["stderr"]):
                raise Refused(code)
    except Refused:
        return {"status": 400, "code": code}
    return {"status": 204}


@pytest.mark.parametrize("case", HTTP_VECTOR["bodies"], ids=lambda case: case["name"])
def test_http_body_vectors(case):
    assert hashlib.sha256(case["body_json"].encode("utf-8")).hexdigest() == case["body_sha256"]
    assert _http_body_result(case) == case["expected"]


@pytest.mark.parametrize("case", HTTP_VECTOR["field_families"], ids=lambda case: case["name"])
def test_http_env_family_vectors(case):
    selected = set(case["selected_fields"])
    candidates = [
        kind for kind, fields in FIELD_FAMILIES.items() if selected and selected <= fields
    ]
    actual = (
        {"validation_kind": candidates[0]} if len(candidates) == 1 else {"error": "job_invalid"}
    )
    assert actual == case["expected"]


@pytest.mark.parametrize("case", HTTP_VECTOR["report_statuses"])
def test_http_report_status_vectors(case):
    if not case["released"]:
        status, code, effect = 409, "runner_dispatch_state_conflict", "none"
    elif case["prior_result"] == "different":
        status, code, effect = 409, "runner_result_conflict", "none"
    elif case["prior_result"] == "identical":
        status, code, effect = 204, None, "none"
    else:
        status, code = 204, None
        effect = "completed" if case["state"] == "dispatching" else "late_evidence"
    assert (status, code, effect) == (case["expected_status"], case.get("code"), case["effect"])


@pytest.mark.parametrize("case", HTTP_VECTOR["claim_statuses"], ids=lambda case: case["name"])
def test_http_claim_status_vectors(case):
    if case["state"] == "outcome_unknown":
        actual = {"status": 409, "code": "runner_reconciliation_required"}
    elif case["state"] == "dispatching":
        actual = (
            {"status": 409, "code": "runner_dispatch_state_conflict"}
            if case["assignment_expired"]
            else {"status": 200, "assignment": "stored_bytes"}
        )
    else:
        actual = {"status": 204}
    assert actual == case["expected"]
