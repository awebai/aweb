"""The Python CSR reader consumes the wire emitted by ordinary aw requests."""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from awid.id_certificate_request import parse_id_certificate_request
from awid.id_certificates import IDCertificateError

VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "docs/vectors/id-certificates-v1.json").read_text()
)
REQUESTS = VECTORS["child_requests"]
PREFIX = b"aweb.id-certificate-request/1\n"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def signed_request(request, key=None, prefix=PREFIX):
    if key is None:
        key = next(name for name, value in VECTORS["keys"].items() if value["did_key"] == request["subject_key"])
    signer = SigningKey(bytes.fromhex(VECTORS["keys"][key]["seed_hex"]))
    signature = signer.sign(prefix + canonical(request)).signature
    return {"request": request, "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode()}


def assert_refused(raw, reason):
    with pytest.raises(IDCertificateError) as caught:
        parse_id_certificate_request(raw)
    assert caught.value.code == reason


@pytest.mark.parametrize("name,case", REQUESTS["requests"].items())
def test_frozen_requests(name, case):
    assert PREFIX.decode() == REQUESTS["prefix_utf8"]
    assert (PREFIX + canonical(case["signed"]["request"])).hex() == case["signing_bytes_hex"]
    if case["expected"]["accepted"]:
        assert parse_id_certificate_request(case["canonical_utf8"].encode()) == case["signed"]
    else:
        assert_refused(case["canonical_utf8"].encode(), case["expected"]["reason"])


@pytest.mark.parametrize("case", [c for c in REQUESTS["file_refusals"] if c["kind"] == "request"], ids=lambda c: c["name"])
def test_frozen_file_limits(case):
    raw = (case["unit_utf8"] * case["repeat"]).encode()
    assert len(raw) == case["file_bytes"]
    assert_refused(raw, case["expected"]["reason"])


@pytest.mark.parametrize("raw,reason", [
    (b'{"request":{},"request":{},"signature":"x"}', "invalid_json"),
    (b'{"request":{"v":1,"v":1},"signature":"x"}', "invalid_json"),
    (b'{}{}', "invalid_json"),
    (b'\xff', "invalid_json"),
    (b'{"x":"\\ud800"}', "invalid_json"),
    (b'{"x":1.0}', "invalid_shape"),
    (b'{"x":1e0}', "invalid_shape"),
    (b'{"x":NaN}', "invalid_shape"),
    (b'{"x":Infinity}', "invalid_shape"),
    (b'[]', "invalid_shape"),
    (b'null', "invalid_shape"),
])
def test_strict_json(raw, reason):
    assert_refused(raw, reason)


@pytest.mark.parametrize("formatting", ["whitespace", "order", "escaped"])
def test_noncanonical_json(formatting):
    signed = REQUESTS["requests"]["human-issue"]["signed"]
    raw = canonical(signed)
    if formatting == "whitespace":
        raw += b"\n"
    elif formatting == "order":
        raw = json.dumps(dict(reversed(list(signed.items()))), separators=(",", ":")).encode()
    else:
        raw = raw.replace(b"did:aw:", b"did\\u003aaw:", 1)
    assert_refused(raw, "noncanonical_json")


@pytest.mark.parametrize("path,value,reason", [
    (("extra",), None, "invalid_shape"),
    (("request", "extra"), None, "invalid_shape"),
    (("request",), [], "invalid_shape"),
    (("request", "v"), True, "invalid_shape"),
    (("request", "type"), "other", "invalid_shape"),
    (("request", "request_id"), "ABCDEFAB-1234-1234-1234-123456789ABC", "invalid_shape"),
    (("request", "request_id"), None, "invalid_shape"),
    (("request", "kind"), "robot", "invalid_kind"),
    (("request", "kind"), [], "invalid_kind"),
    (("request", "id"), "did:aw:bad", "invalid_shape"),
    (("request", "domain"), "Example.com", "invalid_domain"),
    (("request", "domain"), None, "invalid_domain"),
    (("request", "parent"), {"kind": "namespace", "id": "other.example"}, "domain_mismatch"),
    (("request", "parent"), {"kind": "namespace", "id": None}, "invalid_domain"),
    (("request", "parent"), {"kind": "identity", "id": "alias"}, "invalid_shape"),
    (("request", "parent"), {"kind": "other", "id": "example.com"}, "invalid_shape"),
    (("request", "parent"), [], "invalid_shape"),
    (("request", "subject_key"), "did:aw:bad", "invalid_shape"),
    (("request", "operation"), "adopt", "invalid_shape"),
    (("request", "invitation_id"), None, "invalid_shape"),
    (("request", "old_certificate"), {}, "invalid_shape"),
    (("signature",), "AA==", "invalid_encoding"),
    (("signature",), "AA", "invalid_encoding"),
    (("signature",), None, "invalid_encoding"),
])
def test_shape_and_encoding(path, value, reason):
    signed = copy.deepcopy(REQUESTS["requests"]["human-issue"]["signed"])
    target = signed
    for field in path[:-1]:
        target = target[field]
    target[path[-1]] = value
    assert_refused(canonical(signed), reason)


@pytest.mark.parametrize("which", ["wrapper", "request"])
def test_missing_fields(which):
    signed = copy.deepcopy(REQUESTS["requests"]["human-issue"]["signed"])
    target = signed if which == "wrapper" else signed["request"]
    for field in list(target):
        value = target.pop(field)
        assert_refused(canonical(signed), "invalid_shape")
        target[field] = value


def test_signature_is_for_this_request_and_this_prefix():
    request = copy.deepcopy(REQUESTS["requests"]["human-issue"]["signed"]["request"])
    assert_refused(canonical(signed_request(request, prefix=b"aweb.id-certificate/1\n")), "invalid_signature")
    signed = signed_request(request)
    signed["request"]["request_id"] = "00000000-0000-0000-0000-000000000000"
    assert_refused(canonical(signed), "invalid_signature")


@pytest.mark.parametrize("signature", [bytes(64), bytes(32) + bytes([255]) * 32])
def test_strict_ed25519_profile(signature):
    signed = copy.deepcopy(REQUESTS["requests"]["human-issue"]["signed"])
    signed["signature"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    assert_refused(canonical(signed), "invalid_signature")


def test_existing_global_id_can_prove_a_different_current_key_without_derivation():
    request = copy.deepcopy(REQUESTS["requests"]["human-issue"]["signed"]["request"])
    request.update(kind="agent", id=VECTORS["keys"]["alice"]["did_aw"], subject_key=VECTORS["keys"]["alice_rotated"]["did_key"])
    signed = signed_request(request, key="alice_rotated")
    assert parse_id_certificate_request(canonical(signed)) == signed
    # Crypto alone does not establish that AWID currently maps this ID to that key.
    signed = signed_request(request, key="alice")
    assert_refused(canonical(signed), "invalid_signature")


def test_local_subject_must_equal_its_key_and_humans_cannot_be_local():
    request = copy.deepcopy(REQUESTS["requests"]["human-issue"]["signed"]["request"])
    request["id"] = request["subject_key"]
    assert_refused(canonical(signed_request(request)), "invalid_shape")
    request["kind"] = "agent"
    assert parse_id_certificate_request(canonical(signed_request(request)))["request"] == request
    request["id"] = next(value["did_key"] for value in VECTORS["keys"].values() if value["did_key"] != request["subject_key"])
    assert_refused(canonical(signed_request(request)), "invalid_shape")


@pytest.mark.parametrize("field,value", [("invitation_id", "00000000-0000-0000-0000-000000000000"), ("kind", "human"), ("id", VECTORS["keys"]["alice"]["did_aw"]), ("old_certificate", None)])
def test_resign_shape(field, value):
    signed = copy.deepcopy(REQUESTS["requests"]["local-resign"]["signed"])
    signed["request"][field] = value
    assert_refused(canonical(signed), "invalid_shape")
