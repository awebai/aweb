"""The Python CSR reader consumes the wire emitted by ordinary aw requests."""
from __future__ import annotations

import asyncio
import base64
import copy
import json
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from awid.id_certificate_request import (
    build_id_certificate_request,
    id_certificate_request_signing_bytes,
    parse_id_certificate_request,
    parse_id_certificate_response,
)
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



# ---------------------------------------------------------------------------
# Building a request and reading its response, as aw id parent request/import do
# ---------------------------------------------------------------------------

ISSUES = {
    name: case for name, case in REQUESTS["requests"].items()
    if case["expected"]["accepted"] and case["signed"]["request"]["operation"] == "issue"
}


def key_name(did_key):
    return next(name for name, value in VECTORS["keys"].items() if value["did_key"] == did_key)


def vector_signer(did_key):
    key = SigningKey(bytes.fromhex(VECTORS["keys"][key_name(did_key)]["seed_hex"]))

    def signer(payload):
        return did_key, key.sign(payload).signature

    return signer


def async_vector_signer(did_key):
    sign = vector_signer(did_key)

    async def signer(payload):
        await asyncio.sleep(0)
        return sign(payload)

    return signer


def build(request, signer=None):
    return build_id_certificate_request(
        request_id=request["request_id"], invitation_id=request["invitation_id"], id=request["id"],
        domain=request["domain"], parent=request["parent"], kind=request["kind"],
        subject_key=request["subject_key"], signer=signer or vector_signer(request["subject_key"]),
    )


@pytest.mark.parametrize("name", sorted(ISSUES))
@pytest.mark.parametrize("make_signer", [vector_signer, async_vector_signer], ids=["sync", "async"])
@pytest.mark.asyncio
async def test_a_built_request_is_the_go_request_byte_for_byte(name, make_signer):
    case = ISSUES[name]
    request = case["signed"]["request"]
    assert id_certificate_request_signing_bytes(request).hex() == case["signing_bytes_hex"]
    raw = await build(request, make_signer(request["subject_key"]))
    assert raw == case["canonical_utf8"].encode()


def test_the_built_cases_cover_both_parents():
    assert {case["signed"]["request"]["parent"]["kind"] for case in ISSUES.values()} == {"identity", "namespace"}


def _wrong_key(did_key):
    other = next(value["did_key"] for value in VECTORS["keys"].values() if value["did_key"] != did_key)
    return vector_signer(other)


def _other_bytes(did_key):
    sign = vector_signer(did_key)
    return lambda payload: sign(payload + b"x")


def _refusing(did_key):
    def signer(payload):
        raise PermissionError("custody check refused")

    return signer


@pytest.mark.parametrize("make_signer", [_wrong_key, _other_bytes], ids=["wrong-key", "other-bytes"])
@pytest.mark.asyncio
async def test_a_signer_answer_is_checked_before_any_bytes_are_returned(make_signer):
    request = ISSUES["human-issue"]["signed"]["request"]
    with pytest.raises(IDCertificateError) as refused:
        await build(request, make_signer(request["subject_key"]))
    assert refused.value.code == "invalid_signature"


@pytest.mark.asyncio
async def test_a_refusing_signer_builds_nothing():
    request = ISSUES["human-issue"]["signed"]["request"]
    with pytest.raises(PermissionError):
        await build(request, _refusing(request["subject_key"]))


@pytest.mark.parametrize("field,value,reason", [
    ("kind", "robot", "invalid_kind"),
    ("domain", "Example.com", "invalid_domain"),
    ("parent", {"kind": "namespace", "id": "other.example"}, "domain_mismatch"),
    ("invitation_id", "not-a-uuid", "invalid_shape"),
    ("request_id", "not-a-uuid", "invalid_shape"),
])
@pytest.mark.asyncio
async def test_a_request_the_receiver_would_refuse_is_never_signed(field, value, reason):
    request = dict(ISSUES["human-issue"]["signed"]["request"], **{field: value})
    asked = []
    with pytest.raises(IDCertificateError) as refused:
        await build(request, lambda payload: asked.append(payload))
    assert refused.value.code == reason
    assert asked == []


RESPONSES = REQUESTS["responses"]


def request_bytes(name):
    return REQUESTS["requests"][name]["canonical_utf8"].encode()


@pytest.mark.parametrize("name", sorted(RESPONSES))
def test_a_response_is_read_against_the_request_it_answers(name):
    case = RESPONSES[name]
    # As in Go's frozen-response test, a response correlates by its request_id.
    [asked] = [
        request for request in REQUESTS["requests"].values()
        if request["expected"]["accepted"] and request["signed"]["request"]["request_id"] == case["response"]["request_id"]
    ]
    parsed = parse_id_certificate_response(case["canonical_utf8"].encode(), request=asked["canonical_utf8"].encode())
    assert parsed == case["response"]


@pytest.mark.parametrize("field,value", [
    ("request_id", "20000000-0000-4000-8000-0000000000ff"),
    ("id", VECTORS["keys"]["alice"]["did_aw"]),
    ("domain", "other.example"),
    ("parent", {"kind": "identity", "id": VECTORS["keys"]["bob"]["did_aw"]}),
    ("kind", "agent"),
])
def test_a_response_bound_to_another_request_is_refused(field, value):
    request = dict(REQUESTS["requests"]["human-issue"]["signed"]["request"], **{field: value})
    with pytest.raises(IDCertificateError) as refused:
        parse_id_certificate_response(RESPONSES["human-issued"]["canonical_utf8"].encode(), request=canonical(signed_request(request)))
    assert refused.value.code == "request_binding_mismatch"


def test_a_response_is_read_only_against_a_valid_request():
    with pytest.raises(IDCertificateError) as refused:
        parse_id_certificate_response(RESPONSES["human-issued"]["canonical_utf8"].encode(), request=request_bytes("bad-subject-signature"))
    assert refused.value.code == "invalid_signature"


def assert_response_refused(raw, reason):
    with pytest.raises(IDCertificateError) as refused:
        parse_id_certificate_response(raw, request=request_bytes("local-resign"))
    assert refused.value.code == reason


@pytest.mark.parametrize("case", [c for c in REQUESTS["file_refusals"] if c["kind"] == "response"], ids=lambda c: c["name"])
def test_frozen_response_file_limits(case):
    raw = (case["unit_utf8"] * case["repeat"]).encode()
    assert len(raw) == case["file_bytes"]
    assert_response_refused(raw, case["expected"]["reason"])


def test_response_refusals_match_go():
    base = RESPONSES["local-resigned"]
    text = base["canonical_utf8"]
    assert_response_refused(canonical({"v": 1, "request_id": "not-a-uuid", "chain": base["response"]["chain"]}), "invalid_shape")
    oversized = {"v": 1, "type": "aweb.id-chain", "certificates": ["x" * 6200]}
    raw = canonical({"v": 1, "request_id": base["response"]["request_id"], "chain": oversized})
    assert len(raw) <= REQUESTS["max_file_bytes"]
    assert_response_refused(raw, "bundle_too_large")
    assert_response_refused(text.replace(",", ", ", 1).encode(), "noncanonical_json")
    assert_response_refused(text.replace('{"chain":', '{"callback":"x","chain":', 1).encode(), "invalid_shape")
    tampered = text.replace('"issued_at":"2026-10-26T00:11:00Z"', '"issued_at":"2026-10-26T00:12:00Z"', 1)
    assert tampered != text
    assert_response_refused(tampered.encode(), "invalid_signature")
    assert_response_refused(canonical({"v": True, "request_id": base["response"]["request_id"], "chain": base["response"]["chain"]}), "invalid_shape")
