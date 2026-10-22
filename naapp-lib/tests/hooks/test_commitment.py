"""The decision-70/73 commitments, against independently framed inputs."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import struct
from dataclasses import replace
from pathlib import Path

import pytest

from aweb_naapp.hooks.catalog import load_catalog
from aweb_naapp.hooks.commitment import (
    CommitmentContext,
    CommitmentError,
    CommitmentKey,
    Purpose,
    RequestBytes,
    load_commitment_key,
)

CATALOG = load_catalog(
    (Path(__file__).resolve().parents[3] / "docs" / "vectors" / "hook-catalog-v1.json").read_bytes()
)
CONTEXT = CommitmentContext("fixture", "demo:example.com", "install-1", 3, "use")
REQUEST = RequestBytes(
    "POST", b"/mounted/v1/items/a%2Fb?tag=one&tag=two", (b"application/json",), b'{"x":1}'
)
DOMAINS = {
    Purpose.MANIFEST_REQUEST: b"aweb.post-manifest-command.request/1\n",
    Purpose.SECRET_REQUEST: b"aweb.post-secret-use.request/1\n",
    Purpose.SECRET_PARAMS: b"aweb.post-secret-use.params/1\n",
}


def _frame(value: bytes) -> bytes:
    return struct.pack(">Q", len(value)) + value


def _request_bytes(request: RequestBytes) -> bytes:
    return (
        _frame(request.method.encode("ascii"))
        + _frame(request.raw_target)
        + struct.pack(">Q", len(request.content_types))
        + b"".join(_frame(value) for value in request.content_types)
        + _frame(request.body)
    )


def _context_bytes(context: CommitmentContext) -> bytes:
    return json.dumps(
        {
            "app_id": context.app_id,
            "team_id": context.team_id,
            "installation_id": context.installation_id,
            "generation": context.generation,
            "tool": context.tool,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


@pytest.mark.parametrize("purpose", [Purpose.MANIFEST_REQUEST, Purpose.SECRET_REQUEST])
def test_request_mac_matches_the_contract_and_catalog(purpose):
    material = secrets.token_bytes(32)
    key = CommitmentKey(purpose, material)
    expected = hmac.new(
        material,
        DOMAINS[purpose] + _context_bytes(CONTEXT) + b"\n" + _request_bytes(REQUEST),
        hashlib.sha256,
    ).hexdigest()
    actual = key.request(CONTEXT, REQUEST)
    assert actual == expected
    assert actual != hashlib.sha256(_request_bytes(REQUEST)).hexdigest()
    if purpose is Purpose.MANIFEST_REQUEST:
        CATALOG.validate(
            "post-manifest-command-hook",
            {
                "app_id": CONTEXT.app_id,
                "tool": CONTEXT.tool,
                "operation_kind": "mutation",
                "request_sha256": actual,
                "http_status": 200,
            },
        )
    else:
        CATALOG.validate(
            "post-secret-use-hook",
            {
                "action": "refused",
                "op_kind": "broker",
                "refusal_code": "params_invalid",
                "request_sha256": actual,
            },
        )


def test_parameters_commit_the_exact_supplied_canonical_utf8_bytes():
    material = secrets.token_bytes(32)
    key = CommitmentKey(Purpose.SECRET_PARAMS, material)
    # Validated canonical parameter bytes come from the caller's B2 value rules.
    params = '{"count":2,"label":"café"}'.encode()
    actual = key.params(CONTEXT, params)
    expected = hmac.new(
        material,
        DOMAINS[Purpose.SECRET_PARAMS] + _context_bytes(CONTEXT) + b"\n" + _frame(params),
        hashlib.sha256,
    ).hexdigest()
    assert actual == expected
    CATALOG.validate(
        "post-secret-use-hook",
        {
            "action": "refused",
            "op_kind": "broker",
            "refusal_code": "params_invalid",
            "params_sha256": actual,
        },
    )
    assert key.params(CONTEXT, None) is None
    assert key.params(CONTEXT, b"{}") != actual


@pytest.mark.parametrize(
    "changed",
    [
        replace(REQUEST, method="PUT"),
        replace(REQUEST, raw_target=b"/other/v1/items/a%2Fb?tag=one&tag=two"),
        replace(REQUEST, raw_target=b"/mounted/v1/items/a%2fb?tag=one&tag=two"),
        replace(REQUEST, raw_target=b"/mounted/v1/items/a%2Fb?tag=two&tag=one"),
        replace(REQUEST, raw_target=b"/mounted/v1/items/a%2Fb?tag=one&tag=three"),
        replace(REQUEST, content_types=(b"application/json; charset=utf-8",)),
        replace(REQUEST, content_types=()),
        replace(REQUEST, content_types=(b"",)),
        replace(REQUEST, content_types=(b"application/json", b"text/plain")),
        replace(REQUEST, content_types=(b"text/plain", b"application/json")),
        replace(REQUEST, body=b'{ "x": 1 }'),
        replace(REQUEST, body=b'{"x":2}'),
        replace(REQUEST, body=b"\x00\xff\r\n"),
        replace(REQUEST, body=b""),
    ],
)
def test_each_request_component_changes_the_mac(changed):
    key = CommitmentKey(Purpose.SECRET_REQUEST, secrets.token_bytes(32))
    original = key.request(CONTEXT, REQUEST)
    assert key.request(CONTEXT, REQUEST) == original
    assert key.request(CONTEXT, changed) != original


def test_framing_distinguishes_boundaries_and_content_type_order():
    a = RequestBytes("POST", b"/a", (b"bc", b"d"), b"\xff\r\n")
    b = RequestBytes("POST", b"/ab", (b"c", b"d"), b"\xff\r\n")
    assert a.framed() == _request_bytes(a)
    assert a.framed() != b.framed()
    assert a.framed() != replace(a, content_types=tuple(reversed(a.content_types))).framed()
    assert a.framed() != replace(a, body=b"\xff\n").framed()
    absent = replace(a, content_types=())
    assert absent.framed() != replace(a, content_types=(b"",)).framed()


@pytest.mark.parametrize(
    "changed",
    [
        replace(CONTEXT, app_id="other"),
        replace(CONTEXT, team_id="other:example.com"),
        replace(CONTEXT, installation_id="install-2"),
        replace(CONTEXT, generation=4),
        replace(CONTEXT, tool="other"),
    ],
)
def test_each_authoritative_context_component_changes_the_mac(changed):
    key = CommitmentKey(Purpose.SECRET_REQUEST, secrets.token_bytes(32))
    assert key.request(CONTEXT, REQUEST) != key.request(changed, REQUEST)


def test_keys_domains_and_parameter_values_are_separate():
    first, second = secrets.token_bytes(32), secrets.token_bytes(32)
    request = CommitmentKey(Purpose.SECRET_REQUEST, first)
    assert request.request(CONTEXT, REQUEST) != CommitmentKey(
        Purpose.SECRET_REQUEST, second
    ).request(CONTEXT, REQUEST)
    assert request.request(CONTEXT, REQUEST) != CommitmentKey(
        Purpose.MANIFEST_REQUEST, first
    ).request(CONTEXT, REQUEST)
    params = CommitmentKey(Purpose.SECRET_PARAMS, first)
    assert params.params(CONTEXT, b'{"x":1}') != params.params(CONTEXT, b'{"x":2}')
    assert params.params(CONTEXT, b'{"x":1}') != CommitmentKey(
        Purpose.SECRET_PARAMS, second
    ).params(CONTEXT, b'{"x":1}')
    with pytest.raises(CommitmentError):
        params.request(CONTEXT, REQUEST)
    with pytest.raises(CommitmentError):
        request.params(CONTEXT, b"{}")


@pytest.mark.parametrize("generation", [False, 0, -1, 1.0, 2**53])
def test_invalid_context_is_refused(generation):
    with pytest.raises(CommitmentError):
        replace(CONTEXT, generation=generation)


@pytest.mark.parametrize("field,value", [("tool", ""), ("tool", "café"), ("app_id", None)])
def test_context_fields_are_nonempty_printable_ascii(field, value):
    with pytest.raises(CommitmentError):
        replace(CONTEXT, **{field: value})


@pytest.mark.parametrize(
    "field,value",
    [
        ("method", "post"),
        ("method", ""),
        ("raw_target", b"/bad\r\n"),
        ("raw_target", b"/bad\xff"),
        ("raw_target", b"relative"),
        ("body", "text"),
        ("body", bytearray(b"mutable")),
        ("content_types", ("text/plain",)),
    ],
)
def test_invalid_request_components_are_refused_without_echoing_them(field, value):
    with pytest.raises(CommitmentError):
        replace(REQUEST, **{field: value})


def _key_file(tmp_path, data):
    path = tmp_path / "commitment.key"
    path.write_bytes(data)
    path.chmod(0o600)
    return path


@pytest.mark.parametrize("upper,newline", [(False, False), (True, False), (False, True)])
def test_key_loader_accepts_the_named_format_and_purpose(tmp_path, upper, newline):
    material = secrets.token_bytes(32)
    text = material.hex().upper() if upper else material.hex()
    path = _key_file(tmp_path, (text + ("\n" if newline else "")).encode())
    loaded = load_commitment_key(Purpose.SECRET_REQUEST, path)
    assert loaded.request(CONTEXT, REQUEST) == CommitmentKey(
        Purpose.SECRET_REQUEST, material
    ).request(CONTEXT, REQUEST)
    assert material.hex() not in repr(loaded)


@pytest.mark.parametrize(
    "change",
    [
        lambda b: b[:-1],
        lambda b: b + b"\n\n",
        lambda b: b + b"\r\n",
        lambda b: b" " + b,
        lambda b: b"z" + b[1:],
        lambda b: b + b"00",
    ],
)
def test_key_loader_refuses_bad_format_without_echoing_the_file(tmp_path, change):
    data = secrets.token_hex(32).encode()
    with pytest.raises(CommitmentError) as refused:
        load_commitment_key(Purpose.SECRET_REQUEST, _key_file(tmp_path, change(data)))
    assert data.decode() not in str(refused.value)


def test_key_loader_reuses_shared_file_checks_and_mounted_symlinks(tmp_path):
    path = _key_file(tmp_path, secrets.token_hex(32).encode())
    link = tmp_path / "mounted.key"
    link.symlink_to(path)
    assert load_commitment_key(Purpose.SECRET_REQUEST, link).purpose is Purpose.SECRET_REQUEST
    path.chmod(0o622)
    for invalid in (path, tmp_path, tmp_path / "missing.key"):
        with pytest.raises(CommitmentError):
            load_commitment_key(Purpose.SECRET_REQUEST, invalid)


def test_key_material_is_32_immutable_bytes_and_purpose_is_closed():
    for invalid in (b"", secrets.token_bytes(31), secrets.token_bytes(33), bytearray(32)):
        with pytest.raises(CommitmentError):
            CommitmentKey(Purpose.SECRET_REQUEST, invalid)
    with pytest.raises(CommitmentError):
        CommitmentKey("unknown", secrets.token_bytes(32))
