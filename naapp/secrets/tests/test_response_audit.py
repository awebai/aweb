"""Response commitments bind actual upstream and returned bytes, with real TLS."""

import base64
import hashlib
import hmac
import secrets

import pytest
from aweb_naapp.egress import Bounds
from aweb_naapp.hooks.catalog import packaged_catalog
from fastapi import Request, Response

from aweb_secrets.broker import broker, broker_operation
from aweb_secrets.operation_request import render_operation
from aweb_secrets.response_audit import ResponseKey, ResponseKeyInvalid
from tests.harness import running_upstream
from tests.test_broker_operation import _internal, _template


def digest(material, body):
    return (
        base64.urlsafe_b64encode(hmac.digest(material, body, hashlib.sha256)).decode().rstrip("=")
    )


def test_response_key_file_uses_independent_private_material(tmp_path):
    material = secrets.token_bytes(32)
    path = tmp_path / "response-key"
    path.write_text(material.hex() + "\n")
    path.chmod(0o600)
    key = ResponseKey.from_file(path)
    if material.hex() in repr(key) or str(material) in repr(key):
        raise AssertionError("response key appeared in representation")
    assert key == ResponseKey(material)
    path.chmod(0o666)
    with pytest.raises(ResponseKeyInvalid):
        ResponseKey.from_file(path)


@pytest.mark.parametrize("size", [0, 16, 31, 33, 64])
def test_response_key_rejects_wrong_size_without_echoing_material(size):
    material = secrets.token_bytes(size)
    with pytest.raises(ResponseKeyInvalid) as refused:
        ResponseKey(material)
    if size and (material.hex() in str(refused.value) or str(material) in str(refused.value)):
        raise AssertionError("invalid response key appeared in error")


@pytest.mark.parametrize(
    "mode", ["redacted", "projected", "withheld", "empty", "bounded", "egress_cut"]
)
async def test_real_broker_commits_exact_raw_and_handled_response_without_retaining_raw(
    tmp_path, mode
):
    material = secrets.token_bytes(32)
    async with running_upstream(tmp_path) as upstream:
        raw = (
            b""
            if mode == "empty"
            else b'{ "echo" : "' + upstream.creds.bearer.encode() + b'", "kept" : "ok" }'
        )

        @upstream.app.get("/response-audit")
        async def response(request: Request):
            if not secrets.compare_digest(
                request.headers.get("authorization", ""), "Bearer " + upstream.creds.bearer
            ):
                return Response(status_code=401)
            return Response(content=raw, media_type="application/json")

        call = await broker(
            upstream.egress,
            method="GET",
            url=upstream.url("/response-audit"),
            destination=upstream.destination(),
            headers=[],
            body=b"",
            kind="bearer",
            value={"value": upstream.creds.bearer},
            kind_params={},
            secret_ref="response-proof",
            max_bytes=1 if mode == "bounded" else 4096,
            projection=["/kept"] if mode == "projected" else None,
            token_issuing=False,
            content_types=["text/csv"] if mode == "withheld" else None,
            bounds=Bounds(max_response_bytes=8) if mode == "egress_cut" else None,
            response_key=ResponseKey(material),
        )
        received = raw[:8] if mode == "egress_cut" else raw
        fields = call.audit.fields()
        assert fields["upstream_response_hmac"] == digest(material, received)
        assert fields["upstream_status_code"] == 200
        assert fields["upstream_bytes"] == len(received)
        assert fields["upstream_truncated"] == (mode == "egress_cut")
        if mode == "withheld":
            assert call.result.body is None
            assert "returned_hmac" not in fields
        else:
            assert fields["returned_hmac"] == digest(material, call.result.body)
        if mode in {"redacted", "projected", "bounded"}:
            assert fields["upstream_response_hmac"] != fields["returned_hmac"]
            assert fields["redaction_count"] == 1
        if mode == "bounded":
            assert call.result.truncated is True
            assert fields["upstream_truncated"] is False
        if mode == "projected":
            assert call.result.body == b'{"/kept":"ok"}'
        if mode == "empty":
            assert call.result.body == b""
            assert fields["returned_hmac"] == digest(material, b"")
        assert fields["redaction_count"] == call.result.redaction_count
        assert fields["disposition"] == call.result.disposition
        assert fields["undeclared_credential"] is False
        # Validate against the real event catalog, with its ordinary metadata.
        packaged_catalog().validate(
            "post-secret-use-hook",
            {"action": "completed", "op_kind": "broker", **fields},
        )
        for forbidden in (upstream.creds.bearer, material.hex(), str(material)):
            if forbidden in repr(call.audit) + repr(fields):
                raise AssertionError("response audit retained sensitive material")
        fields["upstream_status_code"] = 999
        assert call.audit.fields()["upstream_status_code"] == 200


async def test_named_operation_forwards_response_key_and_records_projected_bytes(tmp_path):
    material = secrets.token_bytes(32)
    async with running_upstream(tmp_path) as upstream:
        request = _internal(
            upstream,
            render_operation(
                _template(upstream),
                {"charge": "ch_public", "amount_minor_units": 5, "currency": "EUR"},
                headers=[],
                idempotency_key="secrets-response-proof",
            ),
        )
        call = await broker_operation(
            upstream.egress,
            request,
            kind="bearer",
            value={"value": upstream.creds.bearer},
            kind_params={},
            secret_ref="response-proof",
            response_key=ResponseKey(material),
        )
        assert call.result.status == 200
        assert call.audit.fields()["returned_hmac"] == digest(material, call.result.body)
        assert call.audit.fields()["upstream_response_hmac"] != digest(material, call.result.body)


async def test_an_unconfigured_response_key_refuses_before_sending(tmp_path):
    async with running_upstream(tmp_path) as upstream:
        with pytest.raises(ResponseKeyInvalid):
            await broker(
                upstream.egress,
                method="GET",
                url=upstream.url("/bearer/echo"),
                destination=upstream.destination(),
                headers=[],
                body=b"",
                kind="bearer",
                value={"value": upstream.creds.bearer},
                kind_params={},
                secret_ref="response-proof",
                max_bytes=4096,
                projection=None,
                token_issuing=False,
                response_key=None,
            )
        assert upstream.paths == []


@pytest.mark.parametrize("content", ["", "0" * 63, "0" * 65, "g" * 64, "0" * 64 + "\n\n"])
def test_invalid_response_key_files_fail_closed(tmp_path, content):
    path = tmp_path / "response-key"
    path.write_text(content)
    path.chmod(0o600)
    with pytest.raises(ResponseKeyInvalid):
        ResponseKey.from_file(path)
