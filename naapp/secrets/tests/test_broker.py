"""Brokered calls through the real egress guard to the S19 upstream over TLS
(see tests/harness.py)."""

from __future__ import annotations

import json
import secrets
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from aweb_naapp.egress import EgressRefused

from aweb_secrets.broker import broker

from .harness import OTHER, Upstream, running_upstream


@pytest.fixture
async def upstream(tmp_path: Path) -> AsyncIterator[Upstream]:
    async with running_upstream(tmp_path) as running:
        yield running


def _secret(upstream: Upstream, kind: str) -> tuple[dict[str, str], dict[str, str]]:
    c = upstream.creds
    return {
        "bearer": ({"value": c.bearer}, {}),
        "basic": ({"username": c.basic_username, "password": c.basic_password}, {}),
        "header": ({"value": c.header_value}, {"name": c.header_name, "prefix": c.header_prefix}),
        "query": ({"value": c.query_value}, {"param": c.query_param}),
    }[kind]


async def _call(upstream: Upstream, kind: str, *, url: str | None = None, headers=(), **kw):
    value, kind_params = _secret(upstream, kind)
    return await broker(
        upstream.egress,
        method=kw.pop("method", "GET"),
        url=url or upstream.url(f"/{kind}/echo"),
        destination=kw.pop("destination", None) or upstream.destination(),
        headers=list(headers),
        body=kw.pop("body", b""),
        kind=kind,
        value=value,
        kind_params=kind_params,
        secret_ref="upstream-test",
        max_bytes=4096,
        projection=None,
        token_issuing=False,
    )


@pytest.mark.parametrize("kind", ["bearer", "basic", "header", "query"])
async def test_each_scheme_verifies_at_the_upstream(upstream: Upstream, kind: str) -> None:
    call = await _call(upstream, kind)
    assert call.result.status == 200, call.result.body
    assert call.result.disposition == "returned"
    assert json.loads(call.result.body)["scheme"] == kind


@pytest.mark.parametrize("kind", ["bearer", "basic", "header", "query"])
async def test_the_request_asks_for_an_unencoded_response(upstream: Upstream, kind: str) -> None:
    call = await _call(upstream, kind)
    assert json.loads(call.result.body)["accept_encoding"] == "identity"


async def test_a_query_credential_echoed_back_is_redacted(upstream: Upstream) -> None:
    call = await _call(upstream, "query")
    echoed = json.loads(call.result.body)
    assert upstream.creds.query_value not in call.result.body.decode()
    assert echoed["query"] == "key=[REDACTED:upstream-test]"
    assert call.result.redaction_count == 1
    assert call.recorded_url == upstream.url("/query/echo") + "?key=[REDACTED]"
    assert upstream.creds.query_value not in call.recorded_url


async def test_a_wrong_host_gets_no_injection(upstream: Upstream) -> None:
    with pytest.raises(EgressRefused) as refused:
        await _call(upstream, "bearer", url=upstream.url("/bearer/echo", name=OTHER))
    assert refused.value.code == "destination_not_in_scope"
    assert upstream.requests == []


@pytest.mark.parametrize(
    "header",
    [
        ("Authorization", "Bearer agent-own"),
        ("X-Upstream-Key", "Key agent-own"),
        ("Cookie", "a=b"),
        ("Accept-Encoding", "gzip"),
        ("X-Request-Id", "ghp_" + "Ab3dEf7hJk" * 4),
    ],
    ids=["authorization", "injected-name", "cookie", "accept-encoding", "credential-shaped"],
)
async def test_a_refused_agent_header_sends_nothing(upstream: Upstream, header) -> None:
    with pytest.raises(EgressRefused) as refused:
        await _call(upstream, "header", headers=[header])
    assert refused.value.code == "header_not_allowed"
    assert upstream.requests == []


async def test_an_allowed_agent_header_passes(upstream: Upstream) -> None:
    call = await _call(upstream, "bearer", headers=[("Accept", "application/json")])
    assert call.result.status == 200


async def test_an_agent_url_carrying_the_injected_param_sends_nothing(upstream: Upstream) -> None:
    with pytest.raises(EgressRefused) as refused:
        await _call(upstream, "query", url=upstream.url("/query/echo?key=mine"))
    assert refused.value.code == "params_invalid"
    assert upstream.requests == []


async def test_a_wrong_credential_is_refused_by_the_upstream(upstream: Upstream) -> None:
    call = await broker(
        upstream.egress,
        method="GET",
        url=upstream.url("/bearer/echo"),
        destination=upstream.destination(),
        headers=[],
        body=b"",
        kind="bearer",
        value={"value": "not-the-upstream-token"},
        kind_params={},
        secret_ref="upstream-test",
        max_bytes=4096,
        projection=None,
        token_issuing=False,
    )
    assert call.result.status == 401


# --- aws-sigv4 -------------------------------------------------------------------


async def _sigv4_call(upstream: Upstream, value: dict, *, headers=(), params=None):
    return await broker(
        upstream.egress,
        method="POST",
        url=upstream.url("/sigv4/echo"),
        destination=upstream.destination(header_allow=["X-Amz-Target"]),
        headers=list(headers),
        body=b'{"q":1}',
        kind="aws-sigv4",
        value=value,
        kind_params=params
        or {"region": upstream.creds.sigv4_region, "service": upstream.creds.sigv4_service},
        secret_ref="aws-test",
        max_bytes=4096,
        projection=None,
        token_issuing=False,
        amz_allowed=["X-Amz-Target"],
    )


def _aws(upstream: Upstream, **change: str) -> dict:
    return {
        "access_key_id": upstream.creds.sigv4_access_key_id,
        "secret_access_key": upstream.creds.sigv4_secret_access_key,
        **change,
    }


async def test_sigv4_verifies_at_the_upstream(upstream: Upstream) -> None:
    call = await _sigv4_call(
        upstream,
        _aws(upstream),
        headers=[("Content-Type", "application/x-amz-json-1.1"), ("X-Amz-Target", "Things.Get")],
    )
    assert call.result.status == 200, call.result.body
    assert json.loads(call.result.body)["scheme"] == "aws-sigv4"


async def test_sigv4_with_a_session_token_verifies_at_the_upstream(upstream: Upstream) -> None:
    call = await _sigv4_call(upstream, _aws(upstream, session_token=secrets.token_urlsafe(40)))
    assert call.result.status == 200, call.result.body


async def test_sigv4_with_a_wrong_secret_key_is_refused_by_the_upstream(upstream: Upstream) -> None:
    call = await _sigv4_call(upstream, _aws(upstream, secret_access_key="wrong-secret-key"))
    assert call.result.status == 401


async def test_sigv4_signs_only_with_the_secrets_region(upstream: Upstream) -> None:
    call = await _sigv4_call(
        upstream, _aws(upstream), params={"region": "us-east-1", "service": upstream.creds.sigv4_service}
    )
    assert call.result.status == 401


async def test_an_undeclared_amz_header_sends_nothing(upstream: Upstream) -> None:
    with pytest.raises(EgressRefused) as refused:
        await _sigv4_call(upstream, _aws(upstream), headers=[("X-Amz-Region-Override", "us-east-1")])
    assert refused.value.code == "header_not_allowed"
    assert upstream.requests == []
