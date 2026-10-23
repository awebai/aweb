"""A named operation sent through the real egress guard to the S19 upstream."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import secrets
from pathlib import Path

import pytest
from aweb_naapp.egress import EgressRefused, Network

from aweb_secrets.broker import SecretVersion, broker_operation
from aweb_secrets.operation import OperationTemplate
from aweb_secrets.operation_request import render_operation
from aweb_secrets.response_audit import ResponseKey
from aweb_secrets.tokens import ProcessTokenCache

from .harness import NAME, Upstream, running_upstream
from .test_operation_record import REFUND


def _template(upstream: Upstream, **changes) -> OperationTemplate:
    after = copy.deepcopy(REFUND)
    after["url"] = {
        "host": NAME,
        "port": upstream.port,
        "path": "/bearer/echo/charges/{charge}/refunds",
    }
    after["response"] = {
        "projection": ["/scheme", "/path", "/body_sha256", "/idempotency_key"],
        "max_bytes": 4096,
        "content_types": ["application/json"],
    }
    after.update(changes)
    return OperationTemplate.from_after(after)


def _internal(upstream: Upstream, request):
    """The operation's own destination, reached on the test network: the same
    target, marked internal with the upstream's exact address."""
    return dataclasses.replace(
        request,
        destination=dataclasses.replace(
            request.destination, network=Network.INTERNAL, cidr=upstream.destination().cidr
        ),
    )


async def _send(upstream: Upstream, request, token: str | None = None):
    return await broker_operation(
        upstream.egress,
        _internal(upstream, request),
        kind="bearer",
        value={"value": token or upstream.creds.bearer},
        kind_params={},
        secret_ref="payments",
        response_key=ResponseKey(secrets.token_bytes(32)),
    )


@pytest.fixture
async def upstream(tmp_path: Path):
    async with running_upstream(tmp_path) as running:
        yield running


async def test_a_named_operation_verifies_and_returns_its_projection(upstream: Upstream) -> None:
    template = _template(upstream)
    request = render_operation(
        template,
        {"charge": "ch_3Pq9", "amount_minor_units": 500, "currency": "EUR"},
        headers=[],
        idempotency_key="secrets-d1",
    )
    assert request.destination.header_allow == frozenset(
        {"stripe-version", "x-request-id", "idempotency-key"}
    )
    call = await _send(upstream, request)
    assert call.result.disposition == "returned", call.result
    assert json.loads(call.result.body) == {
        "/scheme": "bearer",
        "/path": "/bearer/echo/charges/ch_3Pq9/refunds",
        "/body_sha256": hashlib.sha256(request.body).hexdigest(),
        "/idempotency_key": "secrets-d1",
    }


async def test_an_undeclared_response_type_is_withheld(upstream: Upstream) -> None:
    template = _template(
        upstream, response={"projection": None, "max_bytes": 4096, "content_types": ["text/csv"]}
    )
    request = render_operation(
        template,
        {"charge": "ch_1", "amount_minor_units": 5, "currency": "EUR"},
        headers=[],
        idempotency_key="secrets-d2",
    )
    call = await _send(upstream, request)
    assert call.result.disposition == "withheld"
    assert call.result.withheld_reason == "content_type_not_allowed"
    assert call.result.status == 200


async def test_a_wrong_credential_fails_at_the_upstream(upstream: Upstream) -> None:
    request = render_operation(
        _template(upstream),
        {"charge": "ch_1", "amount_minor_units": 5, "currency": "EUR"},
        headers=[],
        idempotency_key="secrets-d3",
    )
    call = await _send(upstream, request, token="not-the-token")
    assert call.result.status == 401


def _issuing(upstream: Upstream, *, handling: str = "withhold", projection=None):
    template = _template(
        upstream,
        url={"host": NAME, "port": upstream.port, "path": "/bearer/issue"},
        token_issuing=handling != "undeclared",
        result_handling="deny" if handling == "undeclared" else handling,
        response={
            "projection": projection,
            "max_bytes": 4096,
            "content_types": ["application/json"],
        },
        params={},
        body=None,
    )
    return render_operation(template, {}, headers=[], idempotency_key="secrets-issue")


@pytest.mark.parametrize("handling", ["deny", "store_as_secret"])
async def test_unsupported_token_issuance_never_reaches_the_upstream(
    upstream: Upstream, handling: str
) -> None:
    # The derived-secret mode is refused at validation today. Its dispatch
    # seam must stay closed too until custody is wired, even for an old row.
    request = dataclasses.replace(_issuing(upstream, handling="deny"), result_handling=handling)
    with pytest.raises(EgressRefused) as refused:
        await _send(upstream, request)
    assert refused.value.code == "token_issuing_denied"
    assert upstream.paths == []


async def test_denied_issuance_is_refused_before_even_exchanging_oauth_credentials(
    upstream: Upstream,
) -> None:
    request = _issuing(upstream, handling="deny")
    with pytest.raises(EgressRefused) as refused:
        await broker_operation(
            upstream.egress,
            _internal(upstream, request),
            kind="oauth2-client-credentials",
            value={
                "client_id": upstream.creds.oauth_client_id,
                "client_secret": upstream.creds.oauth_client_secret,
            },
            kind_params={
                "token_endpoint": upstream.url("/oauth2/token"),
                "client_auth": "client_secret_basic",
                "scope": upstream.creds.oauth_scope,
            },
            secret_ref="oauth-test",
            response_key=ResponseKey(secrets.token_bytes(32)),
            token_destination=upstream.destination(path="/oauth2/token", methods=["POST"]),
            tokens=ProcessTokenCache(),
            secret=SecretVersion("inst-1", "backend:example.com", "sec-oauth", 1),
        )
    assert refused.value.code == "token_issuing_denied"
    assert upstream.paths == []
    assert upstream.issued() == 0


async def test_an_issuing_operation_returns_only_its_noncredential_projection(
    upstream: Upstream,
) -> None:
    request = _issuing(upstream, projection=["/AssumedRoleUser/Arn", "/Credentials/Expiration"])
    assert request.result_handling == "withhold"
    call = await _send(upstream, request)
    assert upstream.paths == ["/bearer/issue"]
    assert call.result.status == 200
    assert call.result.disposition == "returned"
    assert call.result.undeclared_credential is False
    projected = json.loads(call.result.body)
    assert set(projected) == {"/AssumedRoleUser/Arn", "/Credentials/Expiration"}
    assert projected["/AssumedRoleUser/Arn"] == "arn:aws:sts::123456789012:assumed-role/e2e/test"


async def test_an_issuing_operation_that_projects_a_credential_is_withheld(
    upstream: Upstream,
) -> None:
    request = _issuing(upstream, projection=["/Credentials/SessionToken"])
    call = await _send(upstream, request)
    assert upstream.paths == ["/bearer/issue"]
    assert call.result.status == 200
    assert call.result.disposition == "withheld"
    assert call.result.withheld_reason == "credential_shaped"
    assert call.result.body is None
    assert call.result.undeclared_credential is False


async def test_an_undeclared_credential_issuance_is_withheld_and_flagged(
    upstream: Upstream,
) -> None:
    request = _issuing(upstream, handling="undeclared")
    call = await _send(upstream, request)
    assert upstream.paths == ["/bearer/issue"]
    assert call.result.status == 200
    assert call.result.disposition == "withheld"
    assert call.result.withheld_reason == "credential_shaped"
    assert call.result.body is None
    assert call.result.undeclared_credential is True
