"""A named operation sent through the real egress guard to the S19 upstream."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
from pathlib import Path

import pytest
from aweb_naapp.egress import Network

from aweb_secrets.broker import broker_operation
from aweb_secrets.operation import OperationTemplate
from aweb_secrets.operation_request import render_operation

from .harness import NAME, Upstream, running_upstream
from .test_operation_record import REFUND


def _template(upstream: Upstream, **changes) -> OperationTemplate:
    after = copy.deepcopy(REFUND)
    after["url"] = {"host": NAME, "port": upstream.port, "path": "/bearer/echo/charges/{charge}/refunds"}
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
        template, {"charge": "ch_1", "amount_minor_units": 5, "currency": "EUR"}, headers=[]
    )
    call = await _send(upstream, request)
    assert call.result.disposition == "withheld"
    assert call.result.withheld_reason == "content_type_not_allowed"
    assert call.result.status == 200


async def test_a_wrong_credential_fails_at_the_upstream(upstream: Upstream) -> None:
    request = render_operation(
        _template(upstream), {"charge": "ch_1", "amount_minor_units": 5, "currency": "EUR"}, headers=[]
    )
    call = await _send(upstream, request, token="not-the-token")
    assert call.result.status == 401
