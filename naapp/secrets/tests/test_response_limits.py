"""Owner-defined broker response limits reach the real DNS/TLS egress path."""

import copy

import pytest
from fastapi import Response

from aweb_secrets.destination import DestinationInvalid, DestinationRecord
from aweb_secrets.operation import OperationInvalid, OperationTemplate
from aweb_secrets.operation_request import render_operation

from .harness import NAME, running_upstream
from .test_broker_operation import _send, _template
from .test_destination_record import DISABLED, RECORD
from .test_operation_record import REFUND

DEFAULT = 16 * 1024 * 1024
CEILING = 64 * 1024 * 1024


@pytest.fixture
async def upstream(tmp_path):
    async with running_upstream(tmp_path) as running:
        yield running


@pytest.mark.parametrize("maximum", [None, 1024, 32 * 1024 * 1024, CEILING])
def test_destination_owner_can_bound_the_response(maximum):
    after = copy.deepcopy(RECORD)
    if maximum is not None:
        after["response_max_bytes"] = maximum
    record = DestinationRecord.from_after(after, internal_destinations=DISABLED)
    assert record.max_response_bytes == (DEFAULT if maximum is None else maximum)
    assert record.after == after  # Never rewrite the owner's covered bytes.


@pytest.mark.parametrize("maximum", [True, 0, -1, CEILING + 1])
def test_destination_refuses_invalid_response_limit_at_definition(maximum):
    with pytest.raises(DestinationInvalid):
        DestinationRecord.from_after(
            {**RECORD, "response_max_bytes": maximum}, internal_destinations=DISABLED
        )


@pytest.mark.parametrize("maximum", [None, 1024, 32 * 1024 * 1024, CEILING])
def test_operation_limit_defaults_without_rewriting_covered_bytes(maximum):
    after = copy.deepcopy(REFUND)
    if maximum is None:
        del after["response"]["max_bytes"]
    else:
        after["response"]["max_bytes"] = maximum
    operation = OperationTemplate.from_after(after)
    request = render_operation(
        operation,
        {"charge": "ch_proof", "amount_minor_units": 1, "currency": "EUR"},
        headers=[],
        idempotency_key="secrets-response-limit",
    )
    assert operation.after == after
    assert request.max_bytes == (DEFAULT if maximum is None else maximum)
    assert request.bounds.max_response_bytes == request.max_bytes


@pytest.mark.parametrize("maximum", [True, 0, -1, CEILING + 1])
def test_operation_refuses_invalid_response_limit_at_definition(maximum):
    after = copy.deepcopy(REFUND)
    after["response"]["max_bytes"] = maximum
    with pytest.raises(OperationInvalid):
        OperationTemplate.from_after(after)


@pytest.mark.parametrize(
    "maximum,size,cut",
    [(None, 5 * 1024 * 1024, False), (32 * 1024 * 1024, DEFAULT + 1, False), (1024, 1025, True)],
)
async def test_configured_operation_limit_controls_actual_upstream_bytes(
    upstream, maximum, size, cut
):
    raw = b'{"data":"' + b"." * size + b'"}'

    @upstream.app.post("/response-limit/{charge}")
    async def response(charge: str):
        return Response(raw, media_type="application/json")

    definition = {"projection": None, "content_types": ["application/json"]}
    if maximum is not None:
        definition["max_bytes"] = maximum
    operation = _template(
        upstream,
        url={"host": NAME, "port": upstream.port, "path": "/response-limit/{charge}"},
        response=definition,
    )
    request = render_operation(
        operation,
        {"charge": "ch_proof", "amount_minor_units": 1, "currency": "EUR"},
        headers=[],
        idempotency_key="secrets-response-limit-real",
    )
    result = (await _send(upstream, request)).result
    assert result.truncated is cut
    assert result.upstream_bytes == (maximum if cut else len(raw))
    assert result.body == (raw[:maximum] if cut else raw)
