"""A named operation rendered into the one request it allows (§8.1).

Parameters fill only their typed slots: a path segment, a query value, a body
slot. The method, host, port, the rest of the path, the fixed headers and the
body around the slots are the template's.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from aweb_naapp.egress import EgressRefused, canonical_url, match_destination
from aweb_naapp.egress.addresses import InternalDestinations
from aweb_naapp.egress.send import MAX_RESPONSE_BYTES

from aweb_secrets.operation import OperationTemplate
from aweb_secrets.operation_request import render_operation

from .test_operation_record import REFUND

PARAMS = {"charge": "ch_3Pq9", "amount_minor_units": 500, "currency": "EUR"}
KEY = "secrets-d1"


def _render(template: OperationTemplate, params: Any, *, headers=(), idempotency_key: str | None = KEY):
    """Render as the dispatcher does, with its upstream idempotency key."""
    return render_operation(template, params, headers=list(headers), idempotency_key=idempotency_key)


def _template(**changes: Any) -> OperationTemplate:
    after = copy.deepcopy(REFUND)
    after.update(changes)
    return OperationTemplate.from_after(after)


def test_the_operation_renders_its_one_request() -> None:
    request = _render(_template(), PARAMS, headers=[])
    assert request.method == "POST"
    assert request.url == "https://api.payments.example/v1/charges/ch_3Pq9/refunds"
    assert json.loads(request.body) == {
        "amount": 500,
        "currency": "EUR",
        "reason": "requested_by_customer",
    }
    assert ("Content-Type", "application/json") in request.headers
    assert ("Stripe-Version", "2024-06-20") in request.headers
    assert request.projection == ["/id", "/status", "/amount"]
    assert request.max_bytes == 65536
    assert request.content_types == ["application/json"]
    assert request.token_issuing is False
    assert request.bounds.total_timeout == 20
    assert request.bounds.max_response_bytes == 65536


def test_the_request_matches_the_destination_it_carries() -> None:
    request = _render(_template(), PARAMS, headers=[])
    match_destination(
        request.destination,
        request.method,
        canonical_url(request.url),
        internal_destinations=InternalDestinations.DISABLED,
    )
    assert request.destination.header_allow == frozenset({"stripe-version", "idempotency-key"})


def test_the_template_response_bound_applies_above_the_egress_default() -> None:
    template = _template(
        response={"projection": None, "max_bytes": 16 * 1024 * 1024, "content_types": ["application/json"]}
    )
    request = _render(template, PARAMS, headers=[])
    assert request.bounds.max_response_bytes == MAX_RESPONSE_BYTES == 16 * 1024 * 1024
    assert request.max_bytes == MAX_RESPONSE_BYTES


@pytest.mark.parametrize(
    "params",
    [
        {**PARAMS, "amount_minor_units": 5001},
        {**PARAMS, "currency": "GBP"},
        {**PARAMS, "charge": "ch/../x"},
        {k: v for k, v in PARAMS.items() if k != "currency"},
        {**PARAMS, "extra": "x"},
    ],
    ids=["over-ceiling", "outside-enum", "outside-charset", "missing", "undeclared"],
)
def test_parameters_outside_their_slots_are_refused(params: dict) -> None:
    with pytest.raises(EgressRefused) as refused:
        _render(_template(), params, headers=[])
    assert refused.value.code == "params_invalid"


def _free_path_param() -> OperationTemplate:
    after = copy.deepcopy(REFUND)
    after["params"]["charge"]["charset"] = None
    return OperationTemplate.from_after(after)


@pytest.mark.parametrize("value", ["a/b", "..", "a\\b", "%2F", "a?b", "a#b", "a b"])
def test_a_path_parameter_never_becomes_a_separator(value: str) -> None:
    try:
        request = _render(_free_path_param(), {**PARAMS, "charge": value}, headers=[])
    except EgressRefused as refused:
        assert refused.code in ("params_invalid", "destination_not_in_scope")
        return
    segments = canonical_url(request.url).path.split("/")
    assert segments[:3] == ["", "v1", "charges"] and segments[4:] == ["refunds"]
    assert len(segments) == 5


def test_a_query_parameter_is_one_encoded_value() -> None:
    after = copy.deepcopy(REFUND)
    after["params"]["currency"]["placement"] = "query"
    after["body"]["template"].pop("currency")
    template = OperationTemplate.from_after(after)
    request = _render(template, PARAMS, headers=[])
    assert request.url.endswith("/refunds?currency=EUR")


def test_a_query_value_cannot_add_a_parameter() -> None:
    after = copy.deepcopy(REFUND)
    after["params"]["note"] = {"schema": {"type": "string", "maxLength": 32}, "charset": None, "placement": "query"}
    template = OperationTemplate.from_after(after)
    request = _render(template, {**PARAMS, "note": "x&admin=1"}, headers=[])
    query = canonical_url(request.url).query
    assert [name for name, _ in query] == ["note"]


def _allowing(*names: str) -> OperationTemplate:
    after = copy.deepcopy(REFUND)
    after["headers"]["allowed"] = sorted(names)
    return OperationTemplate.from_after(after)


def test_an_allowed_agent_header_passes_and_others_are_refused() -> None:
    template = _allowing("idempotency-key", "x-request-id")
    request = _render(template, PARAMS, headers=[("X-Request-Id", "agent-1")])
    assert ("X-Request-Id", "agent-1") in request.headers
    for header in (("X-Other", "v"), ("Stripe-Version", "2099-01-01"), ("Content-Type", "text/plain")):
        with pytest.raises(EgressRefused) as refused:
            _render(template, PARAMS, headers=[header])
        assert refused.value.code == "header_not_allowed"


def test_the_declared_idempotency_header_is_never_the_agents() -> None:
    # The template lists it as allowed too; it is still the broker's.
    template = _allowing("idempotency-key", "x-request-id")
    with pytest.raises(EgressRefused) as refused:
        _render(template, PARAMS, headers=[("Idempotency-Key", "agent-chosen")])
    assert refused.value.code == "header_not_allowed"


def test_an_idempotent_operation_is_never_rendered_without_the_broker_key() -> None:
    with pytest.raises(ValueError):
        render_operation(_template(), PARAMS, headers=[], idempotency_key=None)


def test_an_operation_without_idempotency_lets_an_allowed_agent_header_through() -> None:
    after = copy.deepcopy(REFUND)
    after["idempotency"] = None
    template = OperationTemplate.from_after(after)
    request = render_operation(template, PARAMS, headers=[("Idempotency-Key", "agent-1")])
    assert ("Idempotency-Key", "agent-1") in request.headers


def test_the_broker_idempotency_key_takes_the_declared_header() -> None:
    request = render_operation(_template(), PARAMS, headers=[], idempotency_key="secrets-d1")
    assert ("Idempotency-Key", "secrets-d1") in request.headers
    with pytest.raises(EgressRefused):
        render_operation(
            _template(), PARAMS, headers=[("Idempotency-Key", "agent-1")], idempotency_key="secrets-d1"
        )


def test_an_operation_without_a_body_sends_none() -> None:
    after = copy.deepcopy(REFUND)
    after["method"] = "GET"
    after["url"]["path"] = "/v1/charges/{charge}"
    after["params"] = {"charge": REFUND["params"]["charge"]}
    after["body"] = None
    template = OperationTemplate.from_after(after)
    request = _render(template, {"charge": "ch_1"}, headers=[])
    assert request.body == b""
    assert all(name != "Content-Type" for name, _ in request.headers)
