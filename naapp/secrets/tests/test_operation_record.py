"""The operation template v1 (§8.1): a bounded, digest-addressed use of a secret."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from aweb_secrets.operation import OperationInvalid, OperationTemplate

REFUND: dict[str, Any] = {
    "v": 1,
    "operation_id": "refund",
    "secret_id": "sec_19ab42",
    "method": "POST",
    "url": {"host": "api.payments.example", "port": 443, "path": "/v1/charges/{charge}/refunds"},
    "params": {
        "charge": {
            "schema": {"type": "string", "minLength": 3, "maxLength": 64},
            "charset": "base64url",
            "placement": "path",
        },
        "amount_minor_units": {
            "schema": {"type": "integer", "minimum": 1, "maximum": 5000},
            "charset": None,
            "placement": "body",
        },
        "currency": {
            "schema": {"type": "string", "enum": ["EUR", "USD"]},
            "charset": None,
            "placement": "body",
        },
    },
    "body": {
        "template": {
            "amount": {"$param": "amount_minor_units"},
            "currency": {"$param": "currency"},
            "reason": "requested_by_customer",
        }
    },
    "headers": {"fixed": {"Stripe-Version": "2024-06-20"}, "allowed": ["x-request-id"]},
    "response": {
        "projection": ["/id", "/status", "/amount"],
        "max_bytes": 65536,
        "content_types": ["application/json"],
    },
    "side_effect": "irreversible",
    "token_issuing": False,
    "result_handling": "deny",
    "store_as_secret": None,
    "idempotency": {"header": "Idempotency-Key"},
    "reconcile": None,
    "timeout_s": 20,
}


def _op(**changes: Any) -> dict[str, Any]:
    op = copy.deepcopy(REFUND)
    op.update(changes)
    return op


def _with(path: list[str], value: Any) -> dict[str, Any]:
    op = copy.deepcopy(REFUND)
    target = op
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return op


def test_the_template_round_trips_as_its_after() -> None:
    assert OperationTemplate.from_after(REFUND).after == REFUND


def test_an_operation_is_addressed_by_the_digest_of_its_template() -> None:
    template = OperationTemplate.from_after(REFUND)
    assert len(template.digest) == 64
    reordered = dict(reversed(list(copy.deepcopy(REFUND).items())))
    assert OperationTemplate.from_after(reordered).digest == template.digest


@pytest.mark.parametrize(
    "edited",
    [
        _op(timeout_s=10),
        _with(["params", "amount_minor_units", "schema", "maximum"], 10000),
        _with(["response", "projection"], ["/id"]),
        _op(secret_id="sec_other01"),
    ],
)
def test_an_edited_operation_has_a_new_digest(edited) -> None:
    assert (
        OperationTemplate.from_after(edited).digest != OperationTemplate.from_after(REFUND).digest
    )


def test_a_read_without_a_body_is_an_operation() -> None:
    status = _op(
        operation_id="charge-status",
        method="GET",
        url={"host": "api.payments.example", "port": 443, "path": "/v1/charges/{charge}"},
        params={k: v for k, v in REFUND["params"].items() if k == "charge"},
        body=None,
        headers={"fixed": {}, "allowed": []},
        side_effect="none",
        idempotency=None,
    )
    assert OperationTemplate.from_after(status).after == status


@pytest.mark.parametrize(
    "broken",
    [
        _op(v=2),
        _op(operation_id="Refund Now"),
        _op(secret_id="19ab42"),
        _op(method="CONNECT"),
        _with(["url", "host"], "API.payments.example"),
        _with(["url", "host"], "*.payments.example"),
        _with(["url", "host"], "10.0.0.1"),
        _with(["url", "path"], "/v1/charges/**"),
        _with(["url", "path"], "/v1/../charges/{charge}/refunds"),
        _with(["url", "port"], 0),
        # A path parameter without its slot, and a slot without its parameter.
        _with(["url", "path"], "/v1/refunds"),
        _with(["url", "path"], "/v1/charges/{charge}/refunds/{refund}"),
        _with(["params", "charge", "placement"], "header"),
        _with(["params", "charge", "schema"], {"type": "string", "pattern": "^ch_"}),
        _with(["params", "charge", "schema"], {"type": "array", "items": {"type": "string"}}),
        _with(["params", "charge", "charset"], "anything"),
        _with(["params", "amount_minor_units", "charset"], "digits"),
        _with(
            ["params", "Amount"],
            {"schema": {"type": "integer"}, "charset": None, "placement": "query"},
        ),
        _with(["params", "charge", "schema"], {"type": "object", "maxProperties": 1}),
        # The body's slots must be exactly its body parameters.
        _with(["body", "template", "currency"], "EUR"),
        _with(["body", "template", "extra"], {"$param": "charge"}),
        _with(["body", "template", "amount"], 12.5),
        _op(body=None),
        _op(method="GET"),
        _with(["headers", "fixed"], {"Authorization": "Bearer x"}),
        _with(["headers", "fixed"], {"Host": "evil.example"}),
        _with(["headers", "fixed"], {"Stripe-Version": "a\nb"}),
        _with(["headers", "allowed"], ["cookie"]),
        _with(["headers", "allowed"], ["x-forwarded-for"]),
        _with(["headers", "allowed"], ["Idempotency-Key"]),
        _with(["headers", "allowed"], ["x-request-id", "idempotency-key"]),
        _with(["response", "projection"], ["id"]),
        _with(["response", "projection"], []),
        _with(["response", "max_bytes"], 0),
        _with(["response", "content_types"], []),
        _with(["response", "content_types"], ["JSON"]),
        _op(side_effect="maybe"),
        _op(result_handling="withhold"),
        _op(result_handling="return", token_issuing=True),
        _op(idempotency={"header": "Idempotency Key"}),
        _op(reconcile="Status Lookup"),
        _op(reconcile="refund"),
        _op(timeout_s=31),
        _op(timeout_s=0),
        _op(surprise=1),
    ],
)
def test_a_malformed_template_is_refused(broken) -> None:
    with pytest.raises(OperationInvalid):
        OperationTemplate.from_after(broken)


@pytest.mark.parametrize("missing", sorted(REFUND))
def test_every_field_is_required(missing) -> None:
    op = copy.deepcopy(REFUND)
    del op[missing]
    with pytest.raises(OperationInvalid):
        OperationTemplate.from_after(op)


@pytest.mark.parametrize(
    "headers",
    [
        {"fixed": {"Idempotency-Key": "fixed-key"}, "allowed": []},
        {"fixed": {"idempotency-key": "fixed-key"}, "allowed": []},
        {"fixed": {}, "allowed": ["idempotency-key"]},
    ],
)
def test_the_idempotency_header_is_never_also_a_fixed_or_agent_header(headers) -> None:
    with pytest.raises(OperationInvalid):
        OperationTemplate.from_after(_op(headers=headers))


def test_a_token_issuing_operation_may_withhold_its_result() -> None:
    issuing = _op(token_issuing=True, result_handling="withhold")
    assert OperationTemplate.from_after(issuing).token_issuing


STORE_AS_SECRET = {
    "derived_kind": "aws-sigv4",
    "capture": {
        "access_key_id": "/Credentials/AccessKeyId",
        "secret_access_key": "/Credentials/SecretAccessKey",
        "session_token": "/Credentials/SessionToken",
    },
    "expires_at": "/Credentials/Expiration",
    "grant_template": "gtp_sts-derived",
}


def test_store_as_secret_is_refused_until_derived_secrets_exist() -> None:
    with pytest.raises(OperationInvalid) as refused:
        OperationTemplate.from_after(
            _op(
                token_issuing=True,
                result_handling="store_as_secret",
                store_as_secret=STORE_AS_SECRET,
            )
        )
    assert refused.value.code == "store_as_secret_unavailable"


@pytest.mark.parametrize(
    "store",
    [
        {**STORE_AS_SECRET, "derived_kind": "api_key"},
        {**STORE_AS_SECRET, "capture": {"password": "/Credentials/AccessKeyId"}},
        {**STORE_AS_SECRET, "expires_at": "Credentials/Expiration"},
        {**STORE_AS_SECRET, "grant_template": "sts-derived"},
    ],
)
def test_a_malformed_store_as_secret_is_refused_for_its_shape(store) -> None:
    with pytest.raises(OperationInvalid) as refused:
        OperationTemplate.from_after(
            _op(token_issuing=True, result_handling="store_as_secret", store_as_secret=store)
        )
    assert refused.value.code == "operation_invalid"


def test_store_as_secret_is_set_only_with_its_result_handling() -> None:
    with pytest.raises(OperationInvalid):
        OperationTemplate.from_after(_op(store_as_secret=STORE_AS_SECRET))


@pytest.mark.parametrize(
    ("charset", "value", "valid"),
    [
        ("base64url", "ch_3Pq-x", True),
        ("base64url", "ch/3Pq", False),
        ("digits", "0042", True),
        ("digits", "42a", False),
        ("hex", "0af3", True),
        ("hex", "0AF3", False),
        ("alnum", "Ab9", True),
        ("alnum", "a-b", False),
        ("slug", "ab-c_d", True),
        ("slug", "-ab", False),
    ],
)
def test_parameters_fill_only_their_typed_slots(charset, value, valid) -> None:
    template = OperationTemplate.from_after(_with(["params", "charge", "charset"], charset))
    params = {"charge": value, "amount_minor_units": 1250, "currency": "EUR"}
    assert template.params_valid(params) is valid


@pytest.mark.parametrize(
    "params",
    [
        {"charge": "ch_3Pq", "amount_minor_units": 1250},
        {"charge": "ch_3Pq", "amount_minor_units": 1250, "currency": "EUR", "extra": 1},
        {"charge": "ch_3Pq", "amount_minor_units": 50000, "currency": "EUR"},
        {"charge": "ch_3Pq", "amount_minor_units": "1250", "currency": "EUR"},
        {"charge": "ch_3Pq", "amount_minor_units": True, "currency": "EUR"},
        {"charge": "ch", "amount_minor_units": 1250, "currency": "EUR"},
    ],
)
def test_parameters_outside_the_schema_are_invalid(params) -> None:
    assert not OperationTemplate.from_after(REFUND).params_valid(params)
