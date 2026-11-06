"""Explicit once-only retry terms survive operation validation and real draft/confirm."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets import records
from aweb_secrets.change import ChangeRefused, validate_change
from aweb_secrets.operation import OperationInvalid, OperationTemplate
from tests.test_change_records import ITEMS, _change
from tests.test_change_set_records import confirmed, item
from tests.test_change_sets import (
    ALICE,
    SECRET,
    SECRET_ID,
    World,
    enrol_owner,
    sealed_value,
    secret_value,
)
from tests.test_change_sets import world as world
from tests.test_operation_record import REFUND

RETRY = {"delay_s": 2, "upstream_honours_idempotency_key": True}
LEGACY_DIGEST = "5f1a2ca725481743a766c2f371f88d96a9e9f8c97a542f3c82a73dfdb7e00e1c"


def operation(**changes: Any) -> dict[str, Any]:
    body = copy.deepcopy(REFUND)
    body.update(changes)
    return body


def test_omitted_retry_terms_preserve_the_legacy_template_and_digest() -> None:
    body = copy.deepcopy(REFUND)
    template = OperationTemplate.from_after(body)
    assert template.after == REFUND == body
    assert "outcome_unknown_retry" not in template.after
    assert template.digest == LEGACY_DIGEST


@pytest.mark.parametrize(
    "changes",
    [
        {"outcome_unknown_retry": None},
        {"outcome_unknown_retry": RETRY},
        {"outcome_unknown_retry": {**RETRY, "delay_s": 1}},
        {"outcome_unknown_retry": {**RETRY, "delay_s": 60}},
        {
            "side_effect": "none",
            "idempotency": None,
            "outcome_unknown_retry": {**RETRY, "upstream_honours_idempotency_key": False},
        },
    ],
)
def test_explicit_retry_terms_round_trip_and_are_digest_bound(changes) -> None:
    body = operation(**changes)
    original = copy.deepcopy(body)
    template = OperationTemplate.from_after(body)
    assert template.after == original == body
    assert template.digest != LEGACY_DIGEST


@pytest.mark.parametrize(
    "retry",
    [
        True,
        [],
        {},
        {"delay_s": 2},
        {"upstream_honours_idempotency_key": True},
        {**RETRY, "repeat_count": 2},
        {**RETRY, "delay_s": True},
        {**RETRY, "delay_s": 0},
        {**RETRY, "delay_s": 61},
        {**RETRY, "delay_s": 2.0},
        {**RETRY, "delay_s": "2"},
        {**RETRY, "upstream_honours_idempotency_key": 1},
        {**RETRY, "upstream_honours_idempotency_key": "true"},
        {**RETRY, "upstream_honours_idempotency_key": None},
    ],
)
def test_retry_terms_require_exact_keys_and_strict_bounded_types(retry) -> None:
    with pytest.raises(OperationInvalid):
        OperationTemplate.from_after(operation(outcome_unknown_retry=retry))


@pytest.mark.parametrize(
    "changes",
    [
        {"reconcile": "refund-status"},
        {"idempotency": None},
        {"side_effect": "none", "idempotency": None},
        {"outcome_unknown_retry": {**RETRY, "upstream_honours_idempotency_key": False}},
    ],
)
def test_retry_requires_no_lookup_and_a_declared_safe_repeat(changes) -> None:
    body = operation(outcome_unknown_retry=RETRY)
    body.update(changes)
    with pytest.raises(OperationInvalid):
        OperationTemplate.from_after(body)


@pytest.mark.parametrize("retry", [None, RETRY])
def test_change_accepts_the_optional_terms_without_normalizing_the_covered_after(retry) -> None:
    change = _change(ITEMS["operation"])
    after = change["changes"][0]["after"]
    # This existing operation is side_effect:none with no idempotency header.
    after["outcome_unknown_retry"] = (
        {**retry, "upstream_honours_idempotency_key": False} if retry else None
    )
    original = copy.deepcopy(change)
    validate_change(change)
    assert change == original


def test_change_still_refuses_unrecognized_or_invalid_operation_fields() -> None:
    for field, value in (("outcome_unknown_retry", {**RETRY, "delay_s": True}), ("retry", RETRY)):
        change = _change(ITEMS["operation"])
        change["changes"][0]["after"][field] = value
        with pytest.raises(ChangeRefused):
            validate_change(change)


@pytest.mark.parametrize("configured", [False, True])
async def test_real_draft_and_confirmation_store_exact_retry_terms_and_digest(
    world: World, configured: bool
) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    first = await sealed_value(world)
    after = operation(**({"outcome_unknown_retry": RETRY} if configured else {}))
    expected = OperationTemplate.from_after(after)
    await confirmed(
        world,
        [
            item("secret", "create", "payments-live", SECRET),
            secret_value(first.version),
            item("operation", "create", "refund", after),
        ],
        [first],
    )
    async with world.db.transaction() as tx:
        stored = await records.current_operation(tx, INSTALLATION_ID, SECRET_ID, "refund")
    assert stored is not None
    assert stored.after == after and stored.digest == expected.digest
    if not configured:
        assert stored.digest == LEGACY_DIGEST
        assert "outcome_unknown_retry" not in stored.after
