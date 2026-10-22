"""Every effect-shaping input is bound before an existing intent can dispatch."""

import copy
from datetime import timedelta
from uuid import uuid4

import pytest
from aweb_naapp.dispatch import Dispatches
from aweb_naapp.hooks.commitment import CommitmentContext

from aweb_secrets.admission import AdmissionRefused
from aweb_secrets.broker_input import BrokerInput
from aweb_secrets.use_context import UseCommitments, apply_use_context_migrations, store_use_context
from tests.test_admission import INSTALLATION, SECRET, TEAM, _admit
from tests.test_admission import db as db
from tests.test_admission import fence as fence
from tests.test_broker_fence import PARAMS, machine, setup


def named():
    return {
        "request_id": "same-request",
        "operation": "create-refund",
        "params": copy.deepcopy(PARAMS),
    }


def opened():
    return {
        "request_id": "same-request",
        "method": "POST",
        "url": "https://api.example/v1/refunds",
        "headers": ["Content-Type: application/json", "X-Request-Id: original"],
        "data": {"amount": 50},
        "reason": "requested refund",
    }


async def binding(db, fence):
    operation, _, _ = await setup(db, fence)
    body = named()
    body["operation"] = operation.operation_id
    original = BrokerInput.from_body(SECRET["ref"], body, operation_digest=operation.digest)
    admission = await _admit(db, fence, request=original.request)
    await apply_use_context_migrations(db)
    dispatch_id = uuid4()
    commitments = UseCommitments(
        CommitmentContext(
            "secrets", TEAM, INSTALLATION, admission.installation.generation, "request"
        ),
        "a" * 64,
        "b" * 64,
    )
    # Deferred FK lets the context precede S3's dispatch in the same tx.
    async with db.transaction() as tx:
        await store_use_context(
            tx, admission=admission, dispatch_id=dispatch_id, commitments=commitments
        )

        async def transition(tx, event):
            pass

        state = Dispatches(
            on_transition=transition,
            max_dispatch=timedelta(seconds=30),
            sweep_margin=timedelta(seconds=5),
        )
        await state.create(tx, dispatch_id=dispatch_id, subject="subject", action="refund")
    return original, admission, dispatch_id


async def test_a_matched_submission_binds_the_original_intent_and_dispatch(db, fence):
    original, admission, dispatch_id = await binding(db, fence)
    async with db.transaction() as tx:
        await original.check_binding(tx, admission=admission, dispatch_id=dispatch_id)
    exposed = original.request.params
    exposed["amount_minor_units"] = 1
    assert original.request.params["amount_minor_units"] == 50


@pytest.mark.parametrize(
    "field",
    ["secret", "request_id", "operation", "operation_digest", "params", "headers", "reason"],
)
async def test_a_changed_named_submission_cannot_supply_inputs_for_the_existing_intent(
    db, fence, field
):
    original, admission, dispatch_id = await binding(db, fence)
    body = named()
    body["operation"] = original.request.operation_id
    digest, ref = original.operation_digest, SECRET["ref"]
    if field == "secret":
        ref = "another-secret"
    elif field == "operation_digest":
        digest = "c" * 64
    elif field == "params":
        body["params"]["amount_minor_units"] += 1
    elif field == "headers":
        body["headers"] = ["X-Request-Id: substituted"]
    else:
        body[field] = "changed"
    changed = BrokerInput.from_body(ref, body, operation_digest=digest)
    with pytest.raises(AdmissionRefused) as refused:
        async with db.transaction() as tx:
            await changed.check_binding(tx, admission=admission, dispatch_id=dispatch_id)
    assert refused.value.code == "idempotency_conflict"


async def test_an_unrelated_dispatch_cannot_borrow_an_intent(db, fence):
    original, admission, dispatch_id = await binding(db, fence)
    unrelated = uuid4()
    await machine(db, unrelated)
    with pytest.raises(AdmissionRefused) as refused:
        async with db.transaction() as tx:
            await original.check_binding(tx, admission=admission, dispatch_id=unrelated)
    assert refused.value.code == "grant_missing"


@pytest.mark.parametrize(
    "field",
    ["secret", "request_id", "method", "url", "header_name", "header_value", "data", "reason"],
)
def test_each_open_effect_input_changes_the_equality_commitment(field):
    body, ref = opened(), SECRET["ref"]
    original = BrokerInput.from_body(ref, body)
    if field == "secret":
        ref = "another-secret"
    elif field == "header_name":
        body["headers"][1] = "X-Correlation-Id: original"
    elif field == "header_value":
        body["headers"][1] = "X-Request-Id: substituted"
    elif field == "data":
        body["data"]["amount"] += 1
    else:
        body[field] = {"method": "PUT", "url": "https://api.example/v2/refunds"}.get(
            field, "changed"
        )
    assert (
        BrokerInput.from_body(ref, body).request.request_sha256 != original.request.request_sha256
    )


def test_open_call_and_header_names_are_built_from_the_same_detached_bytes():
    body = opened()
    submitted = BrokerInput.from_body(SECRET["ref"], body)
    body["headers"][1] = "X-Request-Id: changed"
    body["data"]["amount"] = 1
    call = submitted.open_call
    assert call.body == b'{"amount":50}'
    assert tuple(call.header_names) == tuple(name for name, _ in submitted.headers)
    assert submitted.headers[-1] == ("X-Request-Id", "original")


@pytest.mark.parametrize(
    "change",
    [
        {"request_id": False},
        {"request_id": ""},
        {"method": []},
        {"headers": ["bad"]},
        {"headers": ["X-Request-Id: injected\r\nAuthorization: injected"]},
        {"reason": []},
        {"tool": "contain"},
        {"data": {"bad": float("nan")}},
    ],
)
def test_malformed_inputs_refuse_with_a_value_free_code(change):
    with pytest.raises(AdmissionRefused) as refused:
        BrokerInput.from_body(SECRET["ref"], {**opened(), **change})
    assert str(refused.value) == "params_invalid"
