"""Status retrieves persisted broker outcomes without acquiring send authority."""

import json
import secrets
from dataclasses import replace

import pytest
from aweb_naapp.roles import assign, principal_key, unassign
from aweb_naapp.runtime.authorization import Authorization, DeclaredTool

from aweb_secrets import records
from aweb_secrets.broker_audit import BrokerAudit
from aweb_secrets.member_types import broker_result_reply
from aweb_secrets.redaction import KnownValues
from aweb_secrets.responses import handle_response
from aweb_secrets.status_service import UseStatus
from aweb_secrets.use_approvals import apply_use_approval_migrations
from tests.test_admission import ALICE, BOB, _grant_source_grant
from tests.test_broker_audit import INSTALLATION, machine, prepared, source, view
from tests.test_broker_audit import db as db
from tests.test_broker_audit import fence as fence

STATUS = DeclaredTool(
    "status", "GET", "/v1/status/{ref}", frozenset({"secrets:read"}), frozenset({"agent"})
)


@pytest.fixture(autouse=True)
async def associations(db):  # noqa: F811
    await apply_use_approval_migrations(db)


def authorization(principal=ALICE):
    return Authorization(
        principal=principal,
        tool=STATUS,
        grant=_grant_source_grant(installation_id=INSTALLATION),
    )


async def snapshot(db):  # noqa: F811
    return {
        table: [dict(row) for row in await db.fetch_all("SELECT * FROM {{tables." + table + "}}")]
        for table in (
            "intents",
            "dispatches",
            "idempotency_keys",
            "rate_buckets",
            "outbox_events",
            "broker_use_events",
        )
    }


async def test_request_id_and_opaque_locator_return_same_progress_without_any_writes(db, fence):  # noqa: F811
    _, admission, _, _ = await prepared(db, fence)
    service = UseStatus(db, fence=fence)
    before = await snapshot(db)
    expected = {
        "state": "received",
        "request_id": "broker-request",
        "request_ref": admission.intent_id,
    }
    for ref in ("broker-request", admission.intent_id):
        reply = await service.get(ref=ref, authorization=authorization())
        assert reply.status == 200 and reply.body == expected
    assert await snapshot(db) == before


async def test_unknown_other_principal_and_other_team_are_indistinguishable(db, fence):  # noqa: F811
    _, admission, _, _ = await prepared(db, fence)
    service = UseStatus(db, fence=fence)
    for ref, caller in (
        ("absent", ALICE),
        ("broker-request", BOB),
        (admission.intent_id, BOB),
        (admission.intent_id, replace(ALICE, team_id="backend:other.example")),
    ):
        reply = await service.get(ref=ref, authorization=authorization(caller))
        assert reply.status == 404
        assert reply.body == {"state": "refused", "request_id": None, "code": "not_found"}


async def test_renewed_certificate_keeps_read_access_but_does_not_rewrite_original_provenance(
    db, fence
):  # noqa: F811
    _, admission, _, _ = await prepared(db, fence)
    before = await snapshot(db)
    reply = await UseStatus(db, fence=fence).get(
        ref=admission.intent_id,
        authorization=authorization(replace(ALICE, certificate_id="cert-renewed")),
    )
    assert reply.status == 200
    assert await snapshot(db) == before


async def test_current_grant_and_owner_role_are_required_for_retrieval(db, fence):  # noqa: F811
    _, admission, _, _ = await prepared(db, fence)
    service = UseStatus(db, fence=fence)
    async with db.transaction() as tx:
        await records.revoke_grant(tx, INSTALLATION, admission.grant_id)
    assert (await service.get(ref=admission.intent_id, authorization=authorization())).status == 404
    async with db.transaction() as tx:
        await assign(tx, principal_key(BOB), "secrets.owner")
    owner = await service.get(ref=admission.intent_id, authorization=authorization(BOB))
    assert owner.status == 200 and owner.body["request_id"] == "broker-request"
    # Caller-chosen request IDs never become an owner's cross-principal lookup.
    assert (await service.get(ref="broker-request", authorization=authorization(BOB))).status == 404
    async with db.transaction() as tx:
        await unassign(tx, principal_key(BOB), "secrets.owner")
    assert (
        await service.get(ref=admission.intent_id, authorization=authorization(BOB))
    ).status == 404


async def test_status_never_returns_a_result_from_an_older_installation_generation(db, fence):  # noqa: F811
    _, admission, _, _ = await prepared(db, fence)
    await db.execute("UPDATE {{tables.installation_fences}} SET generation=generation+1")
    reply = await UseStatus(db, fence=fence).get(
        ref=admission.intent_id, authorization=authorization()
    )
    assert reply.status != 200
    assert "result" not in reply.body


async def test_same_installation_new_generation_refuses_original_receipt(db, fence):  # noqa: F811
    _, admission, _, _ = await prepared(db, fence)
    renewed = authorization()
    renewed = replace(
        renewed, grant=replace(renewed.grant, generation=renewed.grant.generation + 1)
    )
    await db.execute("UPDATE {{tables.installation_fences}} SET generation=generation+1")
    reply = await UseStatus(db, fence=fence).get(ref=admission.intent_id, authorization=renewed)
    assert reply.status == 409 and reply.body["code"] == "generation_superseded"
    assert "result" not in reply.body


async def test_refusal_status_uses_the_fixed_transactional_audit_code(db, fence):  # noqa: F811
    _, admission, dispatch_id, _ = await prepared(db, fence)
    state = machine(BrokerAudit(producer=source, view=view(), refusal_code="grant_revoked"))
    async with db.transaction() as tx:
        await state.refuse(tx, dispatch_id)
    before = await snapshot(db)
    reply = await UseStatus(db, fence=fence).get(
        ref=admission.intent_id, authorization=authorization()
    )
    assert reply.status == 200
    assert reply.body == {
        "state": "refused",
        "request_id": "broker-request",
        "request_ref": admission.intent_id,
        "code": "grant_revoked",
    }
    assert await snapshot(db) == before


@pytest.mark.parametrize(
    "state", ["not_sent", "outcome_unknown", "admitted", "dispatching", "cancelled"]
)
async def test_reading_progress_and_no_send_outcomes_never_rearms_dispatch(db, fence, state):  # noqa: F811
    _, admission, dispatch_id, _ = await prepared(db, fence)
    await db.execute(
        "UPDATE {{tables.dispatches}} SET state=$2 WHERE dispatch_id=$1", dispatch_id, state
    )
    before = await snapshot(db)
    reply = await UseStatus(db, fence=fence).get(
        ref=admission.intent_id, authorization=authorization()
    )
    assert reply.status == 200 and reply.body["state"] == state
    assert reply.body.get("next") == ("resubmit" if state == "not_sent" else None)
    assert await snapshot(db) == before


@pytest.mark.parametrize("body", [b"", "caf\u00e9".encode(), b"\xff\x80\x00"])
def test_broker_reply_round_trips_exact_sanitized_entity_and_never_exposes_audit_fields(body):
    import base64

    result = handle_response(
        status=503,
        headers=[("Content-Type", "application/octet-stream"), ("Set-Cookie", "private")],
        body=body,
        truncated=False,
        max_bytes=4096,
        projection=None,
        known=KnownValues(),
        token_issuing=False,
    )
    reply = broker_result_reply(result, request_id="original", request_ref="int_original")
    assert reply.status == 200 and reply.body["state"] == "completed"
    projected = reply.body["result"]
    recovered = (
        projected["body"].encode()
        if projected["body_encoding"] == "utf8"
        else base64.b64decode(projected["body"], validate=True)
    )
    assert recovered == result.body
    assert projected["headers"] == [["Content-Type", "application/octet-stream"]]
    assert set(projected) == {
        "status",
        "headers",
        "body",
        "body_encoding",
        "truncated",
        "upstream_bytes",
        "redaction_count",
    }


def test_withheld_reply_keeps_safe_counts_and_status_without_an_encoded_body():
    issued = secrets.token_urlsafe(32)
    result = handle_response(
        status=201,
        headers=[],
        body=json.dumps({"access_token": issued}).encode(),
        truncated=False,
        max_bytes=4096,
        projection=None,
        known=KnownValues(),
        token_issuing=False,
    )
    reply = broker_result_reply(result, request_id="original", request_ref="int_original")
    assert reply.body["state"] == "result_withheld"
    assert reply.body["code"] == "credential_shaped"
    assert reply.body["result"]["body"] is None
    assert "body_encoding" not in reply.body["result"]
    assert reply.body["result"]["status"] == 201
    if issued in json.dumps(reply.body):
        raise AssertionError("withheld entity appeared in tool reply")


async def test_terminal_status_returns_only_the_stored_sanitized_envelope(db, fence):  # noqa: F811
    _, admission, dispatch_id, _ = await prepared(db, fence)
    sanitized = {
        "state": "completed",
        "request_id": "broker-request",
        "request_ref": admission.intent_id,
        "result": {
            "status": 200,
            "headers": [],
            "body": "safe",
            "body_encoding": "utf8",
            "truncated": False,
            "upstream_bytes": 4,
            "redaction_count": 0,
        },
    }
    await db.execute(
        "UPDATE {{tables.dispatches}} SET state='completed', result=$2::jsonb WHERE dispatch_id=$1",
        dispatch_id,
        json.dumps({**sanitized, "upstream_response_hmac": "restricted"}),
    )
    before = await snapshot(db)
    reply = await UseStatus(db, fence=fence).get(
        ref=admission.intent_id, authorization=authorization()
    )
    assert reply.status == 200 and reply.body == sanitized
    assert await snapshot(db) == before


async def test_stored_result_identity_cannot_override_the_current_scoped_receipt(db, fence):  # noqa: F811
    _, admission, dispatch_id, _ = await prepared(db, fence)
    await db.execute(
        "UPDATE {{tables.dispatches}} SET state='completed', result=$2::jsonb WHERE dispatch_id=$1",
        dispatch_id,
        json.dumps(
            {
                "state": "completed",
                "request_id": "other",
                "request_ref": "int_other",
                "result": {"body": "must-not-return"},
            }
        ),
    )
    reply = await UseStatus(db, fence=fence).get(
        ref=admission.intent_id, authorization=authorization()
    )
    assert reply.status == 503 and "must-not-return" not in json.dumps(reply.body)


async def test_owner_inspection_does_not_disclose_another_members_projected_entity(db, fence):  # noqa: F811
    _, admission, dispatch_id, _ = await prepared(db, fence)
    sanitized = {
        "state": "result_withheld",
        "request_id": "broker-request",
        "request_ref": admission.intent_id,
        "code": "credential_shaped",
        "result": {"status": 201, "body": None, "upstream_bytes": 40},
    }
    await db.execute(
        "UPDATE {{tables.dispatches}} SET state='completed', result=$2::jsonb WHERE dispatch_id=$1",
        dispatch_id,
        json.dumps(sanitized),
    )
    async with db.transaction() as tx:
        await assign(tx, principal_key(BOB), "secrets.owner")
    service = UseStatus(db, fence=fence)
    for state in ("result_withheld", "completed"):
        if state == "completed":
            sanitized = {**sanitized, "state": state, "result": {"body": "requester-only-entity"}}
            sanitized.pop("code")
            await db.execute(
                "UPDATE {{tables.dispatches}} SET result=$2::jsonb WHERE dispatch_id=$1",
                dispatch_id,
                json.dumps(sanitized),
            )
        own = await service.get(ref=admission.intent_id, authorization=authorization())
        assert own.body == sanitized
        inspection = await service.get(ref=admission.intent_id, authorization=authorization(BOB))
        assert inspection.status == 200 and inspection.body["state"] == state
        assert "result" not in inspection.body
        assert inspection.body.get("code") == sanitized.get("code")
