"""11.10: the production approval includes the agent's actual header values."""

import copy
import json
import secrets
from enum import StrEnum
from uuid import uuid4

import pytest
from aweb_naapp.runtime.approvals import ApprovalState, Decision

from aweb_secrets.operation import OperationTemplate
from tests.production_approvals import requester_receipt, stored_approval
from tests.test_operation_record import REFUND
from tests.test_production_bootstrap import ApprovalAction, approval_request
from tests.test_production_bootstrap import root as root

AGENT_HEADERS = (("X-Project", "project-A"), ("X-Account", "account-A"))


class RequestKind(StrEnum):
    OPEN = "open"
    NAMED_OPERATION = "named-operation"


async def header_request(root, *, request_kind: RequestKind):
    operation = None
    if request_kind is RequestKind.NAMED_OPERATION:
        after = copy.deepcopy(REFUND)
        after["headers"]["allowed"] = ["x-account", "x-project"]
        operation = OperationTemplate.from_after(after)
    return await approval_request(
        root,
        kind=ApprovalAction.USE,
        agent_headers=AGENT_HEADERS,
        operation=operation,
        params={"charge": "ch_test", "amount_minor_units": 100, "currency": "EUR"},
    )


@pytest.mark.parametrize("request_kind", list(RequestKind), ids=lambda kind: kind.value)
async def test_the_production_approver_view_discloses_each_agent_header_name_and_value(
    root, request_kind
):
    pending = await header_request(root, request_kind=request_kind)
    service, client, configured, *_ = root
    db = service.runtime.db()
    frozen = json.loads(await db.fetch_value("SELECT request FROM use_approvals"))
    expected = [{"name": name.lower(), "value": value} for name, value in AGENT_HEADERS]
    assert frozen["broker"].get("headers") == expected, (
        "the frozen approval hides agent header values"
    )
    assert frozen["v"] == 2
    human = configured.console_origin
    # Sign in through the approval locator as an ordinary page visitor does;
    # the personal locator itself grants no VIEW or APPROVE authority.
    hint = await client.post(human + "/use-approvals/sign-in", json={"token": pending.token})
    assert hint.status_code == 200
    scope = hint.json()["scope"]
    login = await client.post(human + "/login/options", json={"scope": scope})
    logged = await client.post(
        human + "/login", json={"scope": scope, "assertion": pending.device.get(login.json())}
    )
    assert logged.status_code == 200
    csrf = {"X-CSRF-Token": logged.json()["csrf_token"]}
    options = await client.post(
        human + "/use-approvals/view-options", json={"token": pending.token}, headers=csrf
    )
    viewed = await client.post(
        human + "/use-approvals/view",
        json={"token": pending.token, "assertion": pending.device.get(options.json())},
        headers=csrf,
    )
    assert viewed.status_code == 200
    key = "operation" if request_kind is RequestKind.NAMED_OPERATION else "open_request"
    assert viewed.json()["view"][key]["headers"] == expected
    decision = {"token": pending.token, "decision": Decision.APPROVE.value}
    options = await client.post(
        human + "/use-approvals/decision-options", json=decision, headers=csrf
    )
    approved = await client.post(
        human + "/use-approvals/decide",
        json={**decision, "assertion": pending.device.get(options.json())},
        headers=csrf,
    )
    assert approved.status_code == 200
    # An approved request cannot be resubmitted with a different account value.
    changed = json.loads(pending.raw)
    changed["headers"][1] = "X-Account: account-B"
    raw = json.dumps(changed).encode()
    member = root[3]
    rejected = await client.post(
        configured.public_origin + pending.path,
        content=raw,
        headers={
            **member.headers(
                aud=configured.public_origin, method="POST", path=pending.path, body=raw
            ),
            "Content-Type": "application/json",
        },
    )
    assert rejected.status_code == 409
    assert await requester_receipt(root, pending=pending) == {
        "state": ApprovalState.APPROVED.value,
        "request_id": pending.reply["request_id"],
        "request_ref": pending.reply["request_ref"],
        "next": "resubmit",
    }
    assert (await stored_approval(root, pending=pending)).consumed_operation_id is None


@pytest.mark.parametrize("request_kind", list(RequestKind), ids=lambda kind: kind.value)
async def test_credential_shaped_agent_headers_are_refused_before_freezing(root, request_kind):
    pending = await header_request(root, request_kind=request_kind)
    service, client, configured, member, *_ = root
    body = json.loads(pending.raw)
    body["request_id"] = uuid4().hex
    body["headers"][1] = "X-Account: Bearer " + secrets.token_urlsafe(32)
    raw = json.dumps(body).encode()
    response = await client.post(
        configured.public_origin + pending.path,
        content=raw,
        headers={
            **member.headers(
                aud=configured.public_origin, method="POST", path=pending.path, body=raw
            ),
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 403
    assert response.json()["code"] == "header_not_allowed"
    db = service.runtime.db()
    assert await db.fetch_value("SELECT count(*) FROM use_approvals") == 1
    assert await requester_receipt(root, pending=pending) == pending.reply
    assert (await stored_approval(root, pending=pending)).consumed_operation_id is None
    status_path = "/v1/status/" + body["request_id"]
    absent = await client.get(
        configured.public_origin + status_path,
        headers=member.headers(aud=configured.public_origin, method="GET", path=status_path),
    )
    assert absent.status_code == 404
