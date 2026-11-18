"""11.10: the production approval includes the agent's actual header values."""

import copy
import json

import pytest

from aweb_secrets.operation import OperationTemplate
from tests.test_operation_record import REFUND
from tests.test_production_bootstrap import approval_request
from tests.test_production_bootstrap import root as root

AGENT_HEADERS = (("X-Project", "project-A"), ("X-Account", "account-A"))


async def header_request(root, named):
    operation = None
    if named:
        after = copy.deepcopy(REFUND)
        after["headers"]["allowed"] = ["x-account", "x-project"]
        operation = OperationTemplate.from_after(after)
    return await approval_request(
        root,
        "use",
        agent_headers=AGENT_HEADERS,
        operation=operation,
        params={"charge": "ch_test", "amount_minor_units": 100, "currency": "EUR"},
    )


@pytest.mark.parametrize("named", [False, True], ids=["open", "named-operation"])
async def test_the_production_approver_view_discloses_each_agent_header_name_and_value(root, named):
    pending = await header_request(root, named)
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
    key = "operation" if named else "open_request"
    assert viewed.json()["view"][key]["headers"] == expected
    decision = {"token": pending.token, "decision": "approve"}
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
    assert await db.fetch_value("SELECT state FROM dispatches") == "awaiting_approval"
    assert await db.fetch_value("SELECT consumed_operation_id FROM approvals") is None
