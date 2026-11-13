"""The owner's one page: what waits for them, what happened, which agents
were added without asking, the current bounds and who can approve."""

import pytest

from aweb.protected_signing.owner import owner_view
from tests.test_protected_admission_native import admissions as admissions  # noqa: F401
from tests.test_protected_admission_native import admit_operation, endorse, execute, prepare, root_operation

pytest_plugins = ("tests.test_independent_protected_signer",)


async def scope_of(component):
    async with component.db.transaction() as tx:
        return (await component.authority.binding(tx))["b3_scope"]


@pytest.mark.asyncio
async def test_the_owner_sees_waiting_requests_then_their_history(admissions):
    a = admissions
    operation = root_operation(a)
    frozen = (await prepare(a, operation)).json()
    view = await owner_view(a.group, scope=await scope_of(a.human))
    assert [p["operation_id"] for p in view["pending"]] == [operation.operation_id]
    waiting = view["pending"][0]
    assert waiting["handoff_id"] == frozen["handoff_id"] and waiting["operation"] == "identity.root.endorse"
    assert waiting["requester"] == a.w.root_id and waiting["digest"] == frozen["digest"]
    assert view["history"] == []
    await endorse_existing(a, operation)
    view = await owner_view(a.group, scope=await scope_of(a.human))
    assert view["pending"] == []
    assert [(h["operation_id"], h["state"]) for h in view["history"]] == [(operation.operation_id, "committed")]


async def endorse_existing(a, operation):
    options = await a.human.signer.approval_options(operation.operation_id, human=a.actor)
    result = await a.human.signer.execute(operation.operation_id, a.device.get(dict(options)), human=a.actor)
    assert result.state == "committed"


@pytest.mark.asyncio
async def test_the_team_owner_sees_admitted_agents_counts_bounds_and_approvers(admissions):
    a = admissions
    await endorse(a)
    added = admit_operation(a)
    assert (await prepare(a, added)).status_code == 200
    assert (await execute(a, added)).json()["state"] == "committed"
    view = await owner_view(a.group, scope=await scope_of(a.w.app))
    assert view["authority"]["kind"] == "team_controller"
    [agent] = view["admitted"]
    assert agent["root_id"] == a.w.root_id and agent["alias"] == added.intent()["subject"]["member_alias"]
    assert agent["state"] == "active" and agent["child_key"] == added.intent()["subject"]["child_key"]
    [root] = view["roots"]
    assert (root["root_id"], root["active"], root["in_window"]) == (a.w.root_id, 1, 1)
    assert view["policy"] == a.policy
    [approver] = view["approvers"]
    assert approver["contact"] and approver["passkeys"] and all(set(p) == {"key_id", "added_at"} for p in approver["passkeys"])


@pytest.mark.asyncio
async def test_a_scope_this_host_does_not_hold_shows_nothing(admissions):
    from aweb_naapp.runtime.protected_signer import SignerRefused

    with pytest.raises(SignerRefused, match="scope_refused"):
        await owner_view(admissions.group, scope="protected-not-ours")
