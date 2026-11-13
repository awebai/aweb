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


def test_the_owner_page_reads_as_sentences_and_keeps_identifiers_in_details():
    from aweb.protected_signing.owner import owner_page_html

    view = {
        "authority": {"kind": "team_controller", "id": "engineering:customer.example", "domain": "customer.example",
            "human": "did:aw:HUMAN"},
        "pending": [{"operation_id": "op-1", "operation": "identity.root.endorse", "requester": "did:aw:ROOT",
            "digest": "ab" * 32, "handoff_id": "h-1", "expires_at": "2026-11-14T09:30:00Z"}],
        "history": [{"operation_id": "op-0", "operation": "human-role.revoke", "requester": "did:aw:ROOT",
            "digest": "cd" * 32, "state": "refused", "code": "human_refused", "at": "2026-11-13T10:00:00Z"}],
        "admitted": [{"root_id": "did:aw:ROOT", "alias": "build-<1>", "child_id": None, "child_key": "did:key:zK",
            "admitted_at": "2026-11-13T09:00:00Z", "state": "active"}],
        "roots": [{"root_id": "did:aw:ROOT", "active": 3, "in_window": 2, "next_at": "2026-11-13T10:00:00Z"}],
        "policy": {"version": 1, "digest": "sha256:" + "e" * 64, "teams": ["engineering:customer.example"],
            "root_selector": {"kind": "service_endorsed_root", "service_id": "s"}, "member_role": "member",
            "subject_kinds": ["local_agent", "registered_agent"],
            "bounds": {"max_active": 5, "rate_window_seconds": 3600, "max_per_window": 10}},
        "approvers": [{"contact": "owner@customer.example", "passkeys": [{"key_id": "0a1b2c3d", "added_at": "2026-11-12T08:00:00Z"}]}],
    }
    html = owner_page_html(view)
    for heading in ("Waiting for you", "Agents added without asking you", "Current limits", "History",
            "Who can approve"):
        assert f">{heading}</h2>" in html
    assert 'href="/handoff/h-1"' in html
    assert "3 of 5 at a time" in html and "2 of 10 in the last hour" in html
    assert "owner@customer.example" in html and "added 2026-11-12" in html
    assert "Denied" in html
    # Values are escaped, identifiers sit in Technical details, never in headings.
    assert "build-&lt;1&gt;" in html and "build-<1>" not in html
    head = html.split("<details", 1)[0]
    assert "did:aw:" not in head.split("Agents added without asking you")[0]
    empty = owner_page_html({**view, "pending": [], "history": [], "admitted": [], "roots": []})
    assert "Nothing is waiting for you." in empty and "No agents have been added yet." in empty
    assert "Nothing has happened yet." in empty


@pytest.mark.asyncio
async def test_the_host_serves_the_owner_page_only_behind_sign_in(world, tmp_path):
    import httpx

    from tests.test_independent_protected_signer import HUMAN_ORIGIN, ORIGIN
    from tests.test_protected_host_native import host_for

    host = host_for(world, tmp_path)
    async with host.api_app.router.lifespan_context(host.api_app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=host)) as client:
            response = await client.get(HUMAN_ORIGIN + "/", follow_redirects=False)
            assert response.status_code in (302, 303, 307), response.text
            assert response.headers["location"].startswith("/login")
            assert "Waiting for you" not in response.text
            # Never on the request origin.
            assert (await client.get(ORIGIN + "/", follow_redirects=False)).status_code == 404
