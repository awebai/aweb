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
    assert [(h["operation_id"], h["state"], h["decided_by_you"]) for h in view["history"]] == [
        (operation.operation_id, "committed", True)]


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
    # An admission nobody approved is an added agent, not a decision.
    assert added.operation_id not in [h["operation_id"] for h in view["history"]]
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


def owner_fixture_view():
    return {
        "authority": {"kind": "team_controller", "id": "engineering:customer.example", "domain": "customer.example",
            "human": "did:aw:HUMAN"},
        "pending": [
            {"operation_id": "op-1", "operation": "identity.root.endorse", "requester": "did:aw:ROOT",
             "digest": "ab" * 32, "handoff_id": "h-1", "expires_at": "2026-11-14T09:30:00Z",
             "asked_at": "2026-11-13T09:30:00Z"},
            {"operation_id": "op-2", "operation": "human-role.revoke", "requester": "did:aw:OPS",
             "digest": "ef" * 32, "handoff_id": "h-2", "expires_at": "2026-11-13T10:10:00Z",
             "asked_at": "2026-11-13T10:00:00Z"},
        ],
        "history": [{"operation_id": "op-0", "operation": "human-role.revoke", "requester": "did:aw:ROOT",
            "digest": "cd" * 32, "state": "refused", "code": "human_refused", "at": "2026-11-13T10:00:00Z",
            "decided_by_you": True}],
        "admitted": [{"root_id": "did:aw:ROOT", "alias": "build-<1>", "child_id": None, "child_key": "did:key:zK",
            "admitted_at": "2026-11-13T09:00:00Z", "state": "active"}],
        "roots": [{"root_id": "did:aw:ROOT", "active": 3, "in_window": 2, "next_at": "2026-11-13T10:00:00Z"}],
        "policy": {"version": 1, "digest": "sha256:" + "e" * 64, "teams": ["engineering:customer.example"],
            "root_selector": {"kind": "service_endorsed_root", "service_id": "s"}, "member_role": "member",
            "subject_kinds": ["local_agent", "registered_agent"],
            "bounds": {"max_active": 5, "rate_window_seconds": 3600, "max_per_window": 10}},
        "approvers": [{"contact": "owner@customer.example", "passkeys": [{"key_id": "0a1b2c3d", "added_at": "2026-11-12T08:00:00Z"}]}],
    }


def test_the_owner_page_names_what_it_governs_and_reads_as_sentences():
    from aweb.protected_signing.owner import owner_page_html

    view = owner_fixture_view()
    html = owner_page_html(view)
    assert "<h1>Approvals for team engineering</h1>" in html
    assert "Signed in as owner@customer.example" in html and '<form id="logout">' in html
    for heading in ("Waiting for you", "Agents added without asking you", "Current limits", "History",
            "Who can approve"):
        assert f">{heading}</h2>" in html
    # Every waiting row says who asked and when, so each link reads differently.
    # Times are marked for the viewer's zone and read as UTC without script.
    assert ('href="/handoff/h-1">Review the request from did:aw:ROOT, asked '
        '<time datetime="2026-11-13T09:30:00Z" data-local>2026-11-13 09:30 UTC</time></a>') in html
    assert ('href="/handoff/h-2">Review the request from did:aw:OPS, asked '
        '<time datetime="2026-11-13T10:00:00Z" data-local>2026-11-13 10:00 UTC</time></a>') in html
    assert ('Denied by you, <time datetime="2026-11-13T10:00:00Z" data-local>2026-11-13 10:00 UTC</time>: '
        "a request from did:aw:ROOT") in html
    assert "The root agent: 3 of 5 at a time, 2 of 10 in the last hour." in html
    assert "in engineering" in html and "in engineering:customer.example" not in html
    assert "needs its own approval" not in html
    assert "Passkey added 2026-11-12" in html and "passkey 0a1b2c3d" not in html
    assert "0a1b2c3d" in html.split("Passkey added 2026-11-12", 1)[1]
    assert "build-&lt;1&gt;" in html and "build-<1>" not in html
    human = owner_page_html({**view, "authority": {**view["authority"], "kind": "human_identity", "id": "did:aw:HUMAN"}})
    assert "<h1>Your own approvals</h1>" in human and "Agents added without asking you" not in human
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



def test_the_owner_page_has_its_own_layout_not_an_empty_stylesheet():
    from aweb.protected_signing.bootstrap import protected_shell

    css = protected_shell("aweb.protected.console.csrf").brand.stylesheet
    for rule in ("max-width", "padding", ".owner-list", "overflow-wrap"):
        assert rule in css


def test_the_sign_in_page_title_does_not_repeat_itself():
    from aweb.protected_signing.bootstrap import protected_shell

    page = protected_shell("aweb.protected.console.csrf").page("Sign in", "<h1>Sign in</h1>")
    assert "<title>Sign in · Protected signing</title>" in page.body.decode()
    assert protected_shell("aweb.protected.console.csrf").brand.sign_in.title == "Sign in"
