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
    scope = await scope_of(a.human)
    view = await owner_view(a.group, scope=scope, subject=a.actor.subject)
    assert [p["operation_id"] for p in view["pending"]] == [operation.operation_id]
    waiting = view["pending"][0]
    assert waiting["handoff_id"] == frozen["handoff_id"] and waiting["operation"] == "identity.root.endorse"
    assert waiting["requester"] == a.w.root_id and waiting["digest"] == frozen["digest"]
    # The row asks the definition's own question, filled from the frozen request.
    subject = operation.intent()["subject"]
    assert waiting["title"] == f"Approve {subject['deployment_label']} as the root agent for {', '.join(subject['teams'])}?"
    assert view["history"] == []
    # The page names the approver who is signed in, not the first one listed.
    assert view["you"] == next(x["contact"] for x in view["approvers"] if x["contact"])
    await endorse_existing(a, operation)
    view = await owner_view(a.group, scope=scope, subject=a.actor.subject)
    assert view["pending"] == []
    assert [(h["operation_id"], h["state"], h["decided_by_you"], h["title"]) for h in view["history"]] == [
        (operation.operation_id, "committed", True, waiting["title"])]
    # Another owner of the same scope did not decide it, though the audit
    # names the same governed human for both.
    other = await owner_view(a.group, scope=scope, subject="another-approver")
    assert other["you"] is None and other["history"][0]["decided_by_you"] is False


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
    view = await owner_view(a.group, scope=await scope_of(a.w.app), subject=a.actor.subject)
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
    # Every current member of the team is listed, with its kind and how it
    # joined, whether or not this signer added it.
    members = {m["alias"]: m for m in view["members"]}
    alias = added.intent()["subject"]["member_alias"]
    assert members[alias]["joined"] == "signer" and members[alias]["kind"] == "agent"
    assert members[alias]["member_did_key"] == added.intent()["subject"]["child_key"]
    assert all(set(m) == {"alias", "kind", "joined", "member_did_aw", "member_did_key", "certificate_id"}
        for m in view["members"])
    assert all(m["joined"] in ("signer", "signer_reserved", "signer_removed", "unrecorded") for m in view["members"])
    assert all(m["kind"] in ("agent", "human", "kind not verified", "not checked") for m in view["members"])


@pytest.mark.asyncio
async def test_a_scope_this_host_does_not_hold_shows_nothing(admissions):
    from aweb_naapp.runtime.protected_signer import SignerRefused

    with pytest.raises(SignerRefused, match="scope_refused"):
        await owner_view(admissions.group, scope="protected-not-ours", subject="anyone")


def owner_fixture_view():
    return {
        "authority": {"kind": "team_controller", "id": "engineering:customer.example", "domain": "customer.example",
            "human": "did:aw:HUMAN"},
        "pending": [
            {"operation_id": "op-1", "operation": "identity.root.endorse", "requester": "did:aw:ROOT",
             "digest": "ab" * 32, "handoff_id": "h-1", "expires_at": "2026-11-14T09:30:00Z",
             "asked_at": "2026-11-13T09:30:00Z", "title": "Approve build as the root agent for <eng>?"},
            {"operation_id": "op-2", "operation": "human-role.revoke", "requester": "did:aw:OPS",
             "digest": "ef" * 32, "handoff_id": "h-2", "expires_at": "2026-11-13T10:10:00Z",
             "asked_at": "2026-11-13T10:00:00Z", "title": "Remove did:aw:BOB from app.owner?",
             "requester_name": "ops"},
        ],
        "history": [{"operation_id": "op-0", "operation": "human-role.revoke", "requester": "did:aw:ROOT",
            "digest": "cd" * 32, "state": "refused", "code": "human_refused", "at": "2026-11-13T10:00:00Z",
            "decided_by_you": True, "title": "Remove did:aw:ANN from app.owner?"}],
        "admitted": [{"root_id": "did:aw:ROOT", "alias": "build-<1>", "certificate_id": "cert-1", "child_id": None,
            "child_key": "did:key:zK",
            "admitted_at": "2026-11-13T09:00:00Z", "state": "active"}],
        "roots": [{"root_id": "did:aw:ROOT", "active": 3, "in_window": 2, "next_at": "2026-11-13T10:00:00Z"}],
        "policy": {"version": 1, "digest": "sha256:" + "e" * 64, "teams": ["engineering:customer.example"],
            "root_selector": {"kind": "service_endorsed_root", "service_id": "s"}, "member_role": "member",
            "subject_kinds": ["local_agent", "registered_agent"],
            "bounds": {"max_active": 5, "rate_window_seconds": 3600, "max_per_window": 10}},
        "approvers": [{"contact": "first@customer.example", "passkeys": []},
            {"contact": "owner@customer.example", "passkeys": [{"key_id": "0a1b2c3d", "added_at": "2026-11-12T08:00:00Z"}]}],
        "you": "owner@customer.example",
        "members": [{"alias": "build-<1>", "kind": "agent", "joined": "signer", "member_did_aw": None,
                "member_did_key": "did:key:zK", "certificate_id": "cert-1"},
            {"alias": "ops", "kind": "kind not verified", "joined": "unrecorded", "member_did_aw": "did:aw:OPS",
                "member_did_key": "did:key:zO", "certificate_id": "cert-2"},
            {"alias": "ann", "kind": "not checked", "joined": "signer_reserved", "member_did_aw": "did:aw:ANN",
                "member_did_key": "did:key:zA", "certificate_id": "cert-3"}],
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
    assert "Signed in as first@customer.example" not in html
    # Every waiting row asks the operation's own question, then says who
    # asked and when. Times are marked for the viewer's zone and read as UTC
    # without script.
    assert 'href="/handoff/h-1">Approve build as the root agent for &lt;eng&gt;?</a>' in html
    assert ('<p>Requested by did:aw:ROOT, asked '
        '<time datetime="2026-11-13T09:30:00Z" data-local>2026-11-13 09:30 UTC</time></p>') in html
    assert 'href="/handoff/h-2">Remove did:aw:BOB from app.owner?</a>' in html
    assert ('Denied by you, <time datetime="2026-11-13T10:00:00Z" data-local>2026-11-13 10:00 UTC</time>: '
        "Remove did:aw:ANN from app.owner?") in html
    assert "a request from" not in html
    # A requester the team knows is named by its alias; its identifier stays
    # in Technical details.
    assert ('<p>Requested by ops, asked '
        '<time datetime="2026-11-13T10:00:00Z" data-local>2026-11-13 10:00 UTC</time></p>') in html
    # Every current member is listed with its kind and how it joined; no
    # action is offered from this page.
    assert ">Team members</h2>" in html
    assert "build-&lt;1&gt;: agent, added through this signer" in html
    assert "ops: kind not verified, not recorded by this signer" in html
    assert "ann: kind could not be checked, being added through this signer" in html
    assert "joined another way" not in html
    unread = owner_page_html({**view, "members": None})
    assert "The member list could not be read right now." in unread
    assert "Remove</button>" not in html
    assert "The root agent: 3 of 5 at a time, 2 of 10 in the last hour." in html
    assert "in engineering" in html and "in engineering:customer.example" not in html
    assert "needs its own approval" not in html
    passkey = 'Passkey added <time datetime="2026-11-12T08:00:00Z" data-local="date">2026-11-12</time>'
    assert passkey in html and "passkey 0a1b2c3d" not in html
    assert "0a1b2c3d" in html.split(passkey, 1)[1]
    assert "build-&lt;1&gt;" in html and "build-<1>" not in html
    human = owner_page_html({**view, "authority": {**view["authority"], "kind": "human_identity", "id": "did:aw:HUMAN"}})
    assert "<h1>Your own approvals</h1>" in human and "Agents added without asking you" not in human
    empty = owner_page_html({**view, "pending": [], "history": [], "admitted": [], "roots": [], "members": []})
    assert "Nothing is waiting for you." in empty and "No agents have been added yet." in empty
    assert "Nothing has happened yet." in empty and "No members." in empty


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


@pytest.mark.asyncio
async def test_a_signed_but_unconfirmed_effect_is_unresolved_never_expired(admissions):
    from datetime import UTC, datetime, timedelta

    from aweb.protected_signing.owner import owner_page_html

    a = admissions
    operation = root_operation(a)
    assert (await prepare(a, operation)).status_code == 200
    # The composed engine retains a signed effect before it confirms delivery.
    # The engine also retains the signed effect it has not delivered yet; the
    # owner page never shows any of it.
    canary = "RETAINED-EFFECT-CANARY-7f3a"
    await a.w.db.execute(
        "UPDATE {{tables.protected_signer_operations}} SET signed_result=$2::jsonb,retained_effect=$3::jsonb "
        "WHERE operation_id=$1",
        operation.operation_id, '{"signing":"c2lnbmVk","signature":"c2lnbmF0dXJl"}',
        '{"artifact":"' + canary + '","signature":"' + canary + '"}')
    scope = await scope_of(a.human)
    for when in (datetime.now(UTC), datetime.now(UTC) + timedelta(days=2)):
        view = await owner_view(a.group, scope=scope, subject=a.actor.subject, now=when)
        assert canary not in repr(view) and canary not in owner_page_html(view)
        assert "c2lnbmF0dXJl" not in owner_page_html(view)
        assert view["pending"] == []
        [entry] = [h for h in view["history"] if h["operation_id"] == operation.operation_id]
        assert entry["state"] == "unresolved"
        # This operation's own row (others in the fixture may really expire).
        [row] = [li for li in owner_page_html(view).split("<li>") if entry["digest"] in li]
        assert "Expired, nobody decided" not in row and "not confirmed yet" in row


def test_a_requester_the_team_knows_is_named_by_its_alias():
    from aweb.protected_signing.owner import _name_requesters

    entries = [{"requester": "did:aw:OPS"}, {"requester": "did:key:zK"}, {"requester": "did:aw:STRANGER"}]
    members = [{"alias": "ops", "member_did_aw": "did:aw:OPS", "member_did_key": "did:key:zO"},
        {"alias": "build-1", "member_did_aw": None, "member_did_key": "did:key:zK"}]
    _name_requesters(entries, members)
    assert [e["requester_name"] for e in entries] == ["ops", "build-1", None]
    _name_requesters(entries, None)
    assert [e["requester_name"] for e in entries] == [None, None, None]


@pytest.mark.asyncio
async def test_provenance_comes_only_from_this_signers_exact_record_of_the_certificate():
    """AWID allows several active certificates for one member key. Only the
    certificate this signer recorded is credited to it, with the state it
    recorded; any other certificate is "not recorded by this signer", which
    says nothing about how it joined."""
    from types import SimpleNamespace

    from aweb.protected_signing.owner import _members

    def certificate(certificate_id, key="did:key:zSHARED"):
        return SimpleNamespace(certificate_id=certificate_id, alias=certificate_id, member_did_key=key,
            member_did_aw=None, identity_scope="local")

    async def certificates(domain, name, *, active_only):
        assert (domain, name, active_only) == ("customer.example", "engineering", True)
        return [certificate("cert-admitted"), certificate("cert-same-key"), certificate("cert-reserved", "did:key:zR"),
            certificate("cert-removed", "did:key:zX"), certificate("cert-unknown", "did:key:zU")]

    c = SimpleNamespace(context=SimpleNamespace(authority_id="engineering:customer.example"),
        registry=SimpleNamespace(list_team_certificates_fresh=certificates))
    view = {"admitted": [
        {"child_key": "did:key:zSHARED", "certificate_id": "cert-admitted", "state": "active"},
        {"child_key": "did:key:zR", "certificate_id": "cert-reserved", "state": "reserved"},
        {"child_key": "did:key:zX", "certificate_id": "cert-removed", "state": "removed"}], "members": []}
    await _members(c, view)
    assert {m["certificate_id"]: m["joined"] for m in view["members"]} == {
        "cert-admitted": "signer", "cert-same-key": "unrecorded", "cert-reserved": "signer_reserved",
        "cert-removed": "signer_removed", "cert-unknown": "unrecorded"}


@pytest.mark.asyncio
@pytest.mark.parametrize("bound_key, expected", [("did:key:zCERT", "agent"), ("did:key:zNEW", "kind not verified")])
async def test_member_kind_is_observed_for_the_certificates_own_key(monkeypatch, bound_key, expected):
    """A membership certificate for an old key is never labelled with what
    the identity's current key proves."""
    from types import SimpleNamespace

    from awid.identity_observation import IdentityObservationRefused

    from aweb.protected_signing import owner

    observed = []

    async def observe_binding(registry, *, did_aw, did_key, address=""):
        observed.append(did_key)
        if did_key != bound_key:
            raise IdentityObservationRefused("identity_binding_mismatch")
        return SimpleNamespace(did_aw=did_aw, did_key=did_key)

    async def observe_kind(registry, binding, bundle=None):
        return SimpleNamespace(result={"outcome": "verified", "identity_valid": True, "kind": "agent"})

    monkeypatch.setattr(owner, "observe_identity_binding", observe_binding)
    monkeypatch.setattr(owner, "observe_identity_kind", observe_kind)
    record = SimpleNamespace(identity_scope="global", member_did_aw="did:aw:MEMBER", member_did_key="did:key:zCERT")
    assert await owner._member_kind(SimpleNamespace(registry=object()), record) == expected
    assert observed == ["did:key:zCERT"]
