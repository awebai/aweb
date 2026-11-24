"""Expose the inbox registration budget with and without enforcement."""

import json

import httpx
import pytest

from awid.registry import RegistryClient
from test_dashboard_privacy import TEAM, TEAM_NAME, privacy_app as privacy_app
from test_messages_http import _encode_certificate, _make_certificate, _signed_team_headers
from test_team_room import admit_room_member

__all__ = ["privacy_app"]


async def _warm_inbox_registration_cost(privacy_app, monkeypatch, history, *, enforce):
    env = privacy_app
    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", "false")
    for alias in ("alice", "bob"):
        await admit_room_member(env, alias=alias)
    alice, bob = env.actors["alice"], env.actors["bob"]
    wire = json.dumps(
        {"to_did": bob.did, "subject": "bounded", "body": "same stored mail"}
    ).encode()
    sent = await env.client.post(
        "/v1/messages",
        content=wire,
        headers={
            **_signed_team_headers(alice.sk, alice.did, TEAM, alice.certificate, wire),
            "Content-Type": "application/json",
        },
    )
    assert sent.status_code == 200, sent.text
    original = env.app.state.awid_registry_client
    for number in range(history):
        certificate_id = f"old-inbox-{number}"
        certificate = _make_certificate(
            env.team_sk,
            env.team_did,
            alice.did,
            team_id=TEAM,
            alias=certificate_id,
            identity_scope="local",
            certificate_id=certificate_id,
        )
        await original.register_team_certificate(
            "example.test",
            TEAM_NAME,
            team_controller_signing_key=env.team_sk,
            certificate_id=certificate_id,
            member_did_key=alice.did,
            member_did_aw=None,
            member_address=None,
            alias=certificate_id,
            identity_scope="local",
            certificate=_encode_certificate(certificate),
        )
        await original.revoke_team_certificate(
            "example.test",
            TEAM_NAME,
            team_controller_signing_key=env.team_sk,
            certificate_id=certificate_id,
        )
    pages = []

    class CountedTransport(httpx.ASGITransport):
        async def handle_async_request(self, request):
            if request.method == "GET" and request.url.path.endswith("/certificates"):
                pages.append(
                    {
                        "active_only": request.url.params.get("active_only"),
                        "cursor": "cursor" in request.url.params,
                    }
                )
            return await super().handle_async_request(request)

    # Keep the real uncached SDK client. A cached client would hide repeated
    # page acquisition for hosts that do not delegate collection caching.
    registry = RegistryClient(
        "http://registry.test",
        transport=CountedTransport(app=env.registry_app),
        service_token=original.service_token,
        domain_verifier=env.registry.namespace_authority,
    )
    env.app.state.awid_registry_client = registry
    try:
        monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", str(enforce).lower())
        headers = _signed_team_headers(bob.sk, bob.did, TEAM, bob.certificate)
        warm = await env.client.get("/v1/messages/inbox", headers=headers)
        assert warm.status_code == 200, warm.text
        pages.clear()
        for _ in range(5):
            response = await env.client.get("/v1/messages/inbox", headers=headers)
            assert response.status_code == 200, response.text
            messages = response.json()["messages"]
            assert len(messages) == 1
            assert messages[0]["message_id"] == sent.json()["message_id"]
            assert messages[0]["sender_membership"]["state"] == "active"
        counts = {
            "enforced": enforce,
            "history": history,
            "warm_inbox_requests": 5,
            "certificate_pages": len(pages),
            "cursor_pages": sum(page["cursor"] for page in pages),
            "active_only_values": sorted({page["active_only"] for page in pages}),
        }
        print("INBOX_REGISTRATION_COST " + json.dumps(counts, sort_keys=True))
        return counts
    finally:
        env.app.state.awid_registry_client = original
        await registry.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("history", [0, 2000])
async def test_off_mode_warm_inboxes_never_read_registration_pages(privacy_app, monkeypatch, history):
    counts = await _warm_inbox_registration_cost(privacy_app, monkeypatch, history, enforce=False)
    assert counts["certificate_pages"] == 0, counts


class _RegistrationBudgetExceeded(AssertionError):
    pass


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "history",
    [
        0,
        pytest.param(
            2000,
            marks=pytest.mark.xfail(
                reason="aweb-adus: REQUIRED scans the full catalog, including revoked history",
                raises=_RegistrationBudgetExceeded,
                strict=True,
            ),
        ),
    ],
)
async def test_required_warm_inboxes_stay_within_registration_budget(privacy_app, monkeypatch, history):
    counts = await _warm_inbox_registration_cost(privacy_app, monkeypatch, history, enforce=True)
    assert counts["active_only_values"] in ([], ["false"]), counts
    if counts["certificate_pages"] > 10 or counts["cursor_pages"]:
        raise _RegistrationBudgetExceeded(counts)
