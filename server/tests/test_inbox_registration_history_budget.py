"""Revoked history must not multiply staged registration work on inbox reads."""

import json

import httpx
import pytest

from awid.registry import RegistryClient
from test_dashboard_privacy import TEAM, TEAM_NAME, privacy_app as privacy_app
from test_messages_http import _signed_team_headers
from test_team_room import admit_room_member


@pytest.mark.asyncio
@pytest.mark.parametrize("history", [0, 2000])
async def test_warm_inbox_registration_pages_do_not_grow_with_revoked_history(
    privacy_app, monkeypatch, history
):
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
    # Historical revoked rows are cost input, never accepted authority.
    await env.registry_db.execute(
        """INSERT INTO {{tables.team_certificates}}
               (team_uuid,certificate_id,member_did_key,alias,revoked_at)
           SELECT t.team_uuid,'old-inbox-'||n,$2,'old-'||n,now()
           FROM {{tables.teams}} t CROSS JOIN generate_series(1,$3::int) n
           WHERE t.name=$1""",
        TEAM_NAME,
        alice.did,
        history,
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

    original = env.app.state.awid_registry_client
    # A real uncached SDK client isolates the owner's active-view guarantee,
    # including hosts whose wrapper does not delegate collection caching.
    registry = RegistryClient(
        "http://registry.test",
        transport=CountedTransport(app=env.registry_app),
        service_token=original.service_token,
        domain_verifier=env.registry.namespace_authority,
    )
    env.app.state.awid_registry_client = registry
    try:
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
        assert len(pages) <= 10
        assert pages
        assert all(not page["cursor"] for page in pages)
        print(
            "INBOX_REGISTRATION_COST "
            + json.dumps(
                {
                    "history": history,
                    "warm_inbox_requests": 5,
                    "certificate_pages": len(pages),
                    "active_only_values": sorted({page["active_only"] for page in pages}),
                },
                sort_keys=True,
            )
        )
    finally:
        env.app.state.awid_registry_client = original
        await registry.aclose()
