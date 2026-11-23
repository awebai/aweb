"""Run40's holder credential requests keep F6 outages typed at the HTTP boundary.

The actual Secrets constructor, holder adapter, registry/discovery and grant
routes run here. Removing the external team's publication supplies the same
team_server_unpublished cause as the retained Run40 failure.
"""

from time import monotonic_ns

import httpx
import pytest
from aweb.config import APP_GRANT_MAX_AGE_CEILING_SECONDS
from aweb_naapp.console import CONSOLE_HEADERS
from aweb_naapp_testing import Member
from aweb_naapp_testing.human_members import registered_human
from aweb_naapp_testing.webauthn import SoftAuthenticator

from tests.test_production_bootstrap import root as root
from tests.test_production_handoffs import start_request


async def unchanged_authority_and_handoff(db, handoff):
    row = await db.fetch_value(
        "SELECT to_jsonb(h) FROM console_handoffs h WHERE handoff_id=$1::uuid", handoff
    )
    counts = {
        table: await db.fetch_value("SELECT count(*) FROM " + table)
        for table in (
            "role_holdings",
            "role_assignments",
            "passkey_credentials",
            "console_sessions",
            "console_session_nonces",
            "owner_act_nonces",
            "outbox_events",
        )
    }
    return row, counts


@pytest.mark.parametrize("step", ["state", "options", "complete"])
async def test_holder_credential_outage_is_503_without_writes_and_recovers(
    root, registry, monkeypatch, step
):
    service, client, settings, team_member, _, _, site, _ = root
    # root already registered its own member certificate. This distinct human
    # follows the real registration helper once, under the same team controller.
    member = Member(
        team_id=team_member.team_id,
        team_key=team_member.team_key,
        alias="holder-http",
        certificate_id="holder-http",
    )
    # Use the real healthy freshness window and advance its clock only after
    # the test withdraws the signed publication. Setup scheduling must not
    # expire the SQL fence between permit() and the healthy credential read.
    now = monotonic_ns()

    def clock():
        return now

    monkeypatch.setenv("AWEB_APP_GRANT_MAX_AGE_SECONDS", str(APP_GRANT_MAX_AGE_CEILING_SECONDS))
    directory = service.runtime.team_server_directory()
    grants = service.runtime.installation_grants()
    fence = service.runtime.installation_fence()
    monkeypatch.setattr(directory, "_clock", clock)
    monkeypatch.setattr(grants, "_monotonic", clock)
    monkeypatch.setattr(grants._cache, "_monotonic", clock)
    monkeypatch.setattr(fence, "monotonic", clock)
    async with registered_human(registry, member) as human:
        _, _, raw, headers = start_request(root, member, human.principal)
        started = await client.post(
            settings.public_origin + "/handoffs", content=raw, headers=headers
        )
        assert started.status_code == 201, started.text
        handoff = started.json()["handoff_id"]
        path = f"/handoff/{handoff}/credential"
        origin = settings.console_origin
        browser_headers = {}
        payload = {}
        if step != "state":
            state = await client.get(origin + path)
            assert state.status_code == 200, state.text
            browser_headers = {"Origin": origin, "X-CSRF-Token": state.json()["csrf_token"]}
        if step == "complete":
            options = await client.post(
                origin + path + "/options", json={}, headers=browser_headers
            )
            assert options.status_code == 200, options.text
            payload = {"credential": SoftAuthenticator(origin).create(options.json())}

        # Warm a real active observation so the outage must invalidate its SQL
        # freshness, including on the first browser GET in the observed journey.
        await fence.permit(member.team_id)
        grant = await grants.status_for(member.team_id)
        assert grant is not None and grant.max_age_seconds == APP_GRANT_MAX_AGE_CEILING_SECONDS
        published = await directory.resolve(member.team_id)
        deadline = max(grant.fresh_until, published.expires_at)
        name, domain = member.team_id.split(":", 1)
        removed = await registry.db.fetch_value(
            "DELETE FROM {{tables.team_server_records}} WHERE team_uuid IN "
            "(SELECT team_uuid FROM {{tables.teams}} WHERE domain=$1 AND name=$2) "
            "RETURNING team_uuid",
            domain,
            name,
        )
        assert removed is not None
        now = deadline + 1
        db = service.runtime.db()
        before = await unchanged_authority_and_handoff(db, handoff)
        endpoint = origin + path + ("" if step == "state" else "/" + step)
        # Observe the actual public status even when old code leaks its typed
        # exception through ASGI. Browser cookies/CSRF are genuine prior state.
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(service, raise_app_exceptions=False),
            cookies=client.cookies,
        ) as browser:
            refused = (
                await browser.get(endpoint)
                if step == "state"
                else await browser.post(endpoint, json=payload, headers=browser_headers)
            )
        assert refused.status_code == 503, refused.text
        assert refused.json() == {"detail": "authority_unavailable"}
        for key, value in CONSOLE_HEADERS.items():
            assert refused.headers[key] == value
        assert "set-cookie" not in refused.headers
        assert await unchanged_authority_and_handoff(db, handoff) == before
        fence = await db.fetch_one(
            "SELECT state,fresh_until FROM installation_fences WHERE team_id=$1", member.team_id
        )
        assert fence["state"] == "active" and fence["fresh_until"] is None

        # Restore the real signed publication. The same unspent handoff and,
        # for complete, the original real registration response can now finish.
        await registry.publish_team_server(member.team_id, member.team_key, server_url=site.origin)
        recovered = (
            await client.get(endpoint)
            if step == "state"
            else await client.post(endpoint, json=payload, headers=browser_headers)
        )
        assert recovered.status_code == 200, recovered.text
        assert await db.fetch_value(
            "SELECT fresh_until>clock_timestamp() FROM installation_fences WHERE team_id=$1",
            member.team_id,
        )
