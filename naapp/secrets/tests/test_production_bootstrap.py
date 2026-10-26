"""First owner and member requests go through the actual production root."""

import base64
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import httpx
import pytest
from aweb_naapp.hooks.envelope import verify
from aweb_naapp.runtime.passkeys import contact_sha256
from aweb_naapp_testing import Member
from aweb_naapp_testing.owner_acts import AUDIENCE, TeamOwner
from aweb_naapp_testing.smtp import SmtpServer
from aweb_naapp_testing.webauthn import SoftAuthenticator
from awid_service.testing import SERVICE_TOKEN

from aweb_secrets.composition import create_service
from aweb_secrets.owners import owner_scope
from tests.production_authority import authority, install, install_audit_receiver, no_dns_override
from tests.test_composition import settings
from tests.test_console_bootstrap import delivered_url


async def envelopes(db, team_id):
    rows = await db.fetch_all("SELECT payload,signature FROM outbox_events ORDER BY position")
    return [verify(bytes(row["payload"]), row["signature"], team_id=team_id).fields for row in rows]


@pytest.fixture
async def root(test_db_factory, registry, tmp_path):
    member = Member(team_id="root:example.com")
    async with authority(test_db_factory, registry, member) as (aweb_db, transport):
        database = await test_db_factory.create_db(suffix="production_bootstrap")
        with SmtpServer(tmp_path / "smtp") as smtp:
            configured = settings(database, tmp_path, smtp).model_copy(
                update={
                    "public_origin": AUDIENCE,
                    "awid_service_token": SERVICE_TOKEN,
                }
            )
            service = create_service(
                configured,
                awid_transport=registry.transport,
                team_server_transport=transport,
            )
            service.runtime.team_server_directory()._registry_override = no_dns_override
            async with service.api_app.router.lifespan_context(service.api_app):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(service)) as client:
                    manifest = await client.get(AUDIENCE + "/manifests/v2.json")
                    assert manifest.status_code == 200
                    installed = await install(
                        aweb_db,
                        member,
                        manifest.content,
                        ["secrets:read", "secrets:use", "secrets:run", "secrets:admin"],
                    )
                    await install_audit_receiver(aweb_db, member)
                    assert (
                        await service.runtime.db().fetch_value(
                            "SELECT count(*) FROM installation_fences"
                        )
                        == 0
                    )
                    yield service, client, configured, member, installed, smtp, transport


def owner_body(configured, member, installation_id):
    principal, contact = member.did_key, "owner@example.com"
    scope = owner_scope(installation_id, member.team_id, principal)
    # Only signing is used from the shared throwaway team-owner helper; the
    # production root builds and runs its own K2 verifier against actual AWID.
    owner = TeamOwner(member.team_key, verifier=None, team_id=member.team_id)
    signing, signature = owner.sign(
        "app-role.designate",
        {
            "app_id": configured.app_id,
            "installation_id": installation_id,
            "role": scope,
            "contact_sha256": contact_sha256(contact),
        },
    )
    return scope, {
        "signing": base64.b64encode(signing).decode(),
        "signature": signature,
        "team_id": member.team_id,
        "principal": principal,
        "contact": contact,
    }


async def test_first_owner_enrols_from_actual_smtp_and_logs_into_production_console(root):
    service, client, configured, member, installed, smtp, transport = root
    installation_id = installed["installation_id"]
    scope, body = owner_body(configured, member, installation_id)
    human = configured.console_origin
    response = await client.post(human + f"/installations/{installation_id}/owner-acts", json=body)
    assert response.status_code == 200, (response.status_code, response.text)
    url = delivered_url(smtp.received, contact=body["contact"], path="/enrolment")
    assert (await client.get(url)).status_code == 200
    [token] = parse_qs(urlsplit(url).fragment)["token"]
    device = SoftAuthenticator(human)
    options = await client.post(human + "/enrolment/options", json={"link_token": token})
    assert options.status_code == 200
    enrolled = await client.post(
        human + "/enrolment",
        json={"link_token": token, "credential": device.create(options.json())},
    )
    assert enrolled.status_code == 200, enrolled.text
    options = await client.post(human + "/login/options", json={"scope": scope})
    assert options.status_code == 200
    logged = await client.post(
        human + "/login", json={"scope": scope, "assertion": device.get(options.json())}
    )
    assert logged.status_code == 200, logged.text
    home = await client.get(human + "/")
    assert home.status_code == 200 and "Secrets console" in home.text
    assert (await client.get(AUDIENCE + "/enrolment")).status_code == 404
    db = service.runtime.db()
    assert await db.fetch_value("SELECT count(*) FROM owner_principals") == 1
    assert await db.fetch_value("SELECT count(*) FROM console_sessions") == 1
    assert [event["payload"]["act"] for event in await envelopes(db, member.team_id)] == [
        "role.designated",
        "credential.enrolled",
    ]
    assert any(call.url.path.endswith("/self/grant") for call in transport.calls)
    assert any(
        call.url.path.endswith("/post-governance-hook/registrations") for call in transport.calls
    )
    # B1 authorizes the genuine registered member through the real team-server
    # grant; Catalog sees the same installation/owner state and no secret rows.
    headers = member.headers(aud=AUDIENCE, method="GET", path="/v1/secrets")
    listed = await client.get(AUDIENCE + "/v1/secrets", headers=headers)
    assert listed.status_code == 200, listed.text
    assert listed.json()["result"]["secrets"] == []
    assert (await client.get(AUDIENCE + "/v1/secrets")).status_code == 401
    assert (
        await client.post(human + "/enrolment/options", json={"link_token": token})
    ).status_code == 403


@pytest.mark.parametrize("fault", ["wrong_team", "wrong_installation", "unavailable"])
async def test_bootstrap_authority_controls_leave_no_owner_nonce_or_audit(root, fault):
    service, client, configured, member, installed, smtp, transport = root
    installation_id = installed["installation_id"]
    _, body = owner_body(configured, member, installation_id)
    if fault == "wrong_team":
        body["team_id"] = "other:example.com"
    elif fault == "wrong_installation":
        installation_id = str(uuid4())
    else:
        transport.down = True
    response = await client.post(
        configured.console_origin + f"/installations/{installation_id}/owner-acts", json=body
    )
    assert response.status_code in {403, 503}, response.text
    db = service.runtime.db()
    for table in (
        "owner_principals",
        "owner_act_nonces",
        "credential_authorizations",
        "passkey_approvers",
    ):
        assert await db.fetch_value("SELECT count(*) FROM " + table) == 0, table
    assert await envelopes(db, member.team_id) == []
    assert smtp.received == []
