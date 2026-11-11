"""Controller acts enter through the real production human-origin delivery route.

Only the external installation/hook registration is fixture state. Humans are
registered with their own human ID certificate; no holder writer or legacy
bootstrap creates the first owner before the request under test.
"""

import base64
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from aweb_naapp import roles
from aweb_naapp.hooks.owner_act import HUMAN_ROLE_ACTS
from aweb_naapp.hooks.owner_act_nonces import OwnerActVerifier
from aweb_naapp_testing.owner_acts import TeamOwner

from aweb_secrets.owners import OWNER_ROLE, owner_scope
from aweb_secrets.revisions import config_revision
from tests.human_owner import b64, fixture_principal, holder_credential, human
from tests.test_production_bootstrap import envelopes, mounted_owner_console
from tests.test_production_bootstrap import root as root

pytestmark = pytest.mark.parametrize("root", [{"manifest_version": 3}], indirect=True)
PATH = "/.well-known/aweb-owner-act"
CONTACT = "owner@example.com"


async def delivery(root, registry, *, act="human-role.designate", alias="alice"):
    service, client, settings, member, installed, *_ = root
    world = getattr(client, "owner_delivery_fixture", None)
    if world is None:
        console = mounted_owner_console(service)
        verifier = OwnerActVerifier(
            scope=settings.app_id,
            audience=settings.console_origin,
            acts=HUMAN_ROLE_ACTS,
            team_key_for=console.verifier._team_key_for,
        )
        world = client.owner_delivery_fixture = SimpleNamespace(
            owner=TeamOwner(member.team_key, verifier, member.team_id), registry=registry
        )
    principal = fixture_principal(member.team_id, alias)
    subject = {
        "app_id": settings.app_id,
        "installation_id": installed["installation_id"],
        "role": OWNER_ROLE,
        "principal": principal.principal_did,
    }
    body = {}
    device = None
    if act != "human-role.revoke":
        device, credential = holder_credential(settings.console_origin)
        async with human(world, principal) as (holder, _):
            body["certificate"] = base64.b64encode(json.dumps(holder.certificate()).encode()).decode()
        from aweb_naapp.runtime.passkeys import contact_sha256

        subject.update(
            credential_sha256=credential.sha256, notice_contact_sha256=contact_sha256(CONTACT)
        )
        body.update(
            credential={
                "credential_id": b64(credential.credential_id),
                "public_key": b64(credential.public_key),
                "rp_id": credential.rp_id,
            },
            notice_contact=CONTACT,
        )
    signing, signature = world.owner.sign(act, subject)
    body.update(signing=base64.b64encode(signing).decode(), signature=signature)
    return body, principal, device


async def effects(service, installation_id):
    db = service.runtime.db()
    return (
        await config_revision(db, installation_id),
        *[
            await db.fetch_value("SELECT count(*) FROM " + table)
            for table in (
                "role_assignments",
                "role_holdings",
                "passkey_credentials",
                "owner_act_nonces",
                "credential_authorizations",
                "outbox_events",
            )
        ],
    )


async def test_first_owner_is_designated_by_controller_act_and_can_log_in(root, registry):
    service, client, settings, member, installed, *_ = root
    body, principal, device = await delivery(root, registry)
    db = service.runtime.db()
    assert await db.fetch_value("SELECT count(*) FROM role_holdings") == 0
    assert await config_revision(db, installed["installation_id"]) == 0
    response = await client.post(settings.console_origin + PATH, json=body)
    assert response.status_code == 200, response.text
    assert response.json()["principal"] == principal.principal_did
    assert response.json()["act"] == "human-role.designate"
    assert response.json()["role"] == OWNER_ROLE
    held = await roles.read_holding(
        db,
        installation_id=installed["installation_id"],
        team_id=member.team_id,
        role=OWNER_ROLE,
        principal=principal.principal_did,
    )
    assert held is not None and held.certificate is not None
    assert held.b3_scope == owner_scope(
        installed["installation_id"], member.team_id, principal.principal_did
    )
    assert await config_revision(db, installed["installation_id"]) == 1
    assert await db.fetch_value("SELECT count(*) FROM owner_principals") == 0
    assert await db.fetch_value("SELECT count(*) FROM passkey_enrolments") == 0
    assert [event["payload"]["act"] for event in await envelopes(db, member.team_id)] == [
        "role.designated"
    ]
    options = await client.post(settings.console_origin + "/login/options", json={"scope": held.b3_scope})
    assert options.status_code == 200
    logged = await client.post(
        settings.console_origin + "/login",
        json={"scope": held.b3_scope, "assertion": device.get(options.json())},
    )
    assert logged.status_code == 200


@pytest.mark.parametrize("fault", ["member-signature", "missing-certificate", "contact", "api-origin"])
async def test_refused_delivery_changes_no_owner_revision_nonce_or_audit(root, registry, fault):
    service, client, settings, member, installed, *_ = root
    body, _, _ = await delivery(root, registry)
    before = await effects(service, installed["installation_id"])
    origin = settings.console_origin
    if fault == "member-signature":
        signing = base64.b64decode(body["signing"])
        body["signature"] = base64.b64encode(member.member_key.sign(signing).signature).decode().rstrip("=")
    elif fault == "missing-certificate":
        del body["certificate"]
    elif fault == "contact":
        body["notice_contact"] = "different@example.com"
    else:
        origin = settings.public_origin
    response = await client.post(origin + PATH, json=body, headers={"Cookie": "session=untrusted"})
    assert response.status_code == (404 if fault == "api-origin" else 403)
    if fault == "missing-certificate":
        assert response.json()["detail"] == "principal_not_member"
    assert await effects(service, installed["installation_id"]) == before


async def test_replay_does_not_repeat_the_revision_or_governance_effect(root, registry):
    service, client, settings, _, installed, *_ = root
    body, _, _ = await delivery(root, registry)
    first = await client.post(settings.console_origin + PATH, json=body)
    assert first.status_code == 200, first.text
    before = await effects(service, installed["installation_id"])
    repeated = await client.post(settings.console_origin + PATH, json=body)
    assert repeated.status_code == 403
    assert await effects(service, installed["installation_id"]) == before


async def test_replace_retains_the_holding_and_freezes_its_credential_for_72_hours(root, registry):
    service, client, settings, member, installed, *_ = root
    first, principal, _ = await delivery(root, registry)
    assert (await client.post(settings.console_origin + PATH, json=first)).status_code == 200
    db = service.runtime.db()
    key = dict(
        installation_id=installed["installation_id"], team_id=member.team_id,
        role=OWNER_ROLE, principal=principal.principal_did,
    )
    before = await roles.read_holding(db, **key)
    replacement, _, _ = await delivery(root, registry, act="human-credential.replace")
    started = datetime.now(UTC)
    response = await client.post(settings.console_origin + PATH, json=replacement)
    assert response.status_code == 200, response.text
    effective = datetime.fromisoformat(response.json()["effective_at"].replace("Z", "+00:00"))
    assert started + timedelta(hours=72) <= effective <= datetime.now(UTC) + timedelta(hours=72)
    held = await roles.read_holding(db, **key)
    assert held.held_since == before.held_since
    assert await config_revision(db, installed["installation_id"]) == 2
    assert await mounted_owner_console(service).passkeys.designated_approver(held.b3_scope) is None


async def test_controller_revoke_ends_the_holding_and_moves_the_revision(root, registry):
    service, client, settings, member, installed, *_ = root
    first, principal, _ = await delivery(root, registry)
    assert (await client.post(settings.console_origin + PATH, json=first)).status_code == 200
    revoke, _, _ = await delivery(root, registry, act="human-role.revoke")
    response = await client.post(settings.console_origin + PATH, json=revoke)
    assert response.status_code == 200, response.text
    db = service.runtime.db()
    assert await roles.read_holding(
        db, installation_id=installed["installation_id"], team_id=member.team_id,
        role=OWNER_ROLE, principal=principal.principal_did,
    ) is None
    assert await config_revision(db, installed["installation_id"]) == 2
    assert [event["payload"]["act"] for event in await envelopes(db, member.team_id)] == [
        "role.designated", "role.revoked"
    ]
