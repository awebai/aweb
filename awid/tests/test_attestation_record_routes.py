"""Publishing and reading principal-attestation records through AWID, real PostgreSQL and Redis."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from awid.attestation_records import sign_record
from test_controller_request_v2_http import certificate_body, controller_app, keypair, send  # noqa: F401

TEAM_ID = "base:local"
BASE = "/v1/namespaces/local/teams/base"


def _now(offset_seconds: int = 0) -> str:
    moment = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=offset_seconds)
    return moment.isoformat().replace("+00:00", "Z")


def _custodian(env, *, issued_at=None, issuers=None, custodian_id="custodian.example"):
    return {
        "v": 1, "type": "aweb.team-custodian", "team_id": TEAM_ID, "team_did_key": env.team[1],
        "custodian_id": custodian_id,
        "issuer_did_keys": issuers if issuers is not None else [keypair()[1]],
        "issued_at": issued_at or _now(),
    }


def _custody(env, cert, *, custodian_id="custodian.example", issued_at=None):
    return {
        "v": 1, "type": "aweb.member-custody", "team_id": TEAM_ID, "team_did_key": env.team[1],
        "certificate_id": cert["certificate_id"], "member_did_key": cert["member_did_key"],
        "custodian_id": custodian_id, "issued_at": issued_at or _now(),
    }


def _person(env, cert, *, single_person=True, issued_at=None):
    return {
        "v": 1, "type": "aweb.member-person", "team_id": TEAM_ID, "team_did_key": env.team[1],
        "certificate_id": cert["certificate_id"], "member_did_key": cert["member_did_key"],
        "single_person": single_person, "issued_at": issued_at or _now(),
    }


async def _publish(env, path, operation, key_claim, record, *, signer=None, sign_with=None, covering=True):
    body = {"record": record, "signature": sign_record((sign_with or env.team)[0], record)}
    claims = {"domain": "local", "operation": operation, "team_name": "base", **key_claim}
    return await send(env, "PUT", path, claims, body, signer=signer or env.team, covering=covering)


async def publish_custodian(env, record, **kwargs):
    path = f"{BASE}/custodians/{record['custodian_id']}"
    return await _publish(env, path, "publish_team_custodian", {"custodian_id": record["custodian_id"]}, record, **kwargs)


async def publish_custody(env, record, **kwargs):
    path = f"{BASE}/certificates/{record['certificate_id']}/custody"
    return await _publish(env, path, "publish_member_custody", {"certificate_id": record["certificate_id"]}, record, **kwargs)


async def publish_person(env, record, **kwargs):
    path = f"{BASE}/certificates/{record['certificate_id']}/person"
    return await _publish(env, path, "publish_member_person", {"certificate_id": record["certificate_id"]}, record, **kwargs)


async def register_certificate(env):
    body = certificate_body(env, alias=f"m{uuid4().hex[:8]}")
    claims = {"domain": "local", "operation": "register_certificate", "team_name": "base",
              "certificate_id": body["certificate_id"]}
    response = await send(env, "POST", f"{BASE}/certificates", claims, body, signer=env.team)
    assert response.status_code == 200, response.text
    return body


@pytest.mark.asyncio
async def test_custodian_record_is_published_read_anonymously_and_retry_safe(controller_app):
    env = controller_app
    record = _custodian(env)
    first = await publish_custodian(env, record)
    assert first.status_code == 200, first.text
    stored = await env.client.get(f"{BASE}/custodians/custodian.example")
    assert stored.status_code == 200, stored.text
    assert stored.json()["record"] == record
    signature = stored.json()["signature"]
    retry = await send(env, "PUT", f"{BASE}/custodians/custodian.example",
                       {"domain": "local", "operation": "publish_team_custodian", "team_name": "base",
                        "custodian_id": "custodian.example"},
                       {"record": record, "signature": signature}, signer=env.team)
    assert retry.status_code == 200, retry.text


@pytest.mark.asyncio
async def test_custodian_record_only_moves_forward(controller_app):
    env = controller_app
    assert (await publish_custodian(env, _custodian(env, issued_at=_now(-10)))).status_code == 200
    older = await publish_custodian(env, _custodian(env, issued_at=_now(-20)))
    assert older.status_code == 409, older.text
    assert older.json()["detail"]["code"] == "record_not_newer"
    newer = _custodian(env, issued_at=_now(), issuers=[])
    assert (await publish_custodian(env, newer)).status_code == 200
    assert (await env.client.get(f"{BASE}/custodians/custodian.example")).json()["record"] == newer


@pytest.mark.asyncio
async def test_custodian_publication_refusals(controller_app):
    env = controller_app
    future = await publish_custodian(env, _custodian(env, issued_at=_now(600)))
    assert future.status_code == 422 and future.json()["detail"]["code"] == "issued_at_in_future"
    forged = await publish_custodian(env, _custodian(env), sign_with=keypair())
    assert forged.status_code == 422 and forged.json()["detail"]["code"] == "record_invalid"
    legacy = await publish_custodian(env, _custodian(env), covering=False)
    assert legacy.status_code == 401
    not_controller = await publish_custodian(env, _custodian(env), signer=keypair())
    assert not_controller.status_code == 403
    assert (await env.client.get(f"{BASE}/custodians/custodian.example")).status_code == 404


@pytest.mark.asyncio
async def test_custody_needs_a_registered_custodian_and_is_immutable(controller_app):
    env = controller_app
    cert = await register_certificate(env)
    unregistered = await publish_custody(env, _custody(env, cert))
    assert unregistered.status_code == 409
    assert unregistered.json()["detail"]["code"] == "custodian_not_registered"
    assert (await publish_custodian(env, _custodian(env))).status_code == 200
    record = _custody(env, cert)
    assert (await publish_custody(env, record)).status_code == 200
    stored = (await env.client.get(f"{BASE}/certificates/{cert['certificate_id']}/custody")).json()
    assert stored["record"] == record
    retry = await send(env, "PUT", f"{BASE}/certificates/{cert['certificate_id']}/custody",
                       {"domain": "local", "operation": "publish_member_custody", "team_name": "base",
                        "certificate_id": cert["certificate_id"]}, stored, signer=env.team)
    assert retry.status_code == 200, retry.text
    assert (await publish_custodian(env, _custodian(env, custodian_id="other.example"))).status_code == 200
    moved = await publish_custody(env, _custody(env, cert, custodian_id="other.example", issued_at=_now(1)))
    assert moved.status_code == 409 and moved.json()["detail"]["code"] == "custody_immutable"


@pytest.mark.asyncio
async def test_custody_refuses_a_deregistered_custodian_and_a_foreign_member_key(controller_app):
    env = controller_app
    cert = await register_certificate(env)
    assert (await publish_custodian(env, _custodian(env, issuers=[]))).status_code == 200
    deregistered = await publish_custody(env, _custody(env, cert))
    assert deregistered.status_code == 409
    assert (await publish_custodian(env, _custodian(env, issued_at=_now(1)))).status_code == 200
    wrong_member = dict(_custody(env, cert), member_did_key=keypair()[1])
    assert (await publish_custody(env, wrong_member)).status_code == 422
    unknown = dict(_custody(env, cert), certificate_id=str(uuid4()))
    assert (await publish_custody(env, unknown)).status_code == 404


@pytest.mark.asyncio
async def test_person_declaration_is_revocable_and_newer_only(controller_app):
    env = controller_app
    cert = await register_certificate(env)
    path = f"{BASE}/certificates/{cert['certificate_id']}/person"
    assert (await publish_person(env, _person(env, cert, issued_at=_now(-10)))).status_code == 200
    withdrawn = _person(env, cert, single_person=False)
    assert (await publish_person(env, withdrawn)).status_code == 200
    assert (await env.client.get(path)).json()["record"] == withdrawn
    replay = await publish_person(env, _person(env, cert, issued_at=_now(-5)))
    assert replay.status_code == 409 and replay.json()["detail"]["code"] == "record_not_newer"


@pytest.mark.asyncio
async def test_record_reads_answer_one_identical_404(controller_app):
    env = controller_app
    cert = await register_certificate(env)
    paths = [
        f"/v1/namespaces/local/teams/missing/certificates/{cert['certificate_id']}/custody",
        f"{BASE}/certificates/{uuid4()}/custody",
        f"{BASE}/certificates/{cert['certificate_id']}/custody",
        f"{BASE}/certificates/{cert['certificate_id']}/person",
        f"{BASE}/custodians/nobody.example",
        "/v1/namespaces/missing.example/teams/base/custodians/custodian.example",
    ]
    responses = [await env.client.get(path) for path in paths]
    assert all(response.status_code == 404 for response in responses)
    assert len({response.content for response in responses}) == 1


def _signed(key, record):
    return {"record": record, "signature": sign_record(key, record)}


def _resign(record, new_key_pair, *, offset=1):
    return dict(record, team_did_key=new_key_pair[1], issued_at=_now(offset))


async def _rotate(env, new_did, resigned=None):
    body = {"new_team_did_key": new_did}
    if resigned is not None:
        body["resigned_records"] = resigned
    claims = {"domain": "local", "operation": "rotate_team_key", "name": "base", "new_team_did_key": new_did}
    return await send(env, "POST", f"{BASE}/rotate", claims, body)


async def _team_with_records(env):
    custodian = _custodian(env, issued_at=_now(-30))
    assert (await publish_custodian(env, custodian)).status_code == 200
    cert = await register_certificate(env)
    custody = _custody(env, cert, issued_at=_now(-30))
    person = _person(env, cert, issued_at=_now(-30))
    assert (await publish_custody(env, custody)).status_code == 200
    assert (await publish_person(env, person)).status_code == 200
    return custodian, custody, person


async def _team_key(env):
    return await env.db.fetch_value("SELECT team_did_key FROM {{tables.teams}} WHERE name = 'base'")


@pytest.mark.asyncio
async def test_rotation_swaps_the_key_and_every_record_atomically(controller_app):
    env = controller_app
    custodian, custody, person = await _team_with_records(env)
    new = keypair()
    resigned = {
        "team_custodians": [_signed(new[0], _resign(custodian, new))],
        "member_custody": [_signed(new[0], _resign(custody, new))],
        "member_person": [_signed(new[0], _resign(person, new))],
    }
    response = await _rotate(env, new[1], resigned)
    assert response.status_code == 200, response.text
    assert await _team_key(env) == new[1]
    read = await env.client.get(f"{BASE}/certificates/{custody['certificate_id']}/custody")
    assert read.json() == resigned["member_custody"][0]
    read = await env.client.get(f"{BASE}/custodians/{custodian['custodian_id']}")
    assert read.json() == resigned["team_custodians"][0]


@pytest.mark.asyncio
async def test_an_incomplete_or_changed_set_names_the_keys_and_changes_nothing(controller_app):
    env = controller_app
    custodian, custody, person = await _team_with_records(env)
    old_key = await _team_key(env)
    new = keypair()
    extra_cert = str(uuid4())
    resigned = {
        "team_custodians": [_signed(new[0], _resign(custodian, new))],
        "member_custody": [_signed(new[0], dict(_resign(custody, new), certificate_id=extra_cert))],
        "member_person": [_signed(new[0], _resign(person, new) | {"single_person": False})],
    }
    response = await _rotate(env, new[1], resigned)
    assert response.status_code == 409, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "resigned_records_incomplete"
    assert detail["missing"]["member_custody"] == [custody["certificate_id"]]
    assert detail["extra"]["member_custody"] == [extra_cert]
    assert detail["changed"]["member_person"] == [person["certificate_id"]]
    assert await _team_key(env) == old_key
    read = await env.client.get(f"{BASE}/certificates/{custody['certificate_id']}/custody")
    assert read.json()["record"] == custody


@pytest.mark.asyncio
async def test_resigned_records_must_be_signed_by_the_new_key_and_newer(controller_app):
    env = controller_app
    custodian, custody, person = await _team_with_records(env)
    new = keypair()
    old_signed = {
        "team_custodians": [_signed(env.team[0], _resign(custodian, new))],
        "member_custody": [_signed(new[0], _resign(custody, new))],
        "member_person": [_signed(new[0], _resign(person, new))],
    }
    assert (await _rotate(env, new[1], old_signed)).status_code == 422
    not_newer = {
        "team_custodians": [_signed(new[0], dict(custodian, team_did_key=new[1]))],
        "member_custody": [_signed(new[0], _resign(custody, new))],
        "member_person": [_signed(new[0], _resign(person, new))],
    }
    refused = await _rotate(env, new[1], not_newer)
    assert refused.status_code == 409
    assert refused.json()["detail"]["changed"]["team_custodians"] == [custodian["custodian_id"]]
    assert await _team_key(env) == env.team[1]


@pytest.mark.asyncio
async def test_an_oversize_rotation_is_413(controller_app):
    env = controller_app
    env.app.state.rotate_max_body_bytes = 256
    custodian, custody, person = await _team_with_records(env)
    new = keypair()
    resigned = {
        "team_custodians": [_signed(new[0], _resign(custodian, new))],
        "member_custody": [_signed(new[0], _resign(custody, new))],
        "member_person": [_signed(new[0], _resign(person, new))],
    }
    response = await _rotate(env, new[1], resigned)
    assert response.status_code == 413, response.text
    assert await _team_key(env) == env.team[1]


@pytest.mark.asyncio
async def test_a_rotation_without_resigned_records_still_succeeds_and_leaves_old_key_records(controller_app):
    env = controller_app
    custodian, _, _ = await _team_with_records(env)
    new = keypair()
    response = await _rotate(env, new[1])
    assert response.status_code == 200, response.text
    stored = (await env.client.get(f"{BASE}/custodians/{custodian['custodian_id']}")).json()
    assert stored["record"]["team_did_key"] == env.team[1]


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", ["overwrite", "late-insert"])
async def test_a_publish_waits_for_a_rotation_in_progress_and_then_refuses_the_old_key(controller_app, scenario):
    import asyncio

    env = controller_app
    cert = await register_certificate(env)
    first = _custodian(env, issued_at=_now(-30))
    assert (await publish_custodian(env, first)).status_code == 200
    if scenario == "overwrite":
        path, racing = f"{BASE}/custodians/custodian.example", publish_custodian(env, _custodian(env, issued_at=_now(-1)))
    else:
        path, racing = f"{BASE}/certificates/{cert['certificate_id']}/person", publish_person(env, _person(env, cert))
    before = await env.client.get(path)
    new = keypair()
    async with env.db.transaction() as tx:
        # Holds the team row the way rotate_team_key does, then swaps the key.
        await tx.fetch_one("SELECT team_uuid FROM {{tables.teams}} WHERE name = 'base' FOR UPDATE")
        publish = asyncio.create_task(racing)
        await asyncio.sleep(0.3)
        assert not publish.done(), "the publish must wait for the rotation's team lock"
        await tx.execute("UPDATE {{tables.teams}} SET team_did_key = $1 WHERE name = 'base'", new[1])
    response = await publish
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "team_key_changed"
    after = await env.client.get(path)
    assert (after.status_code, after.content) == (before.status_code, before.content)


@pytest.mark.asyncio
async def test_an_oversize_rotation_is_refused_before_the_body_is_parsed(controller_app):
    env = controller_app
    env.app.state.rotate_max_body_bytes = 64
    new = keypair()
    claims = {"domain": "local", "operation": "rotate_team_key", "name": "base", "new_team_did_key": new[1]}
    response = await send(env, "POST", f"{BASE}/rotate", claims, {"new_team_did_key": new[1], "pad": "x" * 200})
    assert response.status_code == 413, response.text
