"""Reading a team's stored team-key-signed records in pages, for key rotation.

Real AWID on PostgreSQL and Redis. Only the team key or the trusted service
token may read, whatever the team's visibility, and every refusal looks like an
unknown team.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from awid.attestation_records import sign_record
from awid.pagination import MAX_LIMIT
from awid.signing import canonical_json_bytes, sign_message
from awid.team_server_record import record_signing_bytes
from awid.credential_policy import policy_signing_bytes
from test_credential_lifetimes_http import policy_body, set_policy
from test_attestation_record_routes import (
    BASE,
    TEAM_ID,
    _custodian,
    _custody,
    _now,
    _person,
    publish_custodian,
    publish_custody,
    publish_person,
    register_certificate,
)
from test_controller_request_v2_http import controller_app, keypair, send  # noqa: F401

RECORDS = f"{BASE}/signed-records"


def _path_signed(signer, path: str) -> dict[str, str]:
    key, did = signer
    ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    sig = sign_message(key, f"{ts}\nGET\n{path}".encode("utf-8"))
    return {"Authorization": f"DIDKey {did} {sig}", "X-AWEB-Timestamp": ts}


async def _read(env, *, signer=None, query: str = "", headers=None):
    signed = _path_signed(signer or env.team, RECORDS) if signer is not False else {}
    return await env.client.get(RECORDS + query, headers={**signed, **(headers or {})})


async def _read_all(env, *, limit: int) -> tuple[list[dict], int]:
    items, cursor, pages = [], None, 0
    while True:
        query = f"?limit={limit}" + (f"&cursor={cursor}" if cursor else "")
        response = await _read(env, query=query)
        assert response.status_code == 200, response.text
        page = response.json()
        items.extend(page["items"])
        pages += 1
        if not page["has_more"]:
            assert page["next_cursor"] is None
            return items, pages
        cursor = page["next_cursor"]


async def _publish_server(env):
    record = {"v": 1, "type": "aweb.team-server", "team_id": TEAM_ID, "team_did_key": env.team[1],
              "server_url": "https://coord.example/api", "issued_at": _now(-30)}
    signed = {"record": record, "signature": sign_message(env.team[0], record_signing_bytes(record))}
    response = await env.client.put(f"{BASE}/server", json=signed)
    assert response.status_code == 200, response.text
    return signed


async def _revoke(env, certificate_id: str) -> None:
    claims = {"domain": "local", "operation": "revoke_certificate", "team_name": "base",
              "certificate_id": certificate_id}
    revoked = await send(env, "POST", f"{BASE}/certificates/revoke", claims,
                         {"certificate_id": certificate_id}, signer=env.team)
    assert revoked.status_code == 200, revoked.text


async def _every_kind(env):
    server = await _publish_server(env)
    policy = policy_body(env, identity_grant=3600)
    assert (await set_policy(env, policy)).status_code == 200
    custodian = _custodian(env)
    assert (await publish_custodian(env, custodian)).status_code == 200
    standby = _custodian(env, custodian_id="standby.example")
    assert (await publish_custodian(env, standby)).status_code == 200
    alice, bob = await register_certificate(env), await register_certificate(env)
    custody = _custody(env, alice)
    assert (await publish_custody(env, custody)).status_code == 200
    person = _person(env, bob)
    assert (await publish_person(env, person)).status_code == 200
    await _revoke(env, alice["certificate_id"])
    return server, [custodian, standby], custody, person, policy


@pytest.mark.asyncio
async def test_the_controller_reads_every_kind_across_pages_including_revoked_certificates(controller_app):
    env = controller_app
    server, custodians, custody, person, policy = await _every_kind(env)

    items, pages = await _read_all(env, limit=2)

    assert pages == 3
    by_kind = {}
    for item in items:
        by_kind.setdefault(item["kind"], []).append(item)
    assert by_kind["team_server"] == [{"kind": "team_server", "key": None, **server}]
    assert [i["key"] for i in by_kind["team_custodians"]] == ["custodian.example", "standby.example"]
    assert [i["record"] for i in by_kind["team_custodians"]] == custodians
    assert [(i["key"], i["record"]) for i in by_kind["member_custody"]] == [(custody["certificate_id"], custody)]
    assert [(i["key"], i["record"]) for i in by_kind["member_person"]] == [(person["certificate_id"], person)]
    assert by_kind["team_credential_policy"] == [{"kind": "team_credential_policy", "key": None, **policy}]
    for item in items:
        if item["kind"] == "team_credential_policy":
            assert item["signature"] == sign_message(env.team[0], policy_signing_bytes(item["record"]))
        elif item["kind"] != "team_server":
            assert item["signature"] == sign_record(env.team[0], item["record"])


@pytest.mark.asyncio
async def test_an_unsigned_foreign_or_revoked_read_looks_like_an_unknown_team(controller_app):
    env = controller_app
    await _every_kind(env)
    unknown = await env.client.get("/v1/namespaces/local/teams/nobody/signed-records",
                                   headers=_path_signed(env.team, "/v1/namespaces/local/teams/nobody/signed-records"))
    refusals = [
        await _read(env, signer=False),
        await _read(env, signer=keypair()),
        await env.client.get(RECORDS, headers={"Authorization": "DIDKey nonsense", "X-AWEB-Timestamp": "x"}),
    ]
    assert unknown.status_code == 404
    for refusal in refusals:
        assert (refusal.status_code, refusal.json()) == (unknown.status_code, unknown.json())


@pytest.mark.asyncio
async def test_only_the_team_key_and_the_trusted_service_may_read(controller_app):
    env = controller_app
    member = keypair()
    await _member_certificate(env, member)
    unknown = await env.client.get("/v1/namespaces/local/teams/nobody/signed-records")
    refused = await _read(env, signer=member)
    assert (refused.status_code, refused.json()) == (404, unknown.json())
    assert (await _read(env)).status_code == 200
    token = "signed-records-service-token-0123456789"
    env.app.state.awid_service_token = token
    assert (await _read(env, signer=False, headers={"X-AWID-Service-Token": token})).status_code == 200


async def _member_certificate(env, member) -> dict:
    from test_controller_request_v2_http import certificate_body

    body = certificate_body(env, alias="reader", member=member)
    claims = {"domain": "local", "operation": "register_certificate", "team_name": "base",
              "certificate_id": body["certificate_id"]}
    response = await send(env, "POST", f"{BASE}/certificates", claims, body, signer=env.team)
    assert response.status_code == 200, response.text
    return body


@pytest.mark.asyncio
async def test_a_revoked_member_is_refused_like_an_unknown_team(controller_app):
    env = controller_app
    member = keypair()
    body = await _member_certificate(env, member)
    await _revoke(env, body["certificate_id"])
    refused = await _read(env, signer=member)
    unknown = await env.client.get("/v1/namespaces/local/teams/nobody/signed-records")
    assert (refused.status_code, refused.json()) == (404, unknown.json())


@pytest.mark.asyncio
async def test_bad_pagination_is_refused(controller_app):
    env = controller_app
    assert (await _read(env, query="?cursor=not-a-cursor")).status_code == 400
    forged = await _read(env, query="?cursor=eyJyYW5rIjoiMSJ9")  # {"rank":"1"}
    assert forged.status_code == 400


@pytest.mark.asyncio
async def test_the_read_has_its_own_rate_limit_bucket(controller_app, monkeypatch):
    from awid import ratelimit

    env = controller_app
    monkeypatch.setitem(ratelimit._BUCKET_DEFAULTS, "attestation_record_list", (1, 3600))
    assert (await _read(env)).status_code == 200
    limited = await _read(env)
    assert limited.status_code == 429, limited.text
    assert (await env.client.get(f"{BASE}/custodians/none")).status_code == 404


@pytest.mark.asyncio
async def test_five_hundred_records_page_at_the_production_limit(controller_app):
    env = controller_app
    team_uuid = await env.db.fetch_value(
        "SELECT team_uuid FROM {{tables.teams}} WHERE domain = 'local' AND name = 'base'"
    )
    policy = policy_body(env, identity_grant=3600)
    assert (await set_policy(env, policy)).status_code == 200
    expected = []
    for index in range(500):
        record = _custodian(env, custodian_id=f"c{index:03d}.example", issued_at=_now(-60))
        signature = sign_record(env.team[0], record)
        await env.db.execute(
            "INSERT INTO {{tables.team_custodians}} (team_uuid, custodian_id, record_json, signature, team_did_key, issued_at)"
            " VALUES ($1, $2, $3, $4, $5, now())",
            team_uuid, record["custodian_id"], canonical_json_bytes(record).decode(), signature, record["team_did_key"],
        )
        expected.append(record["custodian_id"])

    items, pages = await _read_all(env, limit=MAX_LIMIT)

    assert pages == 3
    assert [item["key"] for item in items[:-1]] == expected
    assert items[-1] == {"kind": "team_credential_policy", "key": None, **policy}
    assert len({json.dumps(item, sort_keys=True) for item in items}) == 501
