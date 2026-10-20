"""aweb.team-server/1 records against the real registry and database."""
import base64
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from awid.did import did_from_public_key, generate_keypair
from awid.signing import canonical_json_bytes, sign_message
from awid.team_server_record import (
    TeamServerRecordError,
    record_signing_bytes,
    verify_team_server_record,
)
from conftest import build_signed_headers as _sign
from test_team_visibility_enforcement import _create_team, _setup_namespace

VECTOR = json.loads(
    (Path(__file__).parents[2] / "docs" / "vectors" / "team-server-record-v1.json").read_text()
)
NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
VECTOR_DOMAIN = "vector-server.example"


def _server_path(domain: str, name: str) -> str:
    return f"/v1/namespaces/{domain}/teams/{name}/server"


def _signed_record(seed: bytes, **fields) -> dict:
    record = {"v": 1, "type": "aweb.team-server", **fields}
    return {"record": record, "signature": sign_message(seed, record_signing_bytes(record))}


def _record_fields(team: dict, team_did: str, *, issued_at: str, server_url: str = "https://coord.example/api"):
    return {
        "team_id": team["team_id"],
        "team_did_key": team_did,
        "server_url": server_url,
        "issued_at": issued_at,
    }


@pytest.mark.parametrize("case", VECTOR["valid"], ids=lambda case: case["name"])
def test_vector_valid_records_verify_against_the_current_team_key(case):
    assert base64.b64decode(case["signing_bytes_b64"]) == record_signing_bytes(case["record"])
    assert record_signing_bytes(case["record"]).startswith(VECTOR["domain_prefix"].encode())
    verified = verify_team_server_record(
        case["record"],
        case["signature"],
        team_id=VECTOR["team_id"],
        current_team_did_key=VECTOR["team_did_key"],
        now=NOW,
    )
    assert verified.server_url == case["record"]["server_url"]


@pytest.mark.parametrize(
    "case",
    [case for case in VECTOR["invalid"] if "requires_stored" not in case],
    ids=lambda case: case["name"],
)
def test_vector_invalid_records_are_refused_with_their_code(case):
    with pytest.raises(TeamServerRecordError) as refused:
        verify_team_server_record(
            case["record"],
            case["signature"],
            team_id=VECTOR["team_id"],
            current_team_did_key=VECTOR["team_did_key"],
            now=NOW,
        )
    assert refused.value.code == case["code"]


@pytest.mark.asyncio
async def test_vector_cases_over_http(client, controller_identity, awid_db_infra):
    ns_key, ns_did = controller_identity
    await _setup_namespace(client, ns_key, ns_did, VECTOR_DOMAIN)
    await _create_team(client, ns_key, ns_did, VECTOR_DOMAIN, "ops")
    await awid_db_infra.get_manager("aweb").execute(
        "UPDATE {{tables.teams}} SET team_did_key = $1 WHERE domain = $2 AND name = 'ops'",
        VECTOR["team_did_key"],
        VECTOR_DOMAIN,
    )
    path = _server_path(VECTOR_DOMAIN, "ops")

    for case in VECTOR["valid"]:
        response = await client.put(path, json={"record": case["record"], "signature": case["signature"]})
        assert response.status_code == 200, response.text
    for case in VECTOR["invalid"]:
        response = await client.put(path, json={"record": case["record"], "signature": case["signature"]})
        assert response.status_code == case["http_status"], (case["name"], response.text)
        assert response.json()["detail"] == case["http_detail"]

    latest = VECTOR["valid"][-1]
    response = await client.get(path)
    assert response.status_code == 200, response.text
    assert response.json() == {"record": latest["record"], "signature": latest["signature"]}


@pytest.mark.asyncio
@pytest.mark.parametrize("visibility", ["public", "private"])
async def test_anonymous_read_returns_the_stored_record(client, controller_identity, visibility):
    ns_key, ns_did = controller_identity
    domain = f"{visibility}-server.example"
    await _setup_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, team = await _create_team(client, ns_key, ns_did, domain, "ops", visibility=visibility)
    body = _signed_record(team_key, **_record_fields(team, team_did, issued_at="2026-01-20T10:00:00Z"))

    put = await client.put(_server_path(domain, "ops"), json=body)
    get = await client.get(_server_path(domain, "ops"))

    assert put.status_code == 200, put.text
    assert get.status_code == 200, get.text
    assert get.json() == body
    verified = verify_team_server_record(
        get.json()["record"], get.json()["signature"],
        team_id=team["team_id"], current_team_did_key=team_did, now=NOW,
    )
    assert verified.server_url == "https://coord.example/api"


@pytest.mark.asyncio
async def test_republishing_the_same_record_is_idempotent(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "idempotent-server.example"
    await _setup_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, team = await _create_team(client, ns_key, ns_did, domain, "ops")
    body = _signed_record(team_key, **_record_fields(team, team_did, issued_at="2026-01-20T10:00:00Z"))

    first = await client.put(_server_path(domain, "ops"), json=body)
    again = await client.put(_server_path(domain, "ops"), json=body)

    assert first.status_code == 200, first.text
    assert again.status_code == 200, again.text


@pytest.mark.asyncio
async def test_unknown_team_missing_record_and_deleted_team_have_identical_404(
    client, controller_identity, awid_db_infra
):
    ns_key, ns_did = controller_identity
    domain = "missing-server.example"
    await _setup_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, team = await _create_team(client, ns_key, ns_did, domain, "ops")
    await _create_team(client, ns_key, ns_did, domain, "bare")
    await _create_team(client, ns_key, ns_did, domain, "gone")
    await client.put(
        _server_path(domain, "gone"),
        json=_signed_record(team_key, **_record_fields(team, team_did, issued_at="2026-01-20T10:00:00Z")),
    )
    await awid_db_infra.get_manager("aweb").execute(
        "UPDATE {{tables.teams}} SET deleted_at = now() WHERE domain = $1 AND name = 'gone'", domain
    )

    responses = [
        await client.get(_server_path(domain, "missing")),
        await client.get(_server_path(domain, "bare")),
        await client.get(_server_path(domain, "gone")),
        await client.get(_server_path("unknown-server.example", "ops")),
    ]

    assert all(response.status_code == 404 for response in responses)
    assert len({response.content for response in responses}) == 1
    assert responses[0].json() == VECTOR["not_found"]["response"]


@pytest.mark.asyncio
async def test_rotation_leaves_the_record_refused_until_re_signed(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "rotate-server.example"
    await _setup_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, team = await _create_team(client, ns_key, ns_did, domain, "ops")
    path = _server_path(domain, "ops")
    await client.put(path, json=_signed_record(team_key, **_record_fields(team, team_did, issued_at="2026-01-20T10:00:00Z")))
    new_key, new_pub = generate_keypair()
    new_did = did_from_public_key(new_pub)
    rotated = await client.post(
        f"/v1/namespaces/{domain}/teams/ops/rotate",
        json={"new_team_did_key": new_did},
        headers=_sign(ns_key, ns_did, domain=domain, operation="rotate_team_key", name="ops", new_team_did_key=new_did),
    )
    assert rotated.status_code == 200, rotated.text

    stored = (await client.get(path)).json()
    with pytest.raises(TeamServerRecordError) as refused:
        verify_team_server_record(
            stored["record"], stored["signature"], team_id=team["team_id"], current_team_did_key=new_did, now=NOW,
        )
    old_key_newer = await client.put(
        path, json=_signed_record(team_key, **_record_fields(team, team_did, issued_at="2026-01-20T11:00:00Z")),
    )
    re_signed = await client.put(
        path, json=_signed_record(new_key, **_record_fields(team, new_did, issued_at="2026-01-20T11:00:00Z")),
    )

    assert refused.value.code == "team_server_key_mismatch"
    assert old_key_newer.status_code == 404, old_key_newer.text
    assert re_signed.status_code == 200, re_signed.text
    current = (await client.get(path)).json()
    verify_team_server_record(
        current["record"], current["signature"], team_id=team["team_id"], current_team_did_key=new_did, now=NOW,
    )


@pytest.mark.asyncio
async def test_far_future_record_is_refused_against_the_registry_clock(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "future-server.example"
    await _setup_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, team = await _create_team(client, ns_key, ns_did, domain, "ops")
    ahead = datetime.now(timezone.utc).replace(microsecond=0).timestamp() + 600
    issued_at = datetime.fromtimestamp(ahead, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    response = await client.put(
        _server_path(domain, "ops"),
        json=_signed_record(team_key, **_record_fields(team, team_did, issued_at=issued_at)),
    )

    assert response.status_code == 422, response.text
    assert response.json()["detail"] == "issued_at_in_future"


@pytest.mark.parametrize(
    "server_url",
    [
        "https://coord.example/api/",
        "https://Coord.example/api",
        "https://coord.example:443/api",
        "https://coord.example/api?x=1",
        "https://user@coord.example/api",
        "https://192.0.2.10/api",
        "ftp://coord.example",
    ],
)
def test_non_canonical_or_disallowed_server_urls_are_refused(server_url):
    seed = bytes.fromhex("33" * 32)
    team_did = did_from_public_key(bytes(SigningKey(seed).verify_key))
    body = _signed_record(seed, team_id="ops:url.example", team_did_key=team_did, server_url=server_url, issued_at="2026-01-20T10:00:00Z")

    with pytest.raises(TeamServerRecordError) as refused:
        verify_team_server_record(
            body["record"], body["signature"], team_id="ops:url.example", current_team_did_key=team_did, now=NOW,
        )
    assert refused.value.code == "server_url_invalid"


def test_records_with_extra_or_missing_fields_are_refused():
    seed = bytes.fromhex("33" * 32)
    team_did = did_from_public_key(bytes(SigningKey(seed).verify_key))
    fields = {"team_id": "ops:url.example", "team_did_key": team_did, "server_url": "https://coord.example", "issued_at": "2026-01-20T10:00:00Z"}
    extra = _signed_record(seed, **fields, note="x")
    missing = {"v": 1, "type": "aweb.team-server", **{k: v for k, v in fields.items() if k != "issued_at"}}
    missing_body = {"record": missing, "signature": sign_message(seed, b"aweb.team-server/1\n" + canonical_json_bytes(missing))}

    for body in (extra, missing_body):
        with pytest.raises(TeamServerRecordError) as refused:
            verify_team_server_record(
                body["record"], body["signature"], team_id="ops:url.example", current_team_did_key=team_did, now=NOW,
            )
        assert refused.value.code == "record_invalid"


@pytest.mark.asyncio
@pytest.mark.parametrize("app_env, expected", [("development", 200), ("production", 422)])
async def test_localhost_http_server_is_accepted_only_in_development(
    client, controller_identity, monkeypatch, app_env, expected
):
    ns_key, ns_did = controller_identity
    domain = f"{app_env}-local-server.example"
    await _setup_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, team = await _create_team(client, ns_key, ns_did, domain, "ops")
    monkeypatch.setenv("APP_ENV", app_env)

    response = await client.put(
        _server_path(domain, "ops"),
        json=_signed_record(
            team_key,
            **_record_fields(team, team_did, issued_at="2026-01-20T10:00:00Z", server_url="http://localhost:8000"),
        ),
    )

    assert response.status_code == expected, response.text


@pytest.mark.asyncio
async def test_unverifiable_records_answer_like_an_unknown_team(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "probe-server.example"
    await _setup_namespace(client, ns_key, ns_did, domain)
    _, team_did, team = await _create_team(client, ns_key, ns_did, domain, "ops", visibility="private")
    stranger_key, stranger_pub = generate_keypair()
    garbage = [
        {"record": {"anything": 1}, "signature": "AAAA"},
        _signed_record(stranger_key, **_record_fields(team, did_from_public_key(stranger_pub), issued_at="2026-01-20T10:00:00Z")),
        {"record": _record_fields(team, team_did, issued_at="2026-01-20T10:00:00Z") | {"v": 1, "type": "aweb.team-server"}, "signature": "AAAA"},
    ]

    unknown = await client.put(_server_path(domain, "missing"), json=garbage[0])
    probes = [await client.put(_server_path(domain, "ops"), json=body) for body in garbage]

    assert unknown.status_code == 404
    assert all(probe.status_code == 404 for probe in probes)
    assert {probe.content for probe in probes} == {unknown.content}


@pytest.mark.asyncio
async def test_publish_body_is_bounded(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "bounded-server.example"
    await _setup_namespace(client, ns_key, ns_did, domain)
    await _create_team(client, ns_key, ns_did, domain, "ops")

    response = await client.put(
        _server_path(domain, "ops"),
        content=json.dumps({"record": {"pad": "x" * 9000}, "signature": "AAAA"}),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413, response.text
