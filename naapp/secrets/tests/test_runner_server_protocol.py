"""S0 cases exercised through the production server verifier and durable replay store."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from aweb_naapp.nonces import apply_nonce_migrations, consume_nonce

from aweb_secrets.runner_protocol import RunnerRefused, parse_request, verify_request

VECTOR = json.loads(
    (Path(__file__).parents[3] / "docs/vectors/secrets-runner-protocol-v1.json").read_text()
)


def at(value):
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


@pytest.fixture
async def db(test_db_factory):
    database = await test_db_factory.create_db(suffix="runner_protocol")
    await apply_nonce_migrations(database)
    return database


@pytest.mark.parametrize("case", VECTOR["requests"], ids=lambda case: case["name"])
async def test_server_consumes_request_vectors(db, case):
    from aweb_naapp.hooks.strictjson import decode_base64url

    async def receive():
        parsed = parse_request(case["header"])
        checked = verify_request(
            parsed,
            registered_kid=case["deployment"]["runners"].get(parsed.runner_id),
            origin=case["deployment"]["origin"],
            method=case["received"]["method"],
            path=case["received"]["path"],
            body=decode_base64url(case["received"]["body_b64url"], "body"),
            now=at(case["now"]),
        )
        async with db.transaction() as tx:
            for runner_id, nonce in case["deployment"]["seen_nonces"]:
                await consume_nonce(
                    tx, scope="runner:" + runner_id, nonce=nonce, expires_at=checked.expires_at
                )
            if not await consume_nonce(
                tx,
                scope="runner:" + checked.runner_id,
                nonce=checked.nonce,
                expires_at=checked.expires_at,
            ):
                raise RunnerRefused("runner_request_replayed")
        return checked

    if "error" in case["expected"]:
        with pytest.raises(RunnerRefused) as refused:
            await receive()
        assert refused.value.code == case["expected"]["error"]
    else:
        checked = await receive()
        assert checked.runner_id == parsed_id(case)


def parsed_id(case):
    return parse_request(case["header"]).runner_id


def test_server_assignment_matches_s0_signed_bytes():
    from nacl.signing import SigningKey

    from aweb_secrets.runner_protocol import sign_assignment
    from tests.test_runner_protocol_vectors import verify_assignment

    case = next(c for c in VECTOR["assignments"] if c["name"] == "valid")
    expected = json.loads(case["body_json"])
    p = expected["assignment"]
    result = sign_assignment(
        key=SigningKey(bytes.fromhex(VECTOR["keys"]["service"]["seed_hex"])),
        origin=p["origin"],
        runner_id=p["runner_id"],
        dispatch_id=p["dispatch_id"],
        job_id=p["job_id"],
        job_digest=p["job_digest"],
        params=expected["params"],
        credentials=expected["credentials"],
        issued_at=at(p["issued_at"]),
        expires_at=at(p["expires_at"]),
    )
    assert result == expected
    assert verify_assignment(dict(case, body_json=json.dumps(result))) == p
