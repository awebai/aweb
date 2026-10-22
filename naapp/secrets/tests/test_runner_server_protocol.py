"""S0 cases exercised through the production server verifier and durable replay store."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from aweb_naapp.nonces import apply_nonce_migrations, consume_nonce

from aweb_secrets.runner_protocol import (
    RunnerRefused,
    consume_request,
    parse_request,
    verify_request,
)

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
            await consume_request(tx, checked, clock=lambda: at(case["now"]))
        return checked

    if "error" in case["expected"]:
        with pytest.raises(RunnerRefused) as refused:
            await receive()
        assert refused.value.code == case["expected"]["error"]
    else:
        checked = await receive()
        assert (
            await db.fetch_value(
                "SELECT count(*) FROM {{tables.scoped_nonces}} WHERE scope=$1 AND nonce=$2",
                "runner:" + checked.runner_id,
                checked.nonce,
            )
            == 1
        )


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


async def test_only_verified_requests_consume_and_pruning_keeps_skew_pad(db):
    from datetime import timedelta

    from aweb_secrets.runner_protocol import prune_request_nonces

    valid = next(c for c in VECTOR["requests"] if c["name"] == "valid")
    parsed = parse_request(valid["header"])
    async with db.transaction() as tx:
        with pytest.raises(TypeError):
            await consume_request(tx, parsed, clock=lambda: at(valid["now"]))
        assert await tx.fetch_value("SELECT count(*) FROM {{tables.scoped_nonces}}") == 0
        await consume_nonce(
            tx, scope="runner:" + parsed.runner_id, nonce=parsed.nonce, expires_at=parsed.expires_at
        )
        assert await prune_request_nonces(tx, now=parsed.expires_at + timedelta(seconds=120)) == 0
        assert await prune_request_nonces(tx, now=parsed.expires_at + timedelta(seconds=121)) == 1
