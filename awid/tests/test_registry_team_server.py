"""Public SDK team-server operations against AWID's real routes and database."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
import pytest_asyncio
from nacl.signing import SigningKey

from awid import team_server_record
from awid.did import did_from_public_key
from awid.registry import RegistryClient, RegistryError
from awid.signing import sign_message
from awid_service.testing import (
    REGISTRY_URL,
    SERVICE_TOKEN,
    running_registry,
    signed_team_server_record,
)

VECTOR = json.loads(
    (Path(__file__).parents[2] / "docs/vectors/team-server-record-v1.json").read_text()
)
TEAM_ID = "ops:publisher.example"
DOMAIN = "publisher.example"
NAME = "ops"
SERVER_URL = "https://coord.publisher.example/api"


@pytest_asyncio.fixture
async def database_url(test_db_factory):
    return (await test_db_factory.create_db(suffix="team_server_sdk")).config.get_dsn()


@pytest.mark.parametrize("case", VECTOR["valid"], ids=lambda case: case["name"])
def test_builder_and_signer_match_go_vector(case):
    expected = case["record"]
    issued_at = datetime.fromisoformat(expected["issued_at"].replace("Z", "+00:00"))
    record = team_server_record.build_team_server_record(
        expected["team_id"], expected["team_did_key"], expected["server_url"], issued_at
    )
    assert record == expected
    assert team_server_record.record_signing_bytes(record) == base64.b64decode(case["signing_bytes_b64"])
    assert team_server_record.sign_team_server_record(
        bytes.fromhex(VECTOR["team_key_seed_hex"]), record
    ) == case["signature"]


def test_builder_formats_utc_seconds_like_go():
    case = VECTOR["valid"][0]
    local = datetime(2026, 1, 20, 12, 0, 0, 123456, tzinfo=timezone(timedelta(hours=2)))
    assert team_server_record.build_team_server_record(
        VECTOR["team_id"], VECTOR["team_did_key"], case["record"]["server_url"], local
    ) == case["record"]


@pytest.mark.asyncio
@pytest.mark.parametrize("visibility", ["public", "private"])
async def test_publish_read_and_idempotent_retry(database_url, visibility):
    key = SigningKey.generate()
    did = did_from_public_key(bytes(key.verify_key))
    async with running_registry(database_url) as registry:
        await registry.add_team(TEAM_ID, did, visibility=visibility)
        client = RegistryClient(registry_url=REGISTRY_URL, transport=registry.transport)
        try:
            assert await client.get_team_server_record(DOMAIN, NAME) is None
            record = team_server_record.build_team_server_record(
                TEAM_ID, did, SERVER_URL, datetime.now(UTC)
            )
            signature = team_server_record.sign_team_server_record(bytes(key), record)
            expected = {"record": record, "signature": signature}
            assert await client.publish_team_server_record(DOMAIN, NAME, record, signature) == expected
            assert await client.get_team_server_record(DOMAIN, NAME) == expected
            assert await client.publish_team_server_record(DOMAIN, NAME, record, signature) == expected
            verified = team_server_record.verify_team_server_record(
                record, signature, team_id=TEAM_ID, current_team_did_key=did, now=datetime.now(UTC)
            )
            assert verified.server_url == SERVER_URL
            assert all("Authorization" not in request.headers for request in registry.transport.calls)
        finally:
            await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["unknown", "no-record", "deleted"])
async def test_get_missing_record_is_none(database_url, state):
    key = SigningKey.generate()
    async with running_registry(database_url) as registry:
        if state != "unknown":
            await registry.add_team(TEAM_ID, did_from_public_key(bytes(key.verify_key)))
        if state == "deleted":
            await registry.publish_team_server(TEAM_ID, key, server_url=SERVER_URL)
            await registry.db.execute(
                "UPDATE {{tables.teams}} SET deleted_at = now() WHERE domain = $1 AND name = $2",
                DOMAIN, NAME,
            )
        client = RegistryClient(registry_url=REGISTRY_URL, transport=registry.transport)
        try:
            assert await client.get_team_server_record(DOMAIN, NAME) is None
        finally:
            await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure,status,detail",
    [
        ("unknown-team", 404, "Team server record not found"),
        ("wrong-signer", 404, "Team server record not found"),
        ("old-record", 409, "not_newer"),
        ("invalid-url", 422, "server_url_invalid"),
        ("future-record", 422, "issued_at_in_future"),
    ],
)
async def test_publish_preserves_typed_refusals(database_url, failure, status, detail):
    key = SigningKey.generate()
    did = did_from_public_key(bytes(key.verify_key))
    issued_at = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=10)
    original = signed_team_server_record(TEAM_ID, key, server_url=SERVER_URL, issued_at=issued_at)
    async with running_registry(database_url) as registry:
        await registry.add_team(TEAM_ID, did)
        await registry.publish_team_server(TEAM_ID, key, server_url=SERVER_URL, issued_at=issued_at)
        record = {**original["record"], "issued_at": (issued_at + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")}
        signer, target_name = key, NAME
        if failure == "unknown-team":
            target_name = "missing"
            record["team_id"] = f"missing:{DOMAIN}"
        elif failure == "wrong-signer":
            signer = SigningKey.generate()
        elif failure == "old-record":
            record["issued_at"] = (issued_at - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        elif failure == "invalid-url":
            record["server_url"] = "http://coord.publisher.example"
        elif failure == "future-record":
            record["issued_at"] = (datetime.now(UTC) + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        signature = sign_message(bytes(signer), team_server_record.record_signing_bytes(record))
        client = RegistryClient(registry_url=REGISTRY_URL, transport=registry.transport)
        try:
            with pytest.raises(RegistryError) as refused:
                await client.publish_team_server_record(DOMAIN, target_name, record, signature)
            assert refused.value.status_code == status
            assert refused.value.detail == detail
            assert await client.get_team_server_record(DOMAIN, NAME) == original
        finally:
            await client.aclose()


@pytest.mark.asyncio
async def test_methods_follow_domain_resolver_without_leaking_home_service_token(database_url):
    key = SigningKey.generate()
    resolved_domains = []

    async def resolve(domain):
        resolved_domains.append(domain)
        return "https://foreign.registry.example"

    body = signed_team_server_record(
        TEAM_ID, key, server_url=SERVER_URL, issued_at=datetime.now(UTC)
    )
    async with running_registry(database_url) as registry:
        await registry.add_team(TEAM_ID, did_from_public_key(bytes(key.verify_key)))
        client = RegistryClient(
            registry_url=REGISTRY_URL, transport=registry.transport,
            domain_registry_resolver=resolve, service_token=SERVICE_TOKEN,
        )
        try:
            assert await client.publish_team_server_record(DOMAIN, NAME, **body) == body
            assert await client.get_team_server_record(DOMAIN, NAME) == body
            assert resolved_domains == [DOMAIN, DOMAIN]
            assert [(request.method, request.url.host, request.url.path) for request in registry.transport.calls] == [
                (method, "foreign.registry.example", f"/v1/namespaces/{DOMAIN}/teams/{NAME}/server")
                for method in ("PUT", "GET")
            ]
            assert json.loads(registry.transport.calls[0].content) == body
            assert all("X-AWID-Service-Token" not in request.headers for request in registry.transport.calls)
        finally:
            await client.aclose()
