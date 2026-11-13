"""Signed installation GET through real auth/SDK code, in-memory HTTP/storage.

Only registry HTTP and local persistence are doubles; no DB/Redis or sockets.
"""

import asyncio
import base64
import hashlib
import json
import math
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI, HTTPException
from nacl.signing import SigningKey

from aweb.identity_binding import observe_identity_binding
from aweb.routes import apps
from awid.did import did_from_public_key, stable_id_from_did_key
from awid.registry import RegistryClient
from awid.registry_types import RegistryThrottled
from awid.signing import canonical_json_bytes, sign_message

pytestmark = pytest.mark.asyncio

TEAM = "lfteam:lf.test"
ORIGIN = "https://aweb.lf.test"
PATH = "/v1/apps/lfteam-secrets/installation?team_id=lfteam%3Alf.test"


class Storage:
    def __init__(self, world):
        self.world = world

    def get_manager(self, name):
        assert name == "aweb"
        return self

    @asynccontextmanager
    async def transaction(self):
        yield self

    async def fetch_one(self, sql, *args):
        assert "FROM {{tables.agents}}" in sql
        return {
            "agent_id": self.world.agent_id,
            "certificate_id": "registered-cert",
            "did_aw": self.world.identity,
            "address": "",
        }

    async def execute(self, sql, *args):
        assert "UPDATE {{tables.agents}}" in sql
        return "UPDATE 1"


class Registry(RegistryClient):
    def __init__(self, world, transport):
        super().__init__(
            "http://registry.test", transport=transport, timeout_seconds=0.1
        )
        self.world = world

    async def get_team_public_key(self, domain, name):
        assert (domain, name) == ("lf.test", "lfteam")
        return self.world.team_did

    async def get_team_revocations(self, domain, name):
        return set()

    async def list_team_certificates(self, domain, name, *, active_only):
        assert not active_only
        return [SimpleNamespace(certificate_id="registered-cert")]


@pytest_asyncio.fixture
async def world(monkeypatch):
    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", "true")
    member, team = SigningKey.generate(), SigningKey.generate()
    value = SimpleNamespace(
        member=member,
        team=team,
        member_did=did_from_public_key(bytes(member.verify_key)),
        team_did=did_from_public_key(bytes(team.verify_key)),
        agent_id=uuid4(),
        status=429,
        retry_after="53",
        mismatched=False,
        registry_reads=0,
        installation_reads=0,
        installation=None,
    )
    value.identity = stable_id_from_did_key(value.member_did)

    async def registry_http(request):
        assert request.url.path == f"/v1/did/{value.identity}/key"
        value.registry_reads += 1
        if value.status != 200:
            headers = (
                {} if value.retry_after is None else {"Retry-After": value.retry_after}
            )
            return httpx.Response(
                value.status, headers=headers, json={"detail": "private upstream body"}
            )
        return httpx.Response(
            200,
            json={
                "did_aw": value.identity,
                "current_did_key": value.team_did
                if value.mismatched
                else value.member_did,
                "id_tree": {"enrolled": False},
            },
        )

    value.registry = Registry(value, httpx.MockTransport(registry_http))
    app = FastAPI()
    app.state.public_origin = ORIGIN
    app.state.awid_registry_client = value.registry
    app.state.db = Storage(value)
    app.include_router(apps.router)

    async def installation(tx, *, team_id, app_id):
        assert (team_id, app_id) == (TEAM, "lfteam-secrets")
        value.installation_reads += 1
        return value.installation

    monkeypatch.setattr(apps, "installation_view_on", installation)
    value.app = app
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url=ORIGIN
    ) as client:
        value.client = client
        try:
            yield value
        finally:
            await value.registry.aclose()


def signed_headers(world, *, forged=False):
    timestamp = datetime.now(UTC).isoformat()
    certificate = {
        "version": 1,
        "certificate_id": "registered-cert",
        "team_id": TEAM,
        "team_did_key": world.team_did,
        "member_did_key": world.member_did,
        "member_did_aw": world.identity,
        "member_address": "",
        "alias": "member",
        "identity_scope": "global",
        "issued_at": timestamp,
    }
    certificate["signature"] = sign_message(
        bytes(world.team), canonical_json_bytes(certificate)
    )
    payload = canonical_json_bytes(
        {
            "v": 2,
            "aud": ORIGIN,
            "team_id": TEAM,
            "timestamp": timestamp,
            "method": "GET",
            "path": PATH,
            "body_sha256": hashlib.sha256(b"").hexdigest(),
        }
    )
    signer = world.team if forged else world.member
    return {
        "Authorization": f"DIDKey {world.member_did} {sign_message(bytes(signer), payload)}",
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(payload).decode().rstrip("="),
        "X-AWID-Team-Certificate": base64.b64encode(
            json.dumps(certificate).encode()
        ).decode(),
    }


async def installation_get(world, **kwargs):
    return await world.client.get(PATH, headers=signed_headers(world, **kwargs))


async def test_authenticated_installation_throttle_preserves_hint_without_reading_installation(
    world,
):
    response = await installation_get(world)
    assert (response.status_code, response.json()) == (
        503,
        {"detail": "identity_binding_unavailable"},
    )
    assert response.headers.get("Retry-After") == "53"
    assert "private upstream body" not in response.text
    assert world.registry_reads == 1  # SDK does not sleep past its own .1s bound.
    assert world.installation_reads == 0
    assert not world.app.state.identity_binding_cache


async def test_generic_registry_failure_remains_503_without_hint(world):
    world.status = 503
    response = await installation_get(world)
    assert (response.status_code, response.json()) == (
        503,
        {"detail": "identity_binding_unavailable"},
    )
    assert "Retry-After" not in response.headers
    assert world.installation_reads == 0


async def test_identity_mismatch_remains_403_without_installation_read(world):
    world.status, world.mismatched = 200, True
    response = await installation_get(world)
    assert (response.status_code, response.json()) == (
        403,
        {"detail": "identity_binding_mismatch"},
    )
    assert "Retry-After" not in response.headers
    assert world.installation_reads == 0


async def test_authenticated_absent_installation_remains_404(world):
    world.status = 200
    response = await installation_get(world)
    assert response.status_code == 404, response.text
    assert "Retry-After" not in response.headers
    assert world.installation_reads == 1


async def test_forged_request_does_not_read_registry_or_installation(world):
    response = await installation_get(world, forged=True)
    assert response.status_code == 401
    assert world.registry_reads == world.installation_reads == 0


@pytest.mark.parametrize(
    "delay,header",
    [
        (53.2, "54"),
        (0, "1"),
        (1e300, str(math.ceil(1e300))),
        (None, None),
        (-1, None),
        (float("inf"), None),
        (float("nan"), None),
    ],
    ids=["fractional", "zero", "huge", "missing", "negative", "infinite", "nan"],
)
async def test_only_sanitized_throttle_hint_is_exposed(delay, header):
    class Throttled:
        async def resolve_key_fresh(self, identity):
            raise RegistryThrottled(
                retry_after_seconds=delay, attempts=1, reason="elapsed_budget"
            )

    with pytest.raises(HTTPException) as caught:
        await observe_identity_binding(
            Throttled(), did_key="did:key:subject", did_aw="did:aw:subject"
        )
    assert (caught.value.status_code, caught.value.detail) == (
        503,
        "identity_binding_unavailable",
    )
    assert (caught.value.headers or {}).get("Retry-After") == header


async def test_cancelled_registry_observation_is_not_converted_to_503():
    class Cancelled:
        async def resolve_key_fresh(self, identity):
            raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await observe_identity_binding(
            Cancelled(), did_key="did:key:subject", did_aw="did:aw:subject"
        )
