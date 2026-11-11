"""A server's ordinary member key can read only its configured private teams."""
import asyncio
import json

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import awid.registry as registry_module
from awid.did import did_from_public_key, generate_keypair
from awid.registry import CachedRegistryClient, RegistryClient, RegistryError
from awid.signing import verify_did_key_signature
from aweb.api import _build_awid_registry_client, create_app
from tests.test_awid_registry_client import _FakeRedis

DOMAIN = "example.com"
TEAM = "engineering"
TEAM_ID = f"{TEAM}:{DOMAIN}"
BASE = f"/v1/namespaces/{DOMAIN}/teams/{TEAM}"


def configure_member(monkeypatch, tmp_path):
    key, public = generate_keypair()
    pem = Ed25519PrivateKey.from_private_bytes(key).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    key_path = tmp_path / "server.pem"
    key_path.write_bytes(pem)
    config = tmp_path / "members.json"
    config.write_text(json.dumps({TEAM_ID: str(key_path)}))
    monkeypatch.setenv("AWID_MEMBER_KEYS_FILE", str(config))
    monkeypatch.delenv("AWID_SERVICE_TOKEN", raising=False)
    monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/test")
    monkeypatch.setenv("AWID_REGISTRY_URL", "https://api.awid.ai")
    return key, did_from_public_key(public), config


@pytest.mark.asyncio
@pytest.mark.parametrize("cached", [False, True])
async def test_server_without_service_token_signs_all_private_and_fresh_reads(monkeypatch, tmp_path, cached):
    key, did, _ = configure_member(monkeypatch, tmp_path)
    paths = []

    async def handle(request):
        assert "x-awid-service-token" not in request.headers
        scheme, signer, signature = request.headers["authorization"].split()
        assert (scheme, signer) == ("DIDKey", did)
        verify_did_key_signature(did_key=signer, signature_b64=signature,
            payload=f"{request.headers['x-aweb-timestamp']}\nGET\n{request.url.path}".encode())
        paths.append(str(request.url))
        if request.url.path.endswith("/revocations"):
            return httpx.Response(200, json={"revocations": [], "has_more": not bool(request.url.params.get("cursor")), "next_cursor": "page2"})
        if request.url.path.endswith("/certificates"):
            return httpx.Response(200, json={"certificates": [], "has_more": False})
        if "/members/" in request.url.path:
            return httpx.Response(200, json={"alias": "alice"})
        return httpx.Response(200, json={"team_id": TEAM_ID, "created_at": "2026-11-11T00:00:00Z", "domain": DOMAIN, "name": TEAM, "team_did_key": did})

    client = _build_awid_registry_client(create_app(), redis=_FakeRedis() if cached else None,
        transport=httpx.MockTransport(handle))
    try:
        assert (await client.get_team(DOMAIN, TEAM)).team_did_key == did
        assert await client.get_team_public_key(DOMAIN, TEAM) == did
        assert await client.get_team_revocations(DOMAIN, TEAM) == set()
        assert await client.list_team_certificates(DOMAIN, TEAM) == []
        # app_tasks and hook_bindings require these fresh methods.
        assert (await client.get_team_fresh(DOMAIN, TEAM)).team_did_key == did
        assert await client.get_team_public_key_fresh(DOMAIN, TEAM) == did
        assert await client.get_team_revocations_fresh(DOMAIN, TEAM) == set()
        assert await client.list_team_certificates_fresh(DOMAIN, TEAM) == []
        # No server caller uses member lookup yet; the same existing read gate applies.
        await client._request_json("GET", BASE + "/members/alice")
        assert sum("cursor=page2" in path for path in paths) == 2
        assert key.hex() not in repr(client)
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_signing_is_scoped_to_team_read_paths_and_configured_registry():
    key, public = generate_keypair()
    other_key, other_public = generate_keypair()
    requests = []

    async def handle(request):
        requests.append(request)
        return httpx.Response(200, json={})

    client = RegistryClient("https://api.awid.ai", member_signing_keys={TEAM_ID: key, "other:example.com": other_key},
        transport=httpx.MockTransport(handle))
    try:
        await client._request_json("GET", BASE)
        await client._request_json("GET", "/v1/namespaces/example.com/teams/other")
        assert did_from_public_key(public) in requests[0].headers["authorization"]
        assert did_from_public_key(other_public) in requests[1].headers["authorization"]
        for method, path, origin in [
            ("GET", BASE, "https://foreign.example"),
            ("GET", BASE.replace(TEAM, "unknown"), None),
            ("GET", BASE + "/certificates/another-members-blob", None),
            ("GET", BASE + "/server", None),
            ("GET", "/v1/namespaces/example.com/addresses", None),
            ("POST", BASE + "/certificates", None),
        ]:
            await client._request_json(method, path, registry_url=origin)
            assert "authorization" not in requests[-1].headers
        # Explicit caller authority must never be silently replaced.
        await client._request_json("GET", BASE, headers={"Authorization": "DIDKey explicit signature"})
        assert requests[-1].headers["authorization"] == "DIDKey explicit signature"
    finally:
        await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["get_team_public_key", "get_team_revocations", "get_team", "list_team_certificates"])
@pytest.mark.parametrize("status", [401, 403])
async def test_revoked_reader_cannot_reuse_cache_after_refusal(monkeypatch, method, status):
    key, public = generate_keypair()
    did = did_from_public_key(public)
    now = [1000]
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now[0])
    revoked = False

    async def handle(request):
        if revoked:
            return httpx.Response(status, json={"detail": "team_private"})
        if request.url.path.endswith("/revocations"):
            return httpx.Response(200, json={"revocations": [], "has_more": False})
        if request.url.path.endswith("/certificates"):
            return httpx.Response(200, json={"certificates": [], "has_more": False})
        return httpx.Response(200, json={"team_id": TEAM_ID, "created_at": "2026-11-11T00:00:00Z", "domain": DOMAIN, "name": TEAM, "team_did_key": did})

    client = CachedRegistryClient("https://api.awid.ai", _FakeRedis(), member_signing_keys={TEAM_ID: key}, transport=httpx.MockTransport(handle))
    try:
        read = getattr(client, method)
        await read(DOMAIN, TEAM)
        revoked = True
        now[0] += 601 if method in ("get_team", "list_team_certificates") else 61
        # A stale-while-revalidate read may return while its refresh runs.
        try:
            await read(DOMAIN, TEAM)
        except RegistryError:
            pass
        await asyncio.gather(*list(client._refresh_tasks.values()))
        with pytest.raises(RegistryError) as caught:
            await read(DOMAIN, TEAM)
        assert caught.value.status_code == status
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_member_cache_is_not_reused_by_another_reader():
    key, _ = generate_keypair()
    other, _ = generate_keypair()
    redis = _FakeRedis()
    clients = [CachedRegistryClient("https://api.awid.ai", redis, member_signing_keys=keys)
        for keys in ({TEAM_ID: key}, {TEAM_ID: other}, {"other:example.com": key}, {})]
    try:
        for name in ("_team_metadata_cache_key", "_team_public_key_cache_key", "_team_revocations_cache_key", "_team_certificates_cache_key"):
            kwargs = {"active_only": True} if name == "_team_certificates_cache_key" else {}
            assert len({getattr(client, name)(DOMAIN, TEAM, **kwargs) for client in clients}) == 4
    finally:
        for client in clients:
            await client.aclose()


@pytest.mark.parametrize("contents", ["{}", "[]", '{"bad-team-id":"missing.pem"}', '{"engineering:example.com":"missing.pem"}'])
def test_invalid_member_configuration_refused_at_startup(monkeypatch, tmp_path, contents):
    _, _, config = configure_member(monkeypatch, tmp_path)
    config.write_text(contents)
    with pytest.raises(ValueError, match="AWID_MEMBER_KEYS_FILE"):
        _build_awid_registry_client(create_app(), redis=None)
