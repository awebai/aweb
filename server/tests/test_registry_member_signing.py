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


@pytest.mark.asyncio
async def test_real_private_team_verification_revocation_and_recovery(real_stack, monkeypatch, tmp_path):
    """Real AWID gates + aweb's member, app-task and hook authority consumers."""
    import hashlib
    from datetime import datetime, timedelta, timezone
    from types import SimpleNamespace
    from uuid import uuid4

    from fastapi import HTTPException
    from starlette.requests import Request
    from awid.signing import sign_message
    from aweb.team_auth_envelope import compact_team_auth_payload
    from aweb.team_auth_deps import verify_request_certificate
    from aweb.coordination.app_tasks import verify_authorization_certificate
    from aweb.hook_bindings import core_owner_act_verifier, OwnerActTeamKeyUnavailable
    from aweb_naapp.hooks.owner_act import owner_act_signing_bytes, hook_binding_subject
    from tests.test_team_auth import _make_certificate, _encode_certificate
    from tests.real_stack import REGISTRY_URL

    team_key = await real_stack.add_team(TEAM_ID)
    team_did = did_from_public_key(bytes(team_key.verify_key))
    await real_stack.awid_db.execute("UPDATE {{tables.teams}} SET visibility = 'private' WHERE domain = $1 AND name = $2", DOMAIN, TEAM)
    _, server_did, _ = configure_member(monkeypatch, tmp_path)
    monkeypatch.setenv("AWID_REGISTRY_URL", REGISTRY_URL)
    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", "true")
    owner = RegistryClient(REGISTRY_URL, transport=real_stack.awid)
    member_key, member_public = generate_keypair()
    member_did = did_from_public_key(member_public)

    async def issue(key_did, alias):
        cert = _make_certificate(bytes(team_key), team_did, key_did, team_id=TEAM_ID,
            alias=alias, identity_scope="local", certificate_id=str(uuid4()))
        await owner.register_team_certificate(DOMAIN, TEAM,
            team_controller_signing_key=bytes(team_key), certificate_id=cert["certificate_id"],
            member_did_key=key_did, member_did_aw=None, member_address=None,
            alias=alias, identity_scope="local", certificate=_encode_certificate(cert))
        return cert

    server_cert = await issue(server_did, "server")
    member_cert = await issue(member_did, "alice")
    now = [1000]
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now[0])
    client = _build_awid_registry_client(create_app(), redis=_FakeRedis(), transport=real_stack.awid)
    hosted = RegistryClient(REGISTRY_URL, service_token=real_stack.service_token, transport=real_stack.awid)
    unsigned = RegistryClient(REGISTRY_URL, transport=real_stack.awid)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    envelope = compact_team_auth_payload(team_id=TEAM_ID, timestamp=timestamp, body_sha256=hashlib.sha256(b"").hexdigest())
    headers = {
        "Authorization": f"DIDKey {member_did} {sign_message(member_key, envelope)}",
        "X-AWEB-Timestamp": timestamp,
        "X-AWID-Team-Certificate": _encode_certificate(member_cert),
    }
    request = Request({"type": "http", "method": "GET", "path": "/v1/tasks", "query_string": b"",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "app": SimpleNamespace(state=SimpleNamespace(awid_registry_client=client, public_origin=""))})
    authorization = {"payload": {"team_id": TEAM_ID, "certificate_id": member_cert["certificate_id"], "actor_did_key": member_did},
        "certificate": _encode_certificate(member_cert)}
    moment = datetime.now(timezone.utc)
    act = {
        "v": 1, "type": "aweb.owner-act", "team_id": TEAM_ID, "team_key_did": team_did,
        "aud": "https://aweb.example", "act": "hook-binding.activate",
        "issued_at": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (moment + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nonce": uuid4().hex,
        "subject": hook_binding_subject(binding_id=str(uuid4()), installation_id=str(uuid4()), generation=1,
            app_id="logs", origin="https://logs.example", digest="sha256:" + "a"*64,
            kind="registration", catalog_id="aweb.hooks", catalog_version=1,
            hook="post-command-hook", tool="audit", method="POST", path="/hooks/audit", scopes=[]),
    }
    signing = owner_act_signing_bytes(act)
    verifier = core_owner_act_verifier(audience="https://aweb.example", registry_client=client)
    try:
        with pytest.raises(RegistryError) as denied:
            await unsigned.get_team(DOMAIN, TEAM)
        assert denied.value.status_code == 403
        assert (await verify_request_certificate(request, real_stack.aweb_db))["alias"] == "alice"
        assert (await verify_authorization_certificate(request, authorization))[0]["alias"] == "alice"
        await verifier.prepare(signing, sign_message(bytes(team_key), signing), team_id=TEAM_ID)
        assert (await client._request_json("GET", BASE + "/members/alice"))["alias"] == "alice"
        assert (await hosted.get_team(DOMAIN, TEAM)).team_did_key == team_did
        await owner.revoke_team_certificate(DOMAIN, TEAM, team_controller_signing_key=bytes(team_key), certificate_id=server_cert["certificate_id"])
        # Fresh app and hook reads refuse immediately, even with warm caches.
        with pytest.raises(HTTPException) as app_denied:
            await verify_authorization_certificate(request, authorization)
        assert app_denied.value.status_code == 503
        with pytest.raises(OwnerActTeamKeyUnavailable):
            await verifier.prepare(signing, sign_message(bytes(team_key), signing), team_id=TEAM_ID)
        now[0] += 61
        with pytest.raises(HTTPException) as auth_denied:
            await verify_request_certificate(request, real_stack.aweb_db)
        assert auth_denied.value.status_code == 503
        assert (await hosted.get_team(DOMAIN, TEAM)).team_did_key == team_did
        # Existing controller issuance restores access; no new recovery protocol.
        await issue(server_did, "server")
        assert (await verify_request_certificate(request, real_stack.aweb_db))["alias"] == "alice"
    finally:
        for registry in (client, hosted, owner, unsigned):
            await registry.aclose()


@pytest.mark.asyncio
async def test_hosted_token_takes_precedence_and_stays_home_scoped(monkeypatch, tmp_path):
    configure_member(monkeypatch, tmp_path)
    token = "hosted-registry-service-token-at-least-32-bytes"
    monkeypatch.setenv("AWID_SERVICE_TOKEN", token)
    requests = []

    async def handle(request):
        requests.append(request)
        return httpx.Response(200, json={})

    client = _build_awid_registry_client(create_app(), redis=None, transport=httpx.MockTransport(handle))
    try:
        await client._request_json("GET", BASE)
        assert requests[-1].headers["x-awid-service-token"] == token
        assert "authorization" not in requests[-1].headers
        await client._request_json("GET", BASE, registry_url="https://elsewhere.example")
        assert "authorization" not in requests[-1].headers
        assert "x-awid-service-token" not in requests[-1].headers
    finally:
        await client.aclose()


def test_relative_member_key_paths_and_non_ed25519_refusal(monkeypatch, tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
    from aweb.config import get_settings

    key, _, config = configure_member(monkeypatch, tmp_path)
    config.write_text(json.dumps({TEAM_ID: "server.pem"}))
    settings = get_settings()
    assert settings.awid_member_signing_keys == {TEAM_ID: key}
    assert repr(key) not in repr(settings)
    wrong_key = generate_private_key(SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    (tmp_path / "server.pem").write_bytes(wrong_key)
    with pytest.raises(ValueError, match="AWID_MEMBER_KEYS_FILE"):
        get_settings()
