"""A server's ordinary member key can read only its configured private teams."""

import asyncio
import base64
import os
import subprocess
import json
from dataclasses import dataclass
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from nacl.signing import SigningKey
from redis.asyncio import Redis

import awid.registry as registry_module
from awid.did import did_from_public_key, generate_keypair
from awid.registry import CachedRegistryClient, RegistryClient, RegistryError
from awid.signing import verify_did_key_signature
from aweb.api import _build_awid_registry_client, create_app
from tests.real_stack import REGISTRY_URL
from tests.test_team_auth import _encode_certificate, _make_certificate

DOMAIN = "example.com"
TEAM = "engineering"
TEAM_ID = f"{TEAM}:{DOMAIN}"
BASE = f"/v1/namespaces/{DOMAIN}/teams/{TEAM}"
OTHER_TEAM_ID = f"other:{DOMAIN}"
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
# The registry client reads revocations 200 per page.
REVOCATION_PAGE = 200


def configure_member(monkeypatch, tmp_path):
    key, public = generate_keypair()
    # awid.SaveSigningKey emits a PEM-wrapped 32-byte seed, not PKCS8.
    pem = (
        b"-----BEGIN ED25519 PRIVATE KEY-----\n"
        + base64.b64encode(key)
        + b"\n-----END ED25519 PRIVATE KEY-----\n"
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


@pytest_asyncio.fixture
async def redis():
    async with Redis.from_url(REDIS_URL, decode_responses=True) as client:
        yield client


@dataclass
class PrivateTeam:
    """A private team in the real AWID whose controller issues and revokes certificates."""

    team_id: str
    key: SigningKey
    owner: RegistryClient

    @property
    def did(self) -> str:
        return did_from_public_key(bytes(self.key.verify_key))

    async def issue(self, member_did: str, alias: str) -> dict:
        name, domain = self.team_id.split(":", 1)
        cert = _make_certificate(
            bytes(self.key),
            self.did,
            member_did,
            team_id=self.team_id,
            alias=alias,
            identity_scope="local",
            certificate_id=str(uuid4()),
        )
        await self.owner.register_team_certificate(
            domain,
            name,
            team_controller_signing_key=bytes(self.key),
            certificate_id=cert["certificate_id"],
            member_did_key=member_did,
            member_did_aw=None,
            member_address=None,
            alias=alias,
            identity_scope="local",
            certificate=_encode_certificate(cert),
        )
        return cert

    async def revoke(self, cert: dict) -> None:
        name, domain = self.team_id.split(":", 1)
        await self.owner.revoke_team_certificate(
            domain,
            name,
            team_controller_signing_key=bytes(self.key),
            certificate_id=cert["certificate_id"],
        )


async def add_private_team(real_stack, team_id: str) -> PrivateTeam:
    key = await real_stack.add_team(team_id)
    owner = RegistryClient(REGISTRY_URL, transport=real_stack.awid)
    name, domain = team_id.split(":", 1)
    await owner.set_team_visibility(domain, name, "private", bytes(key))
    return PrivateTeam(team_id=team_id, key=key, owner=owner)


@pytest_asyncio.fixture
async def private_team(real_stack, monkeypatch, tmp_path):
    """TEAM_ID is private in the real AWID, and this server's configured member key holds a certificate in it."""
    team = await add_private_team(real_stack, TEAM_ID)
    key, server_did, _ = configure_member(monkeypatch, tmp_path)
    monkeypatch.setenv("AWID_REGISTRY_URL", REGISTRY_URL)
    server_cert = await team.issue(server_did, "server")
    try:
        yield SimpleNamespace(
            team=team, server_key=key, server_did=server_did, server_cert=server_cert
        )
    finally:
        await team.owner.aclose()


def assert_signed_by(request: httpx.Request, did: str) -> None:
    assert "x-awid-service-token" not in request.headers
    scheme, signer, signature = request.headers["authorization"].split()
    assert (scheme, signer) == ("DIDKey", did)
    verify_did_key_signature(
        did_key=signer,
        signature_b64=signature,
        payload=f"{request.headers['x-aweb-timestamp']}\nGET\n{request.url.path}".encode(),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("cached", [False, True])
async def test_server_without_service_token_signs_all_private_and_fresh_reads(
    real_stack, private_team, redis, cached
):
    team = private_team.team
    # A second revocation page: the client must sign the cursor read as well.
    revoked = []
    for index in range(REVOCATION_PAGE + 1):
        cert = await team.issue(
            did_from_public_key(generate_keypair()[1]), f"former-{index}"
        )
        await team.revoke(cert)
        revoked.append(cert["certificate_id"])
    client = _build_awid_registry_client(
        create_app(), redis=redis if cached else None, transport=real_stack.awid
    )
    calls = real_stack.awid.calls
    first_read = len(calls)
    try:
        assert (await client.get_team(DOMAIN, TEAM)).team_did_key == team.did
        assert await client.get_team_public_key(DOMAIN, TEAM) == team.did
        assert await client.get_team_revocations(DOMAIN, TEAM) == set(revoked)
        assert [
            c.certificate_id for c in await client.list_team_certificates(DOMAIN, TEAM)
        ] == [private_team.server_cert["certificate_id"]]
        # app_tasks and hook_bindings require these fresh methods.
        assert (await client.get_team_fresh(DOMAIN, TEAM)).team_did_key == team.did
        assert await client.get_team_public_key_fresh(DOMAIN, TEAM) == team.did
        assert await client.get_team_revocations_fresh(DOMAIN, TEAM) == set(revoked)
        assert [
            c.certificate_id
            for c in await client.list_team_certificates_fresh(DOMAIN, TEAM)
        ] == [private_team.server_cert["certificate_id"]]
        # No server caller uses member lookup yet; the same existing read gate applies.
        assert (await client._request_json("GET", BASE + "/members/server"))[
            "alias"
        ] == "server"
        for request in calls[first_read:]:
            assert_signed_by(request, private_team.server_did)
        assert sum("cursor=" in str(request.url) for request in calls[first_read:]) == 2
        assert private_team.server_key.hex() not in repr(client)
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_signing_is_scoped_to_team_read_paths_and_configured_registry(real_stack):
    team = await add_private_team(real_stack, TEAM_ID)
    other = await add_private_team(real_stack, OTHER_TEAM_ID)
    key, public = generate_keypair()
    other_key, other_public = generate_keypair()
    await team.issue(did_from_public_key(public), "reader")
    await other.issue(did_from_public_key(other_public), "reader")
    client = RegistryClient(
        REGISTRY_URL,
        member_signing_keys={TEAM_ID: key, OTHER_TEAM_ID: other_key},
        transport=real_stack.awid,
    )
    calls = real_stack.awid.calls
    try:
        assert (await client._request_json("GET", BASE))["team_did_key"] == team.did
        assert_signed_by(calls[-1], did_from_public_key(public))
        assert (
            await client._request_json("GET", f"/v1/namespaces/{DOMAIN}/teams/other")
        )["team_did_key"] == other.did
        assert_signed_by(calls[-1], did_from_public_key(other_public))
        for method, path, origin, status in [
            ("GET", BASE, "https://foreign.example", 403),
            ("GET", BASE.replace(TEAM, "unknown"), None, 404),
            ("GET", BASE + "/certificates/another-members-blob", None, 401),
            ("GET", BASE + "/server", None, 404),
            ("GET", f"/v1/namespaces/{DOMAIN}/addresses", None, 404),
            ("POST", BASE + "/certificates", None, 422),
        ]:
            with pytest.raises(RegistryError) as refused:
                await client._request_json(method, path, registry_url=origin)
            assert "authorization" not in calls[-1].headers
            assert refused.value.status_code == status
        # Explicit caller authority must never be silently replaced.
        with pytest.raises(RegistryError) as refused:
            await client._request_json(
                "GET", BASE, headers={"Authorization": "DIDKey explicit signature"}
            )
        assert calls[-1].headers["authorization"] == "DIDKey explicit signature"
        assert refused.value.status_code == 401
    finally:
        for registry in (client, team.owner, other.owner):
            await registry.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method",
    [
        "get_team_public_key",
        "get_team_revocations",
        "get_team",
        "list_team_certificates",
    ],
)
@pytest.mark.parametrize("refusal", ["revoked", "unauthenticated"])
async def test_revoked_reader_cannot_reuse_cache_after_refusal(
    real_stack, private_team, redis, monkeypatch, method, refusal
):
    now = [1000]
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now[0])
    client = _build_awid_registry_client(
        create_app(), redis=redis, transport=real_stack.awid
    )
    try:
        read = getattr(client, method)
        warm = await read(DOMAIN, TEAM)
        # The cache is warm: the same answer, and no request reaches AWID.
        origin_reads = len(real_stack.awid.calls)
        assert await read(DOMAIN, TEAM) == warm
        assert len(real_stack.awid.calls) == origin_reads
        if refusal == "revoked":
            await private_team.team.revoke(private_team.server_cert)
            status = 403
        else:
            # The registry no longer accepts the reader's signature.
            real_stack.awid.fault = lambda request, response: httpx.Response(
                401, json={"detail": "invalid signature"}
            )
            status = 401
        now[0] += 601 if method in ("get_team", "list_team_certificates") else 61
        # A stale-while-revalidate read returns the cached answer while its refresh runs, or is refused.
        try:
            stale = await read(DOMAIN, TEAM)
        except RegistryError as refused:
            assert refused.status_code == status
        else:
            assert stale == warm
        await asyncio.gather(*list(client._refresh_tasks.values()))
        with pytest.raises(RegistryError) as caught:
            await read(DOMAIN, TEAM)
        assert caught.value.status_code == status
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_member_cache_is_not_reused_by_another_reader(redis):
    key, _ = generate_keypair()
    other, _ = generate_keypair()
    clients = [
        CachedRegistryClient("https://api.awid.ai", redis, member_signing_keys=keys)
        for keys in ({TEAM_ID: key}, {TEAM_ID: other}, {OTHER_TEAM_ID: key}, {})
    ]
    try:
        for name in (
            "_team_metadata_cache_key",
            "_team_public_key_cache_key",
            "_team_revocations_cache_key",
            "_team_certificates_cache_key",
        ):
            kwargs = (
                {"active_only": True} if name == "_team_certificates_cache_key" else {}
            )
            assert (
                len(
                    {
                        getattr(client, name)(DOMAIN, TEAM, **kwargs)
                        for client in clients
                    }
                )
                == 4
            )
    finally:
        for client in clients:
            await client.aclose()


@pytest.mark.parametrize(
    "contents",
    [
        "{}",
        "[]",
        '{"bad-team-id":"missing.pem"}',
        '{"engineering:example.com":"missing.pem"}',
    ],
)
def test_invalid_member_configuration_refused_at_startup(
    monkeypatch, tmp_path, contents
):
    _, _, config = configure_member(monkeypatch, tmp_path)
    config.write_text(contents)
    with pytest.raises(ValueError, match="AWID_MEMBER_KEYS_FILE"):
        _build_awid_registry_client(create_app(), redis=None)


def test_group_writable_member_key_file_refused_at_startup(monkeypatch, tmp_path):
    from aweb.config import get_settings

    configure_member(monkeypatch, tmp_path)
    (tmp_path / "server.pem").chmod(0o664)
    with pytest.raises(ValueError, match="AWID_MEMBER_KEYS_FILE"):
        get_settings()


def test_member_key_path_that_is_not_a_regular_file_refused_at_startup(
    monkeypatch, tmp_path
):
    from aweb.config import get_settings

    _, _, config = configure_member(monkeypatch, tmp_path)
    fifo = tmp_path / "server.fifo"
    os.mkfifo(fifo)
    config.write_text(json.dumps({TEAM_ID: str(fifo)}))
    with pytest.raises(ValueError, match="AWID_MEMBER_KEYS_FILE"):
        get_settings()


@pytest.mark.asyncio
async def test_real_private_team_verification_revocation_and_recovery(
    real_stack, private_team, redis, monkeypatch
):
    """Real AWID gates + aweb's member, app-task and hook authority consumers."""
    import hashlib
    from datetime import datetime, timedelta, timezone

    from fastapi import HTTPException
    from starlette.requests import Request
    from awid.signing import sign_message
    from aweb.team_auth_envelope import compact_team_auth_payload
    from aweb.team_auth_deps import verify_request_certificate
    from aweb.coordination.app_tasks import verify_authorization_certificate
    from aweb.hook_bindings import core_owner_act_verifier, OwnerActTeamKeyUnavailable
    from awid_service.testing import TXTAnswers
    from aweb_naapp.hooks.owner_act import owner_act_signing_bytes, hook_binding_subject

    team = private_team.team
    team_key, team_did, server_did = team.key, team.did, private_team.server_did
    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", "true")
    member_key, member_public = generate_keypair()
    member_did = did_from_public_key(member_public)
    server_cert = private_team.server_cert
    member_cert = await team.issue(member_did, "alice")
    now = [1000]
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now[0])
    client = _build_awid_registry_client(
        create_app(), redis=redis, transport=real_stack.awid
    )
    hosted = RegistryClient(
        REGISTRY_URL, service_token=real_stack.service_token, transport=real_stack.awid
    )
    unsigned = RegistryClient(REGISTRY_URL, transport=real_stack.awid)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    envelope = compact_team_auth_payload(
        team_id=TEAM_ID,
        timestamp=timestamp,
        body_sha256=hashlib.sha256(b"").hexdigest(),
    )
    headers = {
        "Authorization": f"DIDKey {member_did} {sign_message(member_key, envelope)}",
        "X-AWEB-Timestamp": timestamp,
        "X-AWID-Team-Certificate": _encode_certificate(member_cert),
    }
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/v1/tasks",
            "query_string": b"",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
            "app": SimpleNamespace(
                state=SimpleNamespace(
                    awid_registry_client=client,
                    public_origin="",
                    db=SimpleNamespace(get_manager=lambda _name: real_stack.aweb_db),
                )
            ),
        }
    )
    authorization = {
        "payload": {
            "team_id": TEAM_ID,
            "certificate_id": member_cert["certificate_id"],
            "actor_did_key": member_did,
        },
        "certificate": _encode_certificate(member_cert),
    }
    moment = datetime.now(timezone.utc)
    act = {
        "v": 1,
        "type": "aweb.owner-act",
        "team_id": TEAM_ID,
        "team_key_did": team_did,
        "aud": "https://aweb.example",
        "act": "hook-binding.activate",
        "issued_at": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (moment + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nonce": uuid4().hex,
        "subject": hook_binding_subject(
            binding_id=str(uuid4()),
            installation_id=str(uuid4()),
            generation=1,
            app_id="logs",
            origin="https://logs.example",
            digest="sha256:" + "a" * 64,
            kind="registration",
            catalog_id="aweb.hooks",
            catalog_version=1,
            hook="post-command-hook",
            tool="audit",
            method="POST",
            path="/hooks/audit",
            scopes=[],
        ),
    }
    signing = owner_act_signing_bytes(act)

    # Production hands verification the app's database infra (aweb.deps.get_db).
    aweb_infra = request.app.state.db

    verifier = core_owner_act_verifier(
        audience="https://aweb.example",
        db=real_stack.aweb_db,
        registry_client=client,
        txt_resolver=TXTAnswers(),
    )
    try:
        with pytest.raises(RegistryError) as denied:
            await unsigned.get_team(DOMAIN, TEAM)
        assert denied.value.status_code == 403
        assert (await verify_request_certificate(request, aweb_infra))[
            "alias"
        ] == "alice"
        assert (await verify_authorization_certificate(request, authorization))[0][
            "alias"
        ] == "alice"
        await verifier.prepare(
            signing, sign_message(bytes(team_key), signing), team_id=TEAM_ID
        )
        assert (await client._request_json("GET", BASE + "/members/alice"))[
            "alias"
        ] == "alice"
        assert (await hosted.get_team(DOMAIN, TEAM)).team_did_key == team_did
        await team.revoke(server_cert)
        # Fresh app and hook reads refuse immediately, even with warm caches.
        with pytest.raises(HTTPException) as app_denied:
            await verify_authorization_certificate(request, authorization)
        assert app_denied.value.status_code == 503
        with pytest.raises(OwnerActTeamKeyUnavailable):
            await verifier.prepare(
                signing, sign_message(bytes(team_key), signing), team_id=TEAM_ID
            )
        now[0] += 61
        with pytest.raises(HTTPException) as auth_denied:
            await verify_request_certificate(request, aweb_infra)
        assert auth_denied.value.status_code == 503
        assert (await hosted.get_team(DOMAIN, TEAM)).team_did_key == team_did
        # Existing controller issuance restores access; no new recovery protocol.
        await team.issue(server_did, "server")
        assert (await verify_request_certificate(request, aweb_infra))[
            "alias"
        ] == "alice"
    finally:
        for registry in (client, hosted, unsigned):
            await registry.aclose()


@pytest.mark.asyncio
async def test_hosted_token_takes_precedence_and_stays_home_scoped(
    real_stack, private_team, monkeypatch
):
    monkeypatch.setenv("AWID_SERVICE_TOKEN", real_stack.service_token)
    calls = real_stack.awid.calls
    client = _build_awid_registry_client(
        create_app(), redis=None, transport=real_stack.awid
    )
    try:
        assert (await client._request_json("GET", BASE))[
            "team_did_key"
        ] == private_team.team.did
        assert calls[-1].headers["x-awid-service-token"] == real_stack.service_token
        assert "authorization" not in calls[-1].headers
        with pytest.raises(RegistryError) as refused:
            await client._request_json(
                "GET", BASE, registry_url="https://elsewhere.example"
            )
        assert refused.value.status_code == 403
        assert "authorization" not in calls[-1].headers
        assert "x-awid-service-token" not in calls[-1].headers
    finally:
        await client.aclose()


def test_relative_member_key_paths_and_non_ed25519_refusal(monkeypatch, tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ec import (
        generate_private_key,
        SECP256R1,
    )
    from aweb.config import get_settings

    key, _, config = configure_member(monkeypatch, tmp_path)
    config.write_text(json.dumps({TEAM_ID: "server.pem"}))
    settings = get_settings()
    assert settings.awid_member_signing_keys == {TEAM_ID: key}
    assert repr(key) not in repr(settings)
    wrong_key = generate_private_key(SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    (tmp_path / "server.pem").write_bytes(wrong_key)
    with pytest.raises(ValueError, match="AWID_MEMBER_KEYS_FILE"):
        get_settings()


@pytest.mark.asyncio
async def test_server_loads_key_emitted_by_existing_cli(
    aw_cli_binary, monkeypatch, tmp_path
):
    from aweb.config import get_settings
    from awid.signing import sign_message

    identity = tmp_path / "identity"
    identity.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("AWEB_", "AWID_"))}
    # Local preparation does not register an identity or contact a service.
    result = subprocess.run(
        [
            str(aw_cli_binary),
            "--identity-home",
            str(identity),
            "id",
            "team",
            "request",
            "--create-local-key",
            "--team",
            TEAM_ID,
            "--name",
            "server",
        ],
        env=env,
        cwd=tmp_path,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    key_path = identity / "signing.key"
    assert key_path.read_bytes().startswith(b"-----BEGIN ED25519 PRIVATE KEY-----")
    manifest = tmp_path / "member-keys.json"
    manifest.write_text(json.dumps({TEAM_ID: str(key_path)}))
    monkeypatch.setenv("AWID_MEMBER_KEYS_FILE", str(manifest))
    monkeypatch.delenv("AWID_SERVICE_TOKEN", raising=False)
    monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/test")
    seed = get_settings().awid_member_signing_keys[TEAM_ID]
    from nacl.signing import SigningKey

    did = did_from_public_key(bytes(SigningKey(seed).verify_key))
    assert did in result.stdout
    payload = b"existing CLI key signs through the shared primitive"
    verify_did_key_signature(
        did_key=did, signature_b64=sign_message(seed, payload), payload=payload
    )


@pytest.mark.parametrize(
    "pem",
    [
        b"not a PEM file",
        b"-----BEGIN PRIVATE KEY-----\n"
        + base64.b64encode(bytes(32))
        + b"\n-----END PRIVATE KEY-----",
        b"-----BEGIN ED25519 PRIVATE KEY-----\n!!not-base64!!\n-----END ED25519 PRIVATE KEY-----",
        b"-----BEGIN ED25519 PRIVATE KEY-----\n"
        + base64.b64encode(bytes(31))
        + b"\n-----END ED25519 PRIVATE KEY-----",
        b"-----BEGIN ED25519 PRIVATE KEY-----\n"
        + base64.b64encode(bytes(64))
        + b"\n-----END ED25519 PRIVATE KEY-----",
    ],
)
def test_shared_member_key_loader_refuses_wrong_format(pem):
    from awid.signing import load_signing_key_pem

    with pytest.raises(ValueError) as caught:
        load_signing_key_pem(pem)
    assert pem.decode() not in str(caught.value)
