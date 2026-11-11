"""A reader's aw session on logs' console origin: the shared handoff, on real
PostgreSQL with a real AWID registry, real owner acts and a software passkey.

The member's aw starts a session handoff for its ``logs.reader`` holding on
logs' public origin, the human approves it with the reader's passkey on the
console origin, and aw collects a session bound to its own key. Every read,
the export included, accepts that signed session as the current holding's,
and only while the holding is current."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import secrets
from collections.abc import AsyncIterator
from contextlib import aclosing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from aweb_naapp.console import ClientIdentity, LoginLimiter, apply_console_migrations
from aweb_naapp.runtime.human_member import check_human_member
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp.runtime.team_auth import AWIDTeamCache, authenticate_request
from aweb_naapp_testing import REGISTRY_URL, SERVICE_TOKEN, Member, did_key
from aweb_naapp_testing.owner_acts import INSTALLATION_ID, TEAM_ID
from aweb_naapp_testing.webauthn import SoftAuthenticator
from awid.dns_verify import DomainAuthority
from awid.id_certificates import id_certificate_signing_bytes
from awid.registry import RegistryClient
from awid.signing import canonical_json_bytes
from awid_service.deps import get_domain_verifier
from fastapi import APIRouter, FastAPI, Request
from nacl.signing import SigningKey

from aweb_logs.export import verify_bundle
from aweb_logs.reader_service import ReaderService, reader_sessions
from aweb_logs.readers import READER_ROLE

from .reader_world import (
    CONSOLE,
    LOGS,
    World,
    chained,
    held_reader,
    revoked_reader,
    world_fixture,  # noqa: F401
)
from .test_read_routes import other_team_event, team_event


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def console_signed(
    key: SigningKey,
    method: str,
    path: str,
    body: bytes,
    *,
    subject: str,
    csrf: str = "",
    nonce: str | None = None,
) -> dict[str, str]:
    """The headers aw signs a console-origin request with: a handoff result
    under the handoff's id, anything else under its session's id."""
    timestamp = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    result = path.startswith("/handoffs/")
    payload = canonical_json_bytes(
        {
            "v": 2,
            "auth": "handoff-result" if result else "handoff-session",
            "aud": CONSOLE,
            "method": method,
            "path": path,
            "handoff_id" if result else "session_id": subject,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "timestamp": timestamp,
            "nonce": nonce or secrets.token_hex(16),
        }
    )
    return {
        "Content-Type": "application/json",
        "X-Console-Key": did_key(key),
        "X-Console-Timestamp": timestamp,
        "X-Console-Signed-Payload": b64(payload),
        "X-Console-Signature": base64.b64encode(key.sign(payload).signature).rstrip(b"=").decode(),
        **({"X-CSRF-Token": csrf} if csrf else {}),
    }


@dataclass
class Aw:
    """aw on the member's machine, the reader's passkey, and logs' two origins."""

    client: httpx.AsyncClient
    member: Member
    principal: str
    device: SoftAuthenticator
    world: World
    # A human member of the same team who holds no reader role.
    outsider: tuple[Member, str]

    async def start(self, principal: str | None = None) -> tuple[httpx.Response, SigningKey, str]:
        key = SigningKey.generate()
        verifier = secrets.token_urlsafe(32)
        raw = json.dumps(
            {
                "v": 1,
                "purpose": "session",
                "client_key": did_key(key),
                "return": "loopback",
                "redirect_uri": "http://127.0.0.1:54321/callback",
                "verifier_sha256": hashlib.sha256(verifier.encode()).hexdigest(),
                "scope": {
                    "installation_id": INSTALLATION_ID,
                    "role": READER_ROLE,
                    "principal": principal or self.principal,
                },
            }
        ).encode()
        started = await self.client.post(
            LOGS + "/handoffs",
            content=raw,
            headers={
                "Content-Type": "application/json",
                **self.member.headers(aud=LOGS, method="POST", path="/handoffs", body=raw),
            },
        )
        return started, key, verifier

    async def open(self) -> tuple[SigningKey, dict[str, Any]]:
        """A key-bound session: aw starts the handoff, the human approves it with
        the reader's passkey, and aw collects the session."""
        started, key, verifier = await self.start()
        assert started.status_code == 201, started.text
        handoff = started.json()["handoff_id"]
        prefix = f"/handoff/{handoff}/session"
        state = await self.client.get(prefix)
        assert state.status_code == 200, state.text
        browser = {"Origin": CONSOLE, "X-CSRF-Token": state.json()["csrf_token"]}
        options = await self.client.post(prefix + "/options", json={}, headers=browser)
        assert options.status_code == 200, options.text
        logged_in = await self.client.post(
            prefix + "/login", json={"assertion": self.device.get(options.json())}, headers=browser
        )
        assert logged_in.status_code == 200, logged_in.text
        allowed = await self.client.post(prefix + "/allow", json={"allow": True}, headers=browser)
        assert allowed.status_code == 200, allowed.text
        code = parse_qs(urlsplit(allowed.json()["redirect_uri"]).query)["code"][0]
        path = f"/handoffs/{handoff}/result"
        body = json.dumps({"v": 1, "code": code, "verifier": verifier}).encode()
        collected = await self.client.post(
            path, content=body, headers=console_signed(key, "POST", path, body, subject=handoff)
        )
        assert collected.status_code == 200, collected.text
        assert collected.json()["purpose"] == "session"
        return key, collected.json()

    async def get(
        self, key: SigningKey, issued: dict[str, Any], path: str, *, nonce: str | None = None
    ) -> httpx.Response:
        return await self.client.get(
            path,
            headers=console_signed(
                key, "GET", path.split("?")[0], b"", subject=issued["session_id"], nonce=nonce
            ),
        )


async def registered_human(
    registry: RegistryClient, world: World, root: SigningKey, alias: str
) -> tuple[Member, str]:
    """A human member of the team: its did:aw registered with a human ID
    certificate under the namespace, and its team certificate in AWID."""
    member = Member(
        team_id=TEAM_ID, team_key=world.owner.team_key, alias=alias, certificate_id="cert-" + alias
    )
    principal = (await registry.register_did(member.did_key, bytes(member.member_key))).did_aw
    member.extra_cert_fields = {"member_did_aw": principal}
    await world.registry.add_certificate(member.certificate())
    fields = {
        "v": 1,
        "type": "aweb.id-certificate",
        "id": principal,
        "domain": "example.com",
        "parent": {"kind": "namespace", "id": "example.com"},
        "kind": "human",
        "issuer_key": did_key(root),
        "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    signed = {
        "certificate": fields,
        "signature": b64(root.sign(id_certificate_signing_bytes(fields)).signature),
    }
    await registry.register_id_certificate(
        {"v": 1, "type": "aweb.id-chain", "certificates": [signed]},
        signer=lambda payload: (member.did_key, member.member_key.sign(payload).signature),
        expected_head=None,
        invitation_id=None,
    )
    return member, principal


@pytest.fixture
async def aw(world: World) -> AsyncIterator[Aw]:
    """A designated reader whose aw reaches logs as production composes its
    reader sessions: the public origin starts handoffs, the console origin
    approves them and serves the reads."""
    await apply_console_migrations(world.db)
    root = SigningKey.generate()

    async def dns(domain: str) -> DomainAuthority:
        assert domain == "example.com"
        return DomainAuthority(did_key(root), REGISTRY_URL, "_awid.example.com")

    world.registry.app.dependency_overrides[get_domain_verifier] = lambda: dns
    world.registry.app.state.awid_public_origins = (REGISTRY_URL,)
    async with aclosing(
        RegistryClient(
            REGISTRY_URL,
            transport=world.registry.transport,
            service_token=SERVICE_TOKEN,
            domain_verifier=dns,
        )
    ) as registry:
        await registry.register_namespace("example.com", did_key(root), bytes(root))
        member, principal = await registered_human(registry, world, root, "reader")
        outsider = await registered_human(registry, world, root, "outsider")
        scope, _ = await held_reader(world, principal)
        cache = AWIDTeamCache(
            registry_url=REGISTRY_URL,
            ttl_seconds=60,
            service_token=SERVICE_TOKEN,
            transport=world.registry.transport,
        )

        async def signer(request: Request):
            return await authenticate_request(request, public_origin=LOGS, team_cache=cache)

        async def human_member(team_id, *, principal, certificate):
            return await check_human_member(
                cache, registry, team_id=team_id, principal=principal, certificate=certificate
            )

        limiter = LoginLimiter(
            world.db, client_identity=ClientIdentity(), limit=100, window=timedelta(minutes=1)
        )
        sessions, handoffs = reader_sessions(
            db=world.db,
            directory=world.directory,
            fence=world.fence,
            passkeys=world.passkeys,
            principal=signer,
            human_member=human_member,
            limiter=limiter,
        )
        service = ReaderService(
            db=world.db,
            directory=world.directory,
            fence=world.fence,
            passkeys=world.passkeys,
            recorder=world.recorder,
            sessions=sessions,
            handoffs=handoffs,
            limiter=limiter,
            chain_keys=frozenset({world.signer.did_key}),
            governance=world.governance,
            # This world designates its readers directly: no owner-act delivery.
            owner_acts=APIRouter(),
        )
        api, human = FastAPI(), FastAPI()
        api.include_router(service.handoff_router)
        human.include_router(service.console_router)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(
                app=split_origins(api, human, agent_origin=LOGS, human_origin=CONSOLE)
            ),
            base_url=CONSOLE,
        ) as client:
            yield Aw(client, member, principal, world.devices[scope], world, outsider)


async def test_aw_exports_the_readers_team_log_with_its_key_bound_session(aw: Aw):
    await team_event(aw.world, "task.updated")
    await other_team_event(aw.world)
    key, issued = await aw.open()
    response = await aw.get(key, issued, "/v1/export")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].split(";")[0] == "application/jsonl"
    lines = [json.loads(line) for line in response.content.splitlines()]
    assert lines[0] == {"v": 1, "type": "aweb.logs-export", "team_id": TEAM_ID}
    assert sum("event" in line for line in lines) == len(await chained(aw.world))
    report = verify_bundle(
        io.BytesIO(response.content),
        receipt_keys=frozenset({aw.world.signer.did_key}),
        checkpoint_keys=frozenset({aw.world.signer.did_key}),
    )
    assert report.intact


async def test_every_read_accepts_the_key_bound_session(aw: Aw):
    await team_event(aw.world, "task.updated")
    key, issued = await aw.open()
    events = await aw.get(key, issued, "/v1/events")
    assert events.status_code == 200, events.text
    assert "task.updated" in [event["event_type"] for event in events.json()["events"]]
    tail = await aw.get(key, issued, "/v1/tail")
    assert tail.status_code == 200, tail.text
    verified = await aw.get(key, issued, "/v1/verify")
    assert verified.status_code == 200, verified.text
    assert verified.json()["chain_epoch"] == 1


async def test_a_signed_read_is_not_accepted_twice(aw: Aw):
    key, issued = await aw.open()
    nonce = secrets.token_hex(16)
    assert (await aw.get(key, issued, "/v1/events", nonce=nonce)).status_code == 200
    replayed = await aw.get(key, issued, "/v1/events", nonce=nonce)
    assert replayed.status_code == 401
    assert "events" not in replayed.json()


async def test_a_session_signed_by_another_key_reads_nothing(aw: Aw):
    _, issued = await aw.open()
    stolen = await aw.get(SigningKey.generate(), issued, "/v1/export")
    assert stolen.status_code == 401
    assert b"aweb.logs-export" not in stolen.content


async def test_a_revoked_holding_ends_the_aw_session(aw: Aw):
    key, issued = await aw.open()
    await revoked_reader(aw.world, aw.principal)
    for path in ("/v1/export", "/v1/events"):
        response = await aw.get(key, issued, path)
        assert response.status_code in (401, 403), (path, response.status_code)
        assert b"aweb.logs-export" not in response.content


async def test_aw_cannot_start_a_session_for_a_member_who_holds_no_reader_role(aw: Aw):
    aw.member, principal = aw.outsider
    started, _, _ = await aw.start(principal)
    assert started.status_code == 403
    assert "handoff_id" not in started.json()
