"""The shared factory on the app's real owner-act/B3 holding adapter.

This component harness uses the existing app installation fixture. The supported
root journey is a separate handback using the root owner's RuntimeContext; this
harness must never be described as that journey or used to seed lab authority.
"""

import base64
import hashlib
import json
import secrets
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import aclosing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from aweb_naapp.console import (
    ClientIdentity,
    ConsoleSession,
    LoginLimiter,
    apply_console_migrations,
    session_is_current,
)
from aweb_naapp.console.handoff_authority import HandoffAuthority, PublicScope
from aweb_naapp.roles import PrincipalKey, unassign
from aweb_naapp.runtime.human_member import check_human_member
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp.runtime.team_auth import AWIDTeamCache, authenticate_request
from aweb_naapp_testing import REGISTRY_URL, SERVICE_TOKEN, Member, did_key
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from aweb_naapp_testing.webauthn import SoftAuthenticator
from awid.dns_verify import DomainAuthority
from awid.id_certificates import id_certificate_signing_bytes
from awid.registry import RegistryClient
from awid.signing import canonical_json_bytes
from awid_service.deps import get_domain_verifier
from fastapi import Depends, FastAPI, HTTPException, Request
from nacl.signing import SigningKey

from aweb_secrets.human_holding_identity import owner_holding_identity
from aweb_secrets.owners import OWNER_ROLE
from tests.test_human_holders import authority
from tests.test_owner_bootstrap import TEAM, _apply
from tests.test_owner_bootstrap import world as world

API = "https://api.example"


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def signed_request(key, origin, method, path, body, *, session_id, csrf="", nonce=None):
    timestamp = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    result = "/handoffs/" in path
    payload = canonical_json_bytes(
        {
            "v": 2,
            "auth": "handoff-result" if result else "handoff-session",
            "aud": origin,
            "method": method,
            "path": path,
            "handoff_id" if result else "session_id": session_id,
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
class Journey:
    client: httpx.AsyncClient
    member: Member
    scope: PublicScope
    device: SoftAuthenticator
    factory: object
    world: object
    enrol_owner: Callable[[str], Awaitable[tuple[Member, PublicScope, SoftAuthenticator]]]

    async def open(self):
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
                    "installation_id": self.scope.installation_id,
                    "role": self.scope.role,
                    "principal": self.scope.principal,
                },
            }
        ).encode()
        start = await self.client.post(
            API + "/handoffs",
            content=raw,
            headers={
                "Content-Type": "application/json",
                **self.member.headers(
                    aud=API,
                    method="POST",
                    path="/handoffs",
                    body=raw,
                ),
            },
        )
        assert start.status_code == 201, start.text
        handoff = start.json()["handoff_id"]
        prefix = f"/handoff/{handoff}/session"
        state = await self.client.get(prefix)
        assert state.status_code == 200, state.text
        browser = {"Origin": self.device.origin, "X-CSRF-Token": state.json()["csrf_token"]}
        options = await self.client.post(prefix + "/options", json={}, headers=browser)
        assert options.status_code == 200, options.text
        logged_in = await self.client.post(
            prefix + "/login",
            json={"assertion": self.device.get(options.json())},
            headers=browser,
        )
        assert logged_in.status_code == 200, logged_in.text
        allowed = await self.client.post(prefix + "/allow", json={"allow": True}, headers=browser)
        assert allowed.status_code == 200, allowed.text
        code = parse_qs(urlsplit(allowed.json()["redirect_uri"]).query)["code"][0]
        path = f"/handoffs/{handoff}/result"
        body = json.dumps({"v": 1, "code": code, "verifier": verifier}).encode()
        collected = await self.client.post(
            path,
            content=body,
            headers=signed_request(
                key,
                self.device.origin,
                "POST",
                path,
                body,
                session_id=handoff,
            ),
        )
        assert collected.status_code == 200, collected.text
        assert collected.json()["purpose"] == "session"
        return key, collected.json()

    async def request(
        self, key, issued, *, path="/protected", method="POST", nonce=None, **changes
    ):
        raw = b"{}" if method == "POST" else b""
        headers = signed_request(
            key,
            self.device.origin,
            method,
            path,
            raw,
            session_id=issued["session_id"],
            csrf=issued["csrf_token"],
            nonce=nonce,
        )
        headers.update(changes)
        return await self.client.request(method, path, content=raw, headers=headers)


@pytest.fixture
async def journey(world, human_member_cache_seconds) -> AsyncIterator[Journey]:
    # Imported at runtime so collection remains possible while the factory is
    # test-first work. It will fail at this exact supported API until implemented.
    from aweb_naapp.console.handoff_sessions import ConsoleHandoffs

    await apply_console_migrations(world.db)
    root = SigningKey.generate()

    async def dns(domain):
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

        async def enrol_owner(alias: str):
            # Every extra holder follows the same registered-human, signed owner
            # act and real B3 enrolment as the first. No session is fabricated.
            member = Member(
                team_id=TEAM,
                team_key=world.owner.team_key,
                alias=alias,
                certificate_id="cert-1" if alias == "alice" else "handoff-" + alias,
            )
            contact = "holder@example.com" if alias == "alice" else alias + "@example.com"
            principal = (
                await registry.register_did(member.did_key, bytes(member.member_key))
            ).did_aw
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
            who = PrincipalKey(TEAM, principal)
            await _apply(world, "app-role.designate", who, contact)
            token = world.contacts.inbox[contact][-1]
            device = SoftAuthenticator(world.passkeys.rp.origin)
            prepared = await world.credential_audit.prepare_enrolment(token)
            with world.credential_audit.prepared(prepared):
                await world.passkeys.complete_enrolment(
                    token,
                    device.create(await world.passkeys.enrolment_options(token)),
                    fence=prepared,
                )
            return member, PublicScope(INSTALLATION_ID, OWNER_ROLE, principal), device

        member, public_scope, device = await enrol_owner("alice")
        cache = AWIDTeamCache(
            registry_url=REGISTRY_URL,
            ttl_seconds=human_member_cache_seconds,
            service_token=SERVICE_TOKEN,
            transport=world.registry.transport,
        )

        async def signer(request: Request):
            return await authenticate_request(request, public_origin=API, team_cache=cache)

        async def human_member(team_id, *, principal, certificate):
            return await check_human_member(
                cache,
                registry,
                team_id=team_id,
                principal=principal,
                certificate=certificate,
            )

        app = authority(world)
        factory = ConsoleHandoffs(
            db=world.db,
            passkeys=world.passkeys,
            authority=HandoffAuthority(
                app.credential_target,
                app.session_target,
                app.hold_session_target,
                app.check_session_target,
                owner_holding_identity,
            ),
            principal=signer,
            human_member=human_member,
            limiter=LoginLimiter(
                world.db, client_identity=ClientIdentity(), limit=100, window=timedelta(minutes=1)
            ),
        )
        api, human = FastAPI(), FastAPI()
        api.include_router(factory.api_router())
        human.include_router(factory.human_router())

        @human.api_route("/protected", methods=["GET", "POST"])
        async def protected(session: Annotated[ConsoleSession, Depends(factory.current)]):
            async with world.db.transaction() as tx:
                await factory.prepare(
                    tx, session, approver_pairs=[(session.scope, session.subject)]
                )
                if not await session_is_current(tx, session, hold=False):
                    raise HTTPException(401, "console_session_required")
                return {"scope": session.scope, "subject": session.subject}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(
                app=split_origins(
                    api,
                    human,
                    agent_origin=API,
                    human_origin=device.origin,
                )
            ),
            base_url=device.origin,
        ) as client:
            yield Journey(
                client,
                member,
                public_scope,
                device,
                factory,
                world,
                enrol_owner,
            )


async def test_two_fresh_bound_sessions_share_the_same_real_b3_pair(journey):
    first_key, first = await journey.open()
    retained = await journey.factory.check_holding_member(journey.scope)
    assert retained.principal == journey.scope.principal
    retained.require_fresh()
    second_key, second = await journey.open()
    assert first["session_id"] != second["session_id"]
    a = await journey.request(first_key, first)
    b = await journey.request(second_key, second)
    assert a.status_code == b.status_code == 200
    assert a.json() == b.json()
    assert (await journey.request(first_key, first, method="GET")).status_code == 200


async def test_signed_session_refuses_replay_and_never_becomes_a_cookie(journey):
    key, issued = await journey.open()
    nonce = secrets.token_hex(16)
    assert (await journey.request(key, issued, nonce=nonce)).status_code == 200
    replay = await journey.request(key, issued, nonce=nonce)
    assert (replay.status_code, replay.json()["detail"]) == (401, "console_session_required")
    for headers in (
        {"Cookie": "__Host-console=" + issued["session_id"]},
        {"Cookie": "__Host-console=" + issued["session_id"], "X-Console-Key": did_key(key)},
    ):
        refused = await journey.client.get("/protected", headers=headers)
        assert (refused.status_code, refused.json()["detail"]) == (401, "console_session_required")


async def test_real_role_revocation_is_final(journey):
    key, issued = await journey.open()
    async with journey.world.db.transaction() as tx:
        await unassign(tx, PrincipalKey(TEAM, journey.scope.principal), OWNER_ROLE)
    refused = await journey.request(key, issued)
    assert (refused.status_code, refused.json()["detail"]) == (403, "role_not_held")


async def test_real_recovery_retires_login_before_changed_holding_digest(journey, monkeypatch):
    key, issued = await journey.open()
    old_target = await authority(journey.world).session_target(journey.scope)
    await _apply(
        journey.world,
        "app-credential.recover",
        PrincipalKey(TEAM, journey.scope.principal),
        "recovered@example.com",
    )
    # Complete the genuine replacement enrollment; production cooling-off is
    # retained. The initial old LOGIN already fails during cooling-off.
    token = journey.world.contacts.inbox["recovered@example.com"][-1]
    replacement = SoftAuthenticator(journey.device.origin)
    prepared = await journey.world.credential_audit.prepare_enrolment(token)
    with journey.world.credential_audit.prepared(prepared):
        new = await journey.world.passkeys.complete_enrolment(
            token,
            replacement.create(await journey.world.passkeys.enrolment_options(token)),
            fence=prepared,
        )
    assert new.subject != old_target.subject
    after_cooling = await journey.world.passkeys.recovery_pending_until(old_target.b3_scope)
    assert after_cooling is not None
    monkeypatch.setattr(
        journey.world.passkeys, "_clock", lambda: after_cooling + timedelta(seconds=1)
    )
    fresh = await authority(journey.world).session_target(journey.scope)
    assert owner_holding_identity(fresh) != owner_holding_identity(old_target)
    refused = await journey.request(key, issued)
    assert (refused.status_code, refused.json()["detail"]) == (401, "console_session_required")


async def test_collection_deletes_ended_sessions_nonces_and_handoffs(journey):
    key, issued = await journey.open()
    assert (await journey.request(key, issued)).status_code == 200
    digest = hashlib.sha256(issued["session_id"].encode()).digest()
    assert (
        await journey.world.db.fetch_value(
            "SELECT count(*) FROM {{tables.console_session_nonces}} WHERE token_sha256=$1", digest
        )
        == 1
    )
    # Advance only this real, protocol-issued session's expiry; no authority or
    # session row is seeded. The next genuine handoff must reclaim its storage.
    await journey.world.db.execute(
        "UPDATE {{tables.console_sessions}} SET expires_at=clock_timestamp()-INTERVAL '1 second' "
        "WHERE token_sha256=$1",
        digest,
    )
    await journey.open()
    assert (
        await journey.world.db.fetch_value(
            "SELECT count(*) FROM {{tables.console_sessions}} WHERE token_sha256=$1", digest
        )
        == 0
    )
    assert (
        await journey.world.db.fetch_value(
            "SELECT count(*) FROM {{tables.console_session_nonces}} WHERE token_sha256=$1", digest
        )
        == 0
    )
    assert (
        await journey.world.db.fetch_value(
            "SELECT count(*) FROM {{tables.console_handoffs}} WHERE released_at IS NOT NULL"
        )
        == 0
    )
