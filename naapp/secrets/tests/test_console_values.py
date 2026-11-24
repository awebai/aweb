"""Native TLS ingress against installation, hooks and holder set up through product routes."""

import asyncio
import base64
import hashlib
import json
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from enum import StrEnum
from http import HTTPStatus
from time import monotonic_ns
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from aweb_naapp import roles
from aweb_naapp.console import COOKIE_NAME
from aweb_naapp.runtime.app_credentials import APP_GRANT_READ, AppCredentialSigner
from aweb_naapp.runtime.app_keys import load_app_key
from aweb_naapp.runtime.clock import seconds_to_ns
from aweb_naapp.runtime.passkeys import contact_sha256
from aweb_naapp.runtime.team_grants import AppIdentity, TeamGrantSource
from aweb_naapp_testing.owner_acts import TeamOwner
from aweb_naapp_testing.webauthn import SoftAuthenticator

from aweb_secrets.app import installation_fence
from aweb_secrets.console_values import ValueStagingCode
from aweb_secrets.custody import (
    Custody,
    CustodyUnavailable,
    LocalKeyFileProvider,
    SealContext,
    decode_value,
)
from aweb_secrets.erasure import ErasureFailure
from aweb_secrets.owners import OWNER_ROLE, approver_scope
from aweb_secrets.secret import SecretBackend, SecretKind
from tests.human_owner import b64, holder_credential
from tests.test_change_sets import SECRET_ID
from tests.test_console_bootstrap import delivered_url
from tests.test_owner_delivery import PATH as OWNER_ACT_PATH
from tests.test_production_bootstrap import mounted_owner_verifier
from tests.test_production_routed_owner import ROUTED_GRANT_SECONDS, RoutedOwner
from tests.test_production_routed_owner import (
    enrolled_validation_owner as enrolled_validation_owner,
)
from tests.test_production_routed_owner import production_routed_owner as production_routed_owner
from tests.test_production_routed_owner import (
    production_routed_validation_owner as production_routed_validation_owner,
)
from tests.test_production_routed_owner import routed_anonymous_client as routed_anonymous_client
from tests.test_production_routed_owner import routed_owner_batch as routed_owner_batch

EXPIRING_GRANT_SECONDS = 3
GOVERNANCE_HOOK = "post-governance-hook"

pytestmark = pytest.mark.asyncio(loop_scope="module")


def token_path(world: RoutedOwner) -> str:
    return (
        f"/installations/{world.installation['installation_id']}"
        "/backend-credentials/onepassword/versions"
    )


async def login(client: httpx.AsyncClient, scope: str, device: SoftAuthenticator) -> str:
    options = await client.post("/login/options", json={"scope": scope})
    assert options.status_code == HTTPStatus.OK
    logged = await client.post(
        "/login", json={"scope": scope, "assertion": device.get(options.json())}
    )
    assert logged.status_code == HTTPStatus.OK
    csrf = logged.json()["csrf_token"]
    assert isinstance(csrf, str) and csrf
    return csrf


_FIXED_REFUSALS = (
    frozenset(ValueStagingCode)
    | frozenset(ErasureFailure)
    | {
        "authority_unavailable",
        "generation_superseded",
        "installation_inactive",
        "owner_act_refused",
        "principal_not_member",
        "principal_status_unavailable",
        "release_context_unavailable",
    }
)


def response_status(response: httpx.Response) -> str:
    """Report only allowlisted codes, never bodies or values sent to ingress."""
    try:
        body = response.json()
    except ValueError:
        return f"HTTP {response.status_code}"
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, str) and detail in _FIXED_REFUSALS:
        return f"HTTP {response.status_code} ({detail})"
    return f"HTTP {response.status_code}"


def no_value(response, value):
    if value in response.text:
        raise AssertionError("submitted value appeared in response")


async def test_owner_token_ingress_is_sealed_scoped_inert_and_never_echoed(production_routed_owner):
    world = production_routed_owner
    production_client = world.client
    db = world.service.runtime.db()
    path = token_path(world)
    value = os.urandom(24).hex()
    csrf = await login(production_client, world.holder.scope, world.holder.device)
    response = await production_client.post(
        path, json={"value": value}, headers={"X-CSRF-Token": csrf}
    )
    assert response.status_code == HTTPStatus.CREATED, response_status(response)
    assert response.json() == {
        "v": 1,
        "backend": SecretBackend.ONEPASSWORD,
        "credential_id": "bkc_onepassword",
        "version": 1,
    }
    assert response.headers["cache-control"] == "no-store"
    no_value(response, value)
    # Both listeners use the fixture CA. Send to the actual agent origin.
    agent_response = await production_client.post(
        world.settings.public_origin + path, json={"value": value}
    )
    assert agent_response.status_code == HTTPStatus.NOT_FOUND
    no_value(agent_response, value)
    custody = Custody(LocalKeyFileProvider(world.settings.custody_key_file), db)
    context = SealContext(
        installation_id=world.installation["installation_id"],
        team_id=world.member.team_id,
        secret_id="bkc_onepassword",
        version=1,
    )
    opened = await custody.backend_credential_preview.open(context)
    if decode_value(SecretKind.BEARER, opened.plaintext.reveal())["value"] != value:
        raise AssertionError("sealed token differs from entered token")
    with pytest.raises(CustodyUnavailable):
        await custody.backend_credential_opener.open(context)
    with pytest.raises(CustodyUnavailable):
        await custody.opener.open(context)
    assert (
        await db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
        is None
    )
    assert await db.fetch_value("SELECT count(*) FROM {{tables.secrets}}") == 0
    for row in await db.fetch_all("SELECT * FROM {{tables.sealed_versions}}"):
        if value in str(dict(row)):
            raise AssertionError("entered token present as plaintext in custody")


async def test_ingress_requires_login_and_this_tabs_csrf_before_any_allocation(
    production_routed_validation_owner,
    routed_anonymous_client,
):
    world = production_routed_validation_owner
    production_client = world.client
    path = token_path(world)
    value = os.urandom(24).hex()
    anonymous = await routed_anonymous_client.post(path, json={"value": value})
    assert anonymous.status_code == HTTPStatus.UNAUTHORIZED
    no_value(anonymous, value)
    response = await production_client.post(path, json={"value": value})
    assert response.status_code == HTTPStatus.FORBIDDEN
    assert response.json() == {"detail": "csrf_token_required"}
    no_value(response, value)
    assert (
        await world.service.runtime.db().fetch_value(
            "SELECT count(*) FROM {{tables.custody_secrets}}"
        )
        == 0
    )


@pytest.mark.parametrize(
    "body",
    [{"value": ""}, {"value": {}}, {"value": 1}, {}, {"value": "x", "team_id": "another-team"}],
)
async def test_invalid_ingress_body_is_constant_and_allocates_nothing(
    production_routed_validation_owner, body
):
    world = production_routed_validation_owner
    production_client = world.client
    csrf = world.holder.csrf_token
    response = await production_client.post(
        token_path(world), json=body, headers={"X-CSRF-Token": csrf}
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json() == {"detail": "request_invalid"}
    assert (
        await world.service.runtime.db().fetch_value(
            "SELECT count(*) FROM {{tables.custody_secrets}}"
        )
        == 0
    )


async def test_ingress_json_and_scope_fail_without_reflecting_submitted_bytes(
    production_routed_validation_owner,
):
    world = production_routed_validation_owner
    production_client = world.client
    path = token_path(world)
    csrf = world.holder.csrf_token
    headers = {"X-CSRF-Token": csrf}
    value = os.urandom(24).hex()
    response = await production_client.post(
        path, content=value, headers={**headers, "Content-Type": "text/plain"}
    )
    assert response.status_code == HTTPStatus.UNSUPPORTED_MEDIA_TYPE
    no_value(response, value)
    response = await production_client.post(
        path, content=value, headers={**headers, "Content-Type": "application/json"}
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST
    no_value(response, value)
    installation_id = world.installation["installation_id"]
    response = await production_client.post(
        path.replace(installation_id, "another-installation"),
        json={"value": value},
        headers=headers,
    )
    assert response.status_code == HTTPStatus.FORBIDDEN
    no_value(response, value)
    assert (
        await world.service.runtime.db().fetch_value(
            "SELECT count(*) FROM {{tables.custody_secrets}}"
        )
        == 0
    )


class OwnerAct(StrEnum):
    REVOKE = "human-role.revoke"
    REPLACE = "human-credential.replace"


class FenceFailure(StrEnum):
    STALE = "stale"
    GENERATION = "generation"


async def signed_owner_action(world: RoutedOwner, act: OwnerAct) -> dict:
    verifier = mounted_owner_verifier(world.service)
    owner = TeamOwner(world.member.team_key, verifier, world.member.team_id)
    subject = {
        "app_id": world.settings.app_id,
        "installation_id": world.installation["installation_id"],
        "role": OWNER_ROLE,
        "principal": world.holder.body["principal"],
    }
    body = {}
    if act is OwnerAct.REPLACE:
        held = await roles.read_holding(
            world.service.runtime.db(),
            installation_id=world.installation["installation_id"],
            team_id=world.member.team_id,
            role=OWNER_ROLE,
            principal=world.holder.body["principal"],
        )
        assert held is not None and held.certificate is not None
        _, credential = holder_credential(world.settings.console_origin)
        contact = world.holder.body["contact"]
        subject.update(
            credential_sha256=credential.sha256,
            notice_contact_sha256=contact_sha256(contact),
        )
        body.update(
            credential={
                "credential_id": b64(credential.credential_id),
                "public_key": b64(credential.public_key),
                "rp_id": credential.rp_id,
            },
            certificate=base64.b64encode(held.certificate).decode(),
            notice_contact=contact,
        )
    signing, signature = owner.sign(act, subject)
    return {**body, "signing": base64.b64encode(signing).decode(), "signature": signature}


async def deliver_owner_action(world: RoutedOwner, body: dict) -> httpx.Response:
    request = world.client.build_request("POST", OWNER_ACT_PATH, json=body, timeout=15)
    # The signed delivery route admits controller acts alone. It explicitly
    # refuses a request that also carries the owner's console cookie.
    request.headers.pop("cookie", None)
    return await world.client.send(request)


async def post_token(world: RoutedOwner, *, value: str | None = None) -> httpx.Response:
    return await world.client.post(
        token_path(world),
        json={"value": value if value is not None else os.urandom(24).hex()},
        headers={"X-CSRF-Token": world.holder.csrf_token},
        timeout=ROUTED_GRANT_SECONDS + 15,
    )


async def blocked_pid(db, blocker: int, request: asyncio.Task, *, relation: str) -> int:
    """Wait for this blocker and relation, so a different wait can't pass."""
    async with asyncio.timeout(10):
        while not (
            pid := await db.fetch_value(
                "SELECT pid FROM pg_stat_activity "
                "WHERE $1 = ANY(pg_blocking_pids(pid)) AND query ILIKE '%' || $2 || '%' LIMIT 1",
                blocker,
                relation,
            )
        ):
            if request.done():
                response = await request
                pytest.fail(
                    f"request returned {response_status(response)} before waiting on {relation}"
                )
            await asyncio.sleep(0.01)
    return pid


async def wait_for_grant_expiry(world: RoutedOwner, *, deadline: int = 0) -> None:
    db = world.service.runtime.db()
    async with asyncio.timeout(ROUTED_GRANT_SECONDS + 5):
        while monotonic_ns() < deadline or await db.fetch_value(
            "SELECT fresh_until > clock_timestamp() FROM {{tables.installation_fences}} "
            "WHERE installation_id=$1",
            world.installation["installation_id"],
        ):
            await asyncio.sleep(0.02)


async def action_during_lookup(world: RoutedOwner, act: OwnerAct) -> httpx.Response:
    """Hold a real holder row while the act reaches its effect transaction.

    The act holds F6 in share mode. The ingress captures its valid S4 proof
    and blocks trying to refresh F6 until the act ends the holding or retires
    the credential. The locks schedule real actions; they write no authority.
    """
    db = world.service.runtime.db()
    body = await signed_owner_action(world, act)
    action = posting = None
    try:
        async with db.transaction() as gate:
            gate_pid = await gate.fetch_value("SELECT pg_backend_pid()")
            assert (
                await gate.fetch_value(
                    "SELECT b3_scope FROM {{tables.role_holdings}} WHERE b3_scope=$1 FOR UPDATE",
                    world.holder.scope,
                )
                == world.holder.scope
            )
            action = asyncio.create_task(deliver_owner_action(world, body))
            actor_pid = await blocked_pid(db, gate_pid, action, relation="role_holdings")
            posting = asyncio.create_task(post_token(world))
            await blocked_pid(db, actor_pid, posting, relation="installation_fences")
        applied, response = await asyncio.wait_for(asyncio.gather(action, posting), 15)
        assert applied.status_code == HTTPStatus.OK, response_status(applied)
        assert applied.json()["act"] == act
        return response
    finally:
        tasks = [task for task in (action, posting) if task is not None]
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def test_owner_role_revoked_during_lookup_cannot_enter_a_token(production_routed_owner):
    world = production_routed_owner
    response = await action_during_lookup(world, OwnerAct.REVOKE)
    assert response.status_code == HTTPStatus.FORBIDDEN
    assert response.json() == {"detail": "owner_required"}
    assert (
        await world.service.runtime.db().fetch_value(
            "SELECT count(*) FROM {{tables.custody_secrets}}"
        )
        == 0
    )


async def advance_generation(world: RoutedOwner) -> None:
    installed = world.installation
    server = world.coordination.server
    path = "/v1/apps/install"
    raw = json.dumps(
        {
            "app_id": installed["app_id"],
            "origin": installed["origin"],
            "digest": installed["digest"],
            "granted_scopes": installed["granted_scopes"],
            "expected_generation": installed["generation"],
        }
    ).encode()
    headers = world.member.headers(aud=server.url, method="POST", path=path, body=raw)
    async with server.client() as client:
        updated = await client.post(
            path, content=raw, headers={**headers, "Content-Type": "application/json"}
        )
    assert updated.status_code == HTTPStatus.OK
    receipt = updated.json()
    assert receipt["installation_id"] == installed["installation_id"]
    assert receipt["generation"] > installed["generation"]

    # A second ordinary grant cache reads the new installation from the real
    # server. Keep the ingress replica's genuine unexpired receipt untouched.
    runtime = world.service.runtime
    grants = TeamGrantSource(
        identity=AppIdentity(
            app_id=installed["app_id"], origin=installed["origin"], digest=installed["digest"]
        ),
        signer=AppCredentialSigner(
            app_id=installed["app_id"],
            key=load_app_key(world.settings, runtime.manifest, APP_GRANT_READ),
            purpose=APP_GRANT_READ,
        ),
        discovery=runtime.team_server_directory(),
        transport=server.transport,
    )
    fence = installation_fence(runtime.db(), app_id=installed["app_id"], grants=grants)
    observed = await fence.permit(world.member.team_id)
    assert observed.admitted.generation == receipt["generation"]


async def post_during_expiry(
    world: RoutedOwner,
    monkeypatch,
    *,
    relation: str,
    lock_query: str,
    arguments: tuple,
    value: str | None = None,
) -> httpx.Response:
    db = world.service.runtime.db()
    fence = world.service.runtime.installation_fence()
    previous = await fence.permit(world.member.team_id)
    # Use the server's advertised policy and PostgreSQL's unchanged timeout.
    # The waiter can then see the full freshness window pass under the lock.
    assert await db.fetch_value("SHOW lock_timeout") == "5s"
    monkeypatch.setenv("AWEB_APP_GRANT_MAX_AGE_SECONDS", str(EXPIRING_GRANT_SECONDS))
    await wait_for_grant_expiry(world, deadline=previous.status.fresh_until)
    permit = await fence.permit(world.member.team_id)
    deadline = permit.status.fresh_until
    assert 0 < deadline - monotonic_ns() <= seconds_to_ns(EXPIRING_GRANT_SECONDS)
    posting = None
    try:
        async with db.transaction() as gate:
            gate_pid = await gate.fetch_value("SELECT pg_backend_pid()")
            assert await gate.fetch_value(lock_query, *arguments) is not None
            posting = asyncio.create_task(post_token(world, value=value))
            await blocked_pid(db, gate_pid, posting, relation=relation)
            assert monotonic_ns() < deadline, "the request did not block with a fresh grant"
            await wait_for_grant_expiry(world, deadline=deadline)
        return await asyncio.wait_for(posting, 10)
    finally:
        if posting is not None:
            if not posting.done():
                posting.cancel()
            await asyncio.gather(posting, return_exceptions=True)


@pytest.mark.parametrize(
    "failure,status,code",
    [
        (FenceFailure.STALE, HTTPStatus.SERVICE_UNAVAILABLE, "authority_unavailable"),
        (FenceFailure.GENERATION, HTTPStatus.CONFLICT, "generation_superseded"),
    ],
)
async def test_ingress_preserves_f6_status_and_allocates_nothing(
    production_routed_owner, monkeypatch, failure, status, code
):
    world = production_routed_owner
    value = os.urandom(24).hex()
    if failure is FenceFailure.STALE:
        response = await post_during_expiry(
            world,
            monkeypatch,
            relation="installation_fences",
            lock_query="SELECT generation FROM {{tables.installation_fences}} "
            "WHERE installation_id=$1 FOR UPDATE",
            arguments=(world.installation["installation_id"],),
            value=value,
        )
    else:
        # Retain a fresh old-generation receipt in the ingress replica before
        # the independent replica publishes the newly installed generation.
        fence = world.service.runtime.installation_fence()
        previous = await fence.permit(world.member.team_id)
        await wait_for_grant_expiry(world, deadline=previous.status.fresh_until)
        actual = await fence.permit(world.member.team_id)
        assert actual.admitted.generation == world.installation["generation"]
        await advance_generation(world)
        response = await post_token(world, value=value)
    assert response.status_code == status, response_status(response)
    assert response.json() == {"detail": code}
    no_value(response, value)
    assert (
        await world.service.runtime.db().fetch_value(
            "SELECT count(*) FROM {{tables.custody_secrets}}"
        )
        == 0
    )


async def test_login_evidence_retired_during_lookup_cannot_stage_a_token(production_routed_owner):
    world = production_routed_owner
    original_session = hashlib.sha256(world.client.cookies[COOKIE_NAME].encode()).digest()
    response = await action_during_lookup(world, OwnerAct.REPLACE)
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert "Max-Age=0" in response.headers["set-cookie"]
    db = world.service.runtime.db()
    assert await db.fetch_value(
        "SELECT closed_at IS NOT NULL FROM {{tables.console_sessions}} WHERE token_sha256=$1",
        original_session,
    )
    assert await db.fetch_value("SELECT count(*) FROM {{tables.custody_secrets}}") == 0


def mail_token(world: RoutedOwner, start: int, *, contact: str, path: str) -> str:
    link = delivered_url(world.smtp.received[start:], contact=contact, path=path)
    [token] = parse_qs(urlsplit(link).fragment)["token"]
    return token


async def enrol_contact_approver(
    world: RoutedOwner, *, ref: str, contact: str
) -> SoftAuthenticator:
    change_root = f"/installations/{world.installation['installation_id']}/change-sets"
    headers = {"X-CSRF-Token": world.holder.csrf_token}
    mail_before = len(world.smtp.received)
    drafted = await world.client.post(
        change_root,
        json={
            "reason": "Designate a contact approver",
            "sealed": [],
            "changes": [
                {
                    "kind": "approver",
                    "op": "create",
                    "ref": ref,
                    "after": {
                        "v": 1,
                        "approver_ref": ref,
                        "contact": contact,
                        "covers": [SECRET_ID],
                        "principal": None,
                    },
                }
            ],
        },
        headers=headers,
    )
    assert drafted.status_code == HTTPStatus.CREATED
    change = f"{change_root}/{drafted.json()['change_id']}"
    token = mail_token(world, mail_before, contact=world.holder.body["contact"], path="/approvals")
    options = await world.client.post(
        change + "/approval-options", json={"token": token}, headers=headers
    )
    assert options.status_code == HTTPStatus.OK
    approved = await world.client.post(
        change + "/approve",
        json={"token": token, "assertion": world.holder.device.get(options.json())},
        headers=headers,
    )
    assert approved.status_code == HTTPStatus.OK
    mail_before = len(world.smtp.received)
    confirmed = await world.client.post(change + "/confirm", json={}, headers=headers)
    assert confirmed.status_code == HTTPStatus.OK
    token = mail_token(world, mail_before, contact=contact, path="/enrolment")
    world.client.cookies.clear()
    device = SoftAuthenticator(world.settings.console_origin)
    options = await world.client.post("/enrolment/options", json={"link_token": token})
    assert options.status_code == HTTPStatus.OK
    enrolled = await world.client.post(
        "/enrolment",
        json={"link_token": token, "credential": device.create(options.json())},
    )
    assert enrolled.status_code == HTTPStatus.OK
    assert enrolled.json()["scope"] == approver_scope(
        world.installation["installation_id"], world.member.team_id, ref
    )
    return device


async def test_current_approver_session_has_no_backend_credential_ingress_authority(
    production_routed_owner,
):
    world = production_routed_owner
    ref = "finance"
    device = await enrol_contact_approver(world, ref=ref, contact="finance@example.com")
    scope = approver_scope(world.installation["installation_id"], world.member.team_id, ref)
    csrf = await login(world.client, scope, device)
    response = await world.client.post(
        token_path(world),
        json={"value": os.urandom(24).hex()},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == HTTPStatus.FORBIDDEN
    assert response.json() == {"detail": "owner_required"}
    assert (
        await world.service.runtime.db().fetch_value(
            "SELECT count(*) FROM {{tables.custody_secrets}}"
        )
        == 0
    )


@asynccontextmanager
async def pause_revocation_view(
    world: RoutedOwner, monkeypatch
) -> AsyncIterator[tuple[asyncio.Event, asyncio.Event]]:
    """Hold a genuine governance reply after the revoke's F6 admission."""
    transport = world.coordination.server.transport
    forward = transport.handle_async_request
    observed = asyncio.Event()
    resume = asyncio.Event()

    async def request(incoming: httpx.Request) -> httpx.Response:
        response = await forward(incoming)
        if (
            not observed.is_set()
            and incoming.headers.get("X-AWEB-Team-ID") == world.member.team_id
            and incoming.url.path.endswith(f"/{GOVERNANCE_HOOK}/registrations")
        ):
            assert response.status_code == HTTPStatus.OK
            observed.set()
            await resume.wait()
        return response

    with monkeypatch.context() as patch:
        patch.setattr(transport, "handle_async_request", request)
        try:
            yield observed, resume
        finally:
            resume.set()


PARENT_LOCK = (
    "SELECT credential_id FROM {{tables.onepassword_credentials}} "
    "WHERE installation_id=$1 AND team_id=$2 FOR UPDATE"
)


async def wait_for_idle_governance(world: RoutedOwner) -> None:
    """Let the prior designation drain before observing a new governance read."""
    runtime = world.service.runtime
    team_id = world.member.team_id
    async with asyncio.timeout(ROUTED_GRANT_SECONDS + 10):
        while await runtime.db().fetch_value(
            "SELECT EXISTS(SELECT 1 FROM {{tables.outbox_events}} "
            "WHERE team_id=$1 AND kind=$2 AND drained_at IS NULL)",
            team_id,
            GOVERNANCE_HOOK,
        ):
            await asyncio.sleep(0.02)
        view = await runtime.hook_registrations().view(team_id, GOVERNANCE_HOOK)
        assert view is not None
        while view.is_fresh(datetime.now(UTC)):
            await asyncio.sleep(0.02)


async def test_owner_role_revocation_waits_for_the_real_ingress_transaction(
    production_routed_owner, monkeypatch
):
    world = production_routed_owner
    db = world.service.runtime.db()
    staged = await post_token(world)
    assert staged.status_code == HTTPStatus.CREATED, response_status(staged)
    await wait_for_idle_governance(world)
    body = await signed_owner_action(world, OwnerAct.REVOKE)
    posting = revoking = None
    async with pause_revocation_view(world, monkeypatch) as (observed, resume):
        try:
            revoking = asyncio.create_task(deliver_owner_action(world, body))
            await asyncio.wait_for(observed.wait(), 10)
            async with db.transaction() as gate:
                gate_pid = await gate.fetch_value("SELECT pg_backend_pid()")
                await gate.fetch_value(
                    PARENT_LOCK, world.installation["installation_id"], world.member.team_id
                )
                posting = asyncio.create_task(post_token(world))
                ingress_pid = await blocked_pid(
                    db, gate_pid, posting, relation="onepassword_credentials"
                )
                resume.set()
                revoker_pid = await blocked_pid(
                    db, ingress_pid, revoking, relation="role_assignments"
                )
                assert ingress_pid != revoker_pid and gate_pid != ingress_pid
            response, revoked = await asyncio.wait_for(asyncio.gather(posting, revoking), 15)
            assert response.status_code == HTTPStatus.CREATED and response.json()["version"] == 2, (
                response_status(response)
            )
            assert revoked.status_code == HTTPStatus.OK, response_status(revoked)
            assert (await post_token(world)).status_code == HTTPStatus.UNAUTHORIZED
        finally:
            resume.set()
            tasks = [task for task in (posting, revoking) if task is not None]
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    assert (
        await db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
        is None
    )
    assert await db.fetch_value("SELECT last_version FROM {{tables.custody_secrets}}") == 2


async def test_expired_f6_after_wait_rolls_back_the_new_token_version(
    production_routed_owner, monkeypatch
):
    world = production_routed_owner
    db = world.service.runtime.db()
    await wait_for_grant_expiry(world)
    staged = await post_token(world)
    assert staged.status_code == HTTPStatus.CREATED, response_status(staged)
    response = await post_during_expiry(
        world,
        monkeypatch,
        relation="onepassword_credentials",
        lock_query=PARENT_LOCK,
        arguments=(world.installation["installation_id"], world.member.team_id),
    )
    assert response.status_code == HTTPStatus.SERVICE_UNAVAILABLE, response_status(response)
    assert response.json() == {"detail": "authority_unavailable"}
    assert await db.fetch_value("SELECT last_version FROM {{tables.custody_secrets}}") == 1
    assert await db.fetch_value("SELECT count(*) FROM {{tables.sealed_versions}}") == 1
    assert (
        await db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
        is None
    )
