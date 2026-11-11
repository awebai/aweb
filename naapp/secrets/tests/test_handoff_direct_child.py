"""A session start by the holder's direct-child agent, on the real factory.

The shared factory, the real B3/owner-act holding store, the tests' AWID with
real ID chains, and the requester check bound to that registry
(handoff-wire 1a; contract 584d76c9c :382 and :459). The holder alice is
designated through the owner act; laptop is an agent alice certified; desk is
an agent laptop certified. Nothing is inserted into a certificate cache.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import secrets
import time
from datetime import UTC, datetime

import pytest
from aweb_naapp.console.handoff_requester import RequesterEvidence, requester_parent
from aweb_naapp.roles import PrincipalKey, lock_holding, read_holding
from aweb_naapp_testing import Member, did_key
from awid.id_certificates import encode_id_chain_header, id_certificate_signing_bytes
from fastapi import HTTPException
from nacl.signing import SigningKey

from aweb_secrets.owners import OWNER_ROLE
from tests.human_owner import apply_holder
from tests.test_handoff_sessions import API, b64, journey, world
from tests.test_owner_bootstrap import TEAM

__all__ = ["journey", "world"]

REQUESTER = {"requester_parent": requester_parent}


async def certify_agent(journey, parent: Member, parent_chain: list[dict], alias: str):
    """An agent that ``parent`` certified, a current member of the team."""
    agent = Member(
        team_id=TEAM, team_key=journey.member.team_key, alias=alias, certificate_id="cert-" + alias
    )
    principal = (await journey.registry.register_did(agent.did_key, bytes(agent.member_key))).did_aw
    agent.extra_cert_fields = {"member_did_aw": principal}
    await journey.world.registry.add_certificate(agent.certificate())
    fields = {
        "v": 1, "type": "aweb.id-certificate", "id": principal, "domain": "example.com",
        "parent": {"kind": "identity", "id": parent.extra_cert_fields["member_did_aw"]},
        "kind": "agent", "issuer_key": parent.did_key,
        "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    signed = {
        "certificate": fields,
        "signature": b64(parent.member_key.sign(id_certificate_signing_bytes(fields)).signature),
    }
    chain = [*parent_chain, signed]
    await journey.registry.register_id_certificate(
        {"v": 1, "type": "aweb.id-chain", "certificates": chain},
        signer=lambda payload: (agent.did_key, agent.member_key.sign(payload).signature),
        expected_head=None, invitation_id=None,
    )
    return agent, chain


def start_body(journey, purpose: str = "session") -> bytes:
    key = SigningKey.generate()
    return json.dumps({
        "v": 1, "purpose": purpose, "client_key": did_key(key), "return": "loopback",
        "redirect_uri": "http://127.0.0.1:54321/callback",
        "verifier_sha256": hashlib.sha256(secrets.token_urlsafe(32).encode()).hexdigest(),
        "scope": {"installation_id": journey.scope.installation_id, "role": journey.scope.role,
                  "principal": journey.scope.principal},
    }).encode()


async def start(journey, signer: Member, chain: list[dict] | None, purpose: str = "session"):
    raw = start_body(journey, purpose)
    headers = {"Content-Type": "application/json",
               **signer.headers(aud=API, method="POST", path="/handoffs", body=raw)}
    if chain is not None:
        headers["X-AWID-ID-Chain"] = encode_id_chain_header(
            {"v": 1, "type": "aweb.id-chain", "certificates": chain})
    return await journey.client.post(API + "/handoffs", content=raw, headers=headers)


async def handoffs(journey) -> int:
    return await journey.world.db.fetch_value("SELECT count(*) FROM {{tables.console_handoffs}}")


async def retained(journey) -> bytes | None:
    holding = await read_holding(
        journey.world.db, installation_id=journey.scope.installation_id, team_id=TEAM,
        role=OWNER_ROLE, principal=journey.scope.principal)
    return None if holding is None else holding.certificate


@pytest.mark.parametrize("journey", [REQUESTER], indirect=True)
async def test_the_first_direct_child_start_after_designation_is_admitted(journey):
    laptop, chain = await certify_agent(journey, journey.member, [journey.member.id_certificate], "laptop")
    response = await start(journey, laptop, chain)
    assert response.status_code == 201, response.text
    state = await journey.client.get(f"/handoff/{response.json()['handoff_id']}/session")
    assert state.status_code == 200, state.text
    requester = state.json()["requester"]
    assert requester["id"] == laptop.extra_cert_fields["member_did_aw"]
    assert requester["key_fingerprint"]


@pytest.mark.parametrize("journey", [REQUESTER], indirect=True)
async def test_a_grandchild_or_an_unrelated_agent_is_refused_and_creates_nothing(journey):
    laptop, chain = await certify_agent(journey, journey.member, [journey.member.id_certificate], "laptop")
    desk, desk_chain = await certify_agent(journey, laptop, chain, "desk")
    before = await handoffs(journey)
    for signer, signer_chain in ((desk, desk_chain), (laptop, None)):
        response = await start(journey, signer, signer_chain)
        assert response.status_code == 403 and response.json() == {"detail": "scope_not_signer"}
    assert await handoffs(journey) == before


@pytest.mark.parametrize("journey", [REQUESTER], indirect=True)
async def test_a_renewed_holder_certificate_refuses_until_the_holders_credential_start_refreshes_it(journey):
    laptop, chain = await certify_agent(journey, journey.member, [journey.member.id_certificate], "laptop")
    old = await retained(journey)
    # Renewal: a new certificate under alice's same key; the old one revoked.
    renewed = Member(team_id=TEAM, team_key=journey.member.team_key, member_key=journey.member.member_key,
                     alias="alice", certificate_id="cert-1-renewed",
                     extra_cert_fields=dict(journey.member.extra_cert_fields))
    await journey.world.registry.add_certificate(renewed.certificate())
    await journey.world.registry.revoke(journey.member.certificate_id)

    refused = await start(journey, laptop, chain)
    assert refused.status_code == 403 and refused.json() == {"detail": "principal_not_member"}
    assert await retained(journey) == old

    # The holder's own credential start refreshes at acceptance: no
    # registration, no new passkey, no owner act.
    accepted = await start(journey, renewed, None, purpose="credential")
    assert accepted.status_code == 201, accepted.text
    assert await retained(journey) != old

    admitted = await start(journey, laptop, chain)
    assert admitted.status_code == 201, admitted.text


@pytest.mark.parametrize("journey", [REQUESTER], indirect=True)
async def test_a_failed_credential_start_verification_refreshes_nothing(journey):
    old = await retained(journey)
    stranger = Member(team_id=TEAM, team_key=SigningKey.generate(), member_key=journey.member.member_key,
                      alias="alice", certificate_id="cert-forged",
                      extra_cert_fields=dict(journey.member.extra_cert_fields))
    response = await start(journey, stranger, None, purpose="credential")
    # Team-auth refuses a certificate under another team key before any effect.
    assert response.status_code in (401, 403)
    assert await retained(journey) == old


@pytest.mark.parametrize("journey", [REQUESTER], indirect=True)
async def test_concurrent_credential_starts_on_one_holding_both_complete(journey):
    # Both starts' refreshes are seen waiting on the held holding row, so
    # their transactions overlap when it is released; a deadlock fails the bound.
    async with joined() as tasks:
        async with holding_locked(journey) as blocker:
            for _ in range(2):
                tasks.append(asyncio.create_task(start(journey, journey.member, None, purpose="credential")))
            await blocked_on(journey, blocker, count=2)
        responses = await asyncio.wait_for(asyncio.gather(*tasks), timeout=BOUND)
    assert [r.status_code for r in responses] == [201, 201], [r.text for r in responses]
    assert await retained(journey) is not None


@pytest.mark.parametrize("journey", [REQUESTER], indirect=True)
async def test_a_credential_start_whose_holding_proof_fails_refreshes_nothing(journey):
    # Properly authenticated as alice, but the holding-specific membership
    # check cannot confirm her: the start proceeds and nothing is refreshed.
    old = await retained(journey)

    async def unavailable(team_id, *, principal, certificate):
        raise HTTPException(503, "principal_status_unavailable")

    journey.factory.human_member = unavailable
    response = await start(journey, journey.member, None, purpose="credential")
    assert response.status_code == 201, response.text
    assert await retained(journey) == old


BOUND = 30  # seconds: any wait in these tests fails past it rather than hanging


class ShortWindowOnce:
    """The real requester check, whose first verdict keeps only a short
    original window (recorded in ``deadline``), so the test can cross it while
    the start is blocked on the holding."""

    def __init__(self, registry):
        self.real = requester_parent(registry)
        self.deadline: int | None = None

    async def __call__(self, request, signer):
        evidence = await self.real(request, signer)
        if evidence is not None and self.deadline is None:
            self.deadline = time.monotonic_ns() + 100_000_000
            return RequesterEvidence(evidence.parent, self.deadline)
        return evidence


short_windows: list[ShortWindowOnce] = []


def short_window_once(registry):
    check = ShortWindowOnce(registry)
    short_windows.append(check)
    return check


@contextlib.asynccontextmanager
async def holding_locked(journey):
    """Hold alice's holding row FOR UPDATE, as a concurrent owner act would;
    yields the holding backend's pid."""
    async with journey.world.db.transaction() as tx:
        held = await lock_holding(
            tx, installation_id=journey.scope.installation_id, team_id=TEAM,
            role=OWNER_ROLE, principal=journey.scope.principal)
        assert held is not None
        yield await tx.fetch_value("SELECT pg_backend_pid()")


# Backends waiting on ``$1`` directly or through another waiter: a row's
# second waiter queues on the first waiter's tuple lock, not on the holder.
WAIT_CHAIN = """
WITH RECURSIVE waiters(pid) AS (
    SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))
    UNION
    SELECT a.pid FROM pg_stat_activity a JOIN waiters w ON w.pid = ANY(pg_blocking_pids(a.pid))
)
SELECT count(*) FROM waiters
"""


async def blocked_on(journey, blocker: int, *, count: int) -> None:
    """Wait, bounded, until ``count`` backends wait on ``blocker``'s locks."""

    async def waiting() -> None:
        while await journey.world.db.fetch_value(WAIT_CHAIN, blocker) < count:
            await asyncio.sleep(0.01)

    await asyncio.wait_for(waiting(), timeout=BOUND)


@contextlib.asynccontextmanager
async def joined():
    """Tasks the body starts; on any failure they are cancelled and joined."""
    tasks: list[asyncio.Task] = []
    try:
        yield tasks
    finally:
        pending = [task for task in tasks if not task.done()]
        for task in pending:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.parametrize("journey", [{"requester_parent": short_window_once}], indirect=True)
async def test_a_requester_window_crossed_during_a_lock_wait_creates_nothing(journey):
    check = short_windows[-1]
    laptop, chain = await certify_agent(journey, journey.member, [journey.member.id_certificate], "laptop")
    before = await handoffs(journey)
    async with joined() as tasks:
        async with holding_locked(journey) as blocker:
            waiting = asyncio.create_task(start(journey, laptop, chain))
            tasks.append(waiting)
            await blocked_on(journey, blocker, count=1)
            # Cross the recorded deadline while the start is blocked on the holding.
            assert check.deadline is not None
            await asyncio.sleep(max(0, check.deadline - time.monotonic_ns()) / 1e9 + 0.05)
            assert time.monotonic_ns() > check.deadline and not waiting.done()
        expired = await asyncio.wait_for(waiting, timeout=BOUND)
    assert expired.status_code == 503 and expired.json() == {"detail": "principal_status_unavailable"}
    assert await handoffs(journey) == before
    fresh = await start(journey, laptop, chain)
    assert fresh.status_code == 201, fresh.text


@pytest.mark.parametrize("journey", [REQUESTER], indirect=True)
async def test_a_credential_replace_racing_a_credential_start_both_complete(journey):
    # The owner's replace and the holder's credential start both take the
    # holding for writing; queued behind the lock they overlap on release.
    # Neither deadlocks, and the holding keeps a retained certificate.
    who = PrincipalKey(TEAM, journey.scope.principal)
    async with joined() as tasks:
        async with holding_locked(journey) as blocker:
            tasks.append(asyncio.create_task(apply_holder(
                journey.world, "human-credential.replace", who, "holder@example.com",
                member=journey.member, client=journey.registry)))
            tasks.append(asyncio.create_task(start(journey, journey.member, None, purpose="credential")))
            await blocked_on(journey, blocker, count=2)
        _, response = await asyncio.wait_for(asyncio.gather(*tasks), timeout=BOUND)
    assert response.status_code == 201, response.text
    assert await retained(journey) is not None
