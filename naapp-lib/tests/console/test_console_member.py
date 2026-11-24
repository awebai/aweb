"""The console session's member answer on real PostgreSQL: each scope's answer
is asked on every cookie request, a definite refusal ends the session, an
unreadable one refuses only the request, and a proof's own deadline holds at
the effect fence."""

import asyncio
from dataclasses import dataclass, field, replace

import pytest
from aweb_naapp_testing import Member
from aweb_naapp_testing.human_members import registered_human
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN
from fastapi import HTTPException

from aweb_naapp.console import ConsoleSessions, ContactEnrolment, ScopeMember, session_is_current
from aweb_naapp.runtime import human_member
from aweb_naapp.runtime.human_member import HumanMemberProof, check_human_member
from aweb_naapp.runtime.team_auth import AWIDTeamCache
from tests.console.support import OWNER_A, OWNER_B, Console
from tests.console.test_console_session import (
    Owner,
    _client,
    _login,
    _session,
    owners,  # noqa: F401
)

TEAM = "people:example.com"
WINDOW_NS = 61 * 1_000_000_000


@dataclass
class Members:
    """An app's answers: the scopes it names, and a refusal for any other."""

    answers: dict[str, ScopeMember | HTTPException] = field(default_factory=dict)

    async def __call__(self, scope: str) -> ScopeMember:
        answer = self.answers.get(scope, HTTPException(403, "principal_not_member"))
        if isinstance(answer, HTTPException):
            raise answer
        return answer


def _sessions(console: Console, members: Members) -> ConsoleSessions:
    return ConsoleSessions(
        console.db, passkeys=console.passkeys, scopes=console.admits, member=members
    )


async def _open(console: Console) -> int:
    return await console.db.fetch_value(
        "SELECT count(*) FROM {{tables.console_sessions}} WHERE closed_at IS NULL"
    )


@pytest.mark.parametrize("code", ["principal_not_member", "principal_not_human"])
async def test_a_definite_refusal_closes_the_session(
    console: Console,
    owners: dict[str, Owner],  # noqa: F811
    code: str,
) -> None:
    members = Members({OWNER_A: ContactEnrolment()})
    async with await _client(_sessions(console, members)) as client:
        cookie, _ = await _login(client, owners)
        assert (await client.get("/whoami", headers={"Cookie": cookie})).status_code == 200
        members.answers[OWNER_A] = HTTPException(403, code)
        refused = await client.get("/whoami", headers={"Cookie": cookie})
        assert (refused.status_code, refused.json()) == (403, {"detail": code})
        assert "Max-Age=0" in refused.headers["set-cookie"]
        assert await _open(console) == 0
        members.answers[OWNER_A] = ContactEnrolment()
        again = await client.get("/whoami", headers={"Cookie": cookie})
        assert again.status_code == 401


async def test_an_unreadable_status_keeps_the_session(
    console: Console,
    owners: dict[str, Owner],  # noqa: F811
) -> None:
    members = Members({OWNER_A: HTTPException(503, "principal_status_unavailable")})
    async with await _client(_sessions(console, members)) as client:
        cookie, _ = await _login(client, owners)
        refused = await client.get("/whoami", headers={"Cookie": cookie})
        assert (refused.status_code, refused.json()) == (
            503,
            {"detail": "principal_status_unavailable"},
        )
        assert "set-cookie" not in refused.headers
        members.answers[OWNER_A] = ContactEnrolment()
        assert (await client.get("/whoami", headers={"Cookie": cookie})).status_code == 200


async def test_a_contact_scope_is_admitted_and_an_unnamed_scope_is_not(
    console: Console,
    owners: dict[str, Owner],  # noqa: F811
) -> None:
    members = Members({OWNER_A: ContactEnrolment()})
    async with await _client(_sessions(console, members)) as client:
        contact, _ = await _login(client, owners, OWNER_A)
        unnamed, _ = await _login(client, owners, OWNER_B)
        assert (await client.get("/whoami", headers={"Cookie": contact})).status_code == 200
        assert (await client.get("/whoami", headers={"Cookie": unnamed})).status_code == 403


async def test_a_wrong_csrf_token_is_refused_before_the_member_is_asked(
    console: Console,
    owners: dict[str, Owner],  # noqa: F811
) -> None:
    members = Members({OWNER_A: HTTPException(503, "principal_status_unavailable")})
    async with await _client(_sessions(console, members)) as client:
        cookie, csrf = await _login(client, owners)
        wrong = await client.post("/change", headers={"Cookie": cookie, "X-CSRF-Token": "wrong"})
        assert (wrong.status_code, wrong.json()) == (403, {"detail": "csrf_token_required"})
        right = await client.post("/change", headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert right.status_code == 503


@pytest.fixture
async def proof(registry) -> HumanMemberProof:
    member = Member(team_id=TEAM)
    await registry.add_team(TEAM, member.team_did_key)
    async with registered_human(registry, member) as human:
        return await check_human_member(
            AWIDTeamCache(
                registry_url=REGISTRY_URL,
                ttl_seconds=60,
                service_token=SERVICE_TOKEN,
                transport=registry.transport,
            ),
            human.client,
            team_id=TEAM,
            principal=human.principal,
            certificate=member.certificate(),
        )


async def test_a_proof_that_expires_during_a_lock_wait_refuses_the_effect(
    console: Console,
    owners: dict[str, Owner],  # noqa: F811
    proof: HumanMemberProof,
    monkeypatch,
) -> None:
    async with await _client(console.sessions()) as client:
        cookie, _ = await _login(client, owners)
    session = replace(await _session(console, cookie), member=proof)

    async def effect() -> bool:
        async with console.db.transaction() as tx:
            return await session_is_current(tx, session, hold=True)

    assert await effect()
    async with console.db.transaction() as tx:
        await tx.execute(
            "SELECT 1 FROM {{tables.console_sessions}} WHERE token_sha256=$1 FOR UPDATE",
            session.token_sha256,
        )
        waiting = asyncio.create_task(effect())
        async with asyncio.timeout(10):
            while not await console.db.fetch_value(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity"
                " WHERE datname=current_database() AND wait_event_type='Lock')"
            ):
                assert not waiting.done()
                await asyncio.sleep(0.01)
        now = human_member.monotonic_ns
        monkeypatch.setattr(human_member, "monotonic_ns", lambda: now() + WINDOW_NS)
    with pytest.raises(HTTPException) as refused:
        await waiting
    assert (refused.value.status_code, refused.value.detail) == (
        503,
        "principal_status_unavailable",
    )
