"""A reader's passkey login and cookie session, on real PostgreSQL with a real
AWID registry: both admit only a holder who is a current human team member."""

from __future__ import annotations

import asyncio
import time
from dataclasses import replace

import httpx
import pytest
from aweb_naapp.runtime import human_member
from aweb_naapp_testing.owner_acts import TEAM_ID

from .reader_world import CONSOLE, reader_scope, world_fixture  # noqa: F401
from .test_reader_handoffs import Aw, aw  # noqa: F401

# Longer than any membership evidence stays fresh.
EVIDENCE_WINDOW_NS = 61 * 1_000_000_000

NOT_A_MEMBER = (403, {"detail": "principal_not_member"})
UNAVAILABLE = (503, {"detail": "principal_status_unavailable"})


class Clock:
    """The monotonic clock the membership evidence's freshness is read from."""

    def __init__(self) -> None:
        self.offset = 0
        self._now = time.monotonic_ns

    def __call__(self) -> int:
        return self._now() + self.offset

    def expire_evidence(self) -> None:
        self.offset += EVIDENCE_WINDOW_NS


@pytest.fixture
def clock(monkeypatch) -> Clock:
    clock = Clock()
    monkeypatch.setattr(time, "monotonic_ns", clock)
    monkeypatch.setattr(human_member, "monotonic_ns", clock)
    return clock


async def login(aw: Aw) -> httpx.Response:  # noqa: F811
    scope = reader_scope(aw.principal)
    options = await aw.client.post("/login/options", json={"scope": scope})
    assert options.status_code == 200, options.text
    return await aw.client.post(
        "/login", json={"scope": scope, "assertion": aw.device.get(options.json())}
    )


async def signed_in(aw: Aw) -> str:  # noqa: F811
    """A cookie session of the reader: its CSRF token."""
    response = await login(aw)
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


async def removed_from_team(aw: Aw) -> None:  # noqa: F811
    await aw.world.registry.revoke(aw.member.certificate_id, team_id=TEAM_ID)


def outcome(response: httpx.Response) -> tuple[int, dict]:
    return response.status_code, response.json()


async def open_sessions(aw: Aw) -> int:  # noqa: F811
    return await aw.world.db.fetch_value(
        "SELECT count(*) FROM {{tables.console_sessions}} WHERE closed_at IS NULL"
    )


async def test_a_current_member_signs_in_and_reads(aw: Aw, clock: Clock):  # noqa: F811
    await signed_in(aw)
    for path in ("/v1/events", "/v1/tail", "/v1/verify", "/v1/export"):
        assert (await aw.client.get(path)).status_code == 200, path


async def test_a_reader_removed_from_the_team_cannot_sign_in(aw: Aw, clock: Clock):  # noqa: F811
    await removed_from_team(aw)
    assert outcome(await login(aw)) == NOT_A_MEMBER
    assert await open_sessions(aw) == 0
    assert (await aw.client.get("/v1/events")).status_code == 401


@pytest.mark.parametrize("path", ["/v1/events", "/v1/tail", "/v1/verify", "/v1/export"])
async def test_removal_from_the_team_ends_an_open_session(aw: Aw, clock: Clock, path: str):  # noqa: F811
    await signed_in(aw)
    await removed_from_team(aw)
    clock.expire_evidence()
    assert outcome(await aw.client.get(path)) == NOT_A_MEMBER
    assert await open_sessions(aw) == 0


async def test_an_unreadable_registry_refuses_and_the_session_recovers(aw: Aw, clock: Clock):  # noqa: F811
    await signed_in(aw)
    clock.expire_evidence()
    aw.world.registry.transport.down = True
    assert outcome(await aw.client.get("/v1/events")) == UNAVAILABLE
    assert await open_sessions(aw) == 1
    aw.world.registry.transport.down = False
    assert (await aw.client.get("/v1/events")).status_code == 200


async def test_an_unreadable_registry_opens_no_session(aw: Aw, clock: Clock):  # noqa: F811
    aw.world.registry.transport.down = True
    assert outcome(await login(aw)) == UNAVAILABLE
    assert await open_sessions(aw) == 0


async def test_requests_in_one_evidence_window_share_one_observation(aw: Aw, clock: Clock):  # noqa: F811
    await signed_in(aw)
    calls = aw.world.registry.transport.calls
    observed = len(calls)
    for _ in range(5):
        assert (await aw.client.get("/v1/events")).status_code == 200
    assert len(calls) == observed
    clock.expire_evidence()
    assert (await aw.client.get("/v1/events")).status_code == 200
    assert len(calls) > observed


@pytest.mark.parametrize("ended", ["removed", "outage"])
async def test_logout_needs_no_membership(aw: Aw, clock: Clock, ended: str):  # noqa: F811
    csrf = await signed_in(aw)
    if ended == "removed":
        await removed_from_team(aw)
    else:
        aw.world.registry.transport.down = True
    clock.expire_evidence()
    headers = {"Origin": CONSOLE, "X-CSRF-Token": csrf}
    refused = await aw.client.post("/logout", headers={**headers, "X-CSRF-Token": "wrong"})
    assert outcome(refused) == (403, {"detail": "csrf_token_required"})
    assert await open_sessions(aw) == 1
    assert (await aw.client.post("/logout", headers=headers)).status_code == 200
    assert await open_sessions(aw) == 0


async def test_a_session_handoff_refreshes_the_certificate_sign_in_checks(aw: Aw):  # noqa: F811
    reissued = replace(aw.member, certificate_id="cert-reissued")
    registry = aw.world.registry
    await registry.add_certificate(reissued.certificate(), team_key=reissued.team_key)
    await registry.revoke(aw.member.certificate_id, team_id=TEAM_ID)
    assert outcome(await login(aw)) == NOT_A_MEMBER
    aw.member = reissued
    await aw.open()
    assert (await login(aw)).status_code == 200


async def test_two_sessions_of_one_holding_open_at_once(aw: Aw):  # noqa: F811
    async with httpx.AsyncClient(transport=aw.transport, base_url=CONSOLE) as other:
        async with asyncio.timeout(30):
            opened = await asyncio.gather(aw.open(), replace(aw, client=other).open())
    for key, issued in opened:
        assert (await aw.get(key, issued, "/v1/events")).status_code == 200
    assert (await login(aw)).status_code == 200
