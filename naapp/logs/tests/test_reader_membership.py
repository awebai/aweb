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
from nacl.signing import SigningKey

from aweb_logs.reader_acts import OWNER_ACTS
from aweb_logs.readers import READER_ROLE

from .reader_world import CONSOLE, reader_scope, world_fixture  # noqa: F401
from .test_reader_handoffs import Aw, aw  # noqa: F401
from .test_reader_viewer import Html

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


async def test_two_sessions_of_one_holding_open_at_once(aw: Aw):  # noqa: F811
    async with httpx.AsyncClient(transport=aw.transport, base_url=CONSOLE) as other:
        async with asyncio.timeout(30):
            opened = await asyncio.gather(aw.open(), replace(aw, client=other).open())
    for key, issued in opened:
        assert (await aw.get(key, issued, "/v1/events")).status_code == 200
    assert (await login(aw)).status_code == 200


PAGES = ("/", "/login", "/events", "/follow", "/integrity")


@pytest.mark.parametrize("path", PAGES)
async def test_a_page_refused_to_a_non_member_leads_on_to_sign_in(
    aw: Aw,  # noqa: F811
    clock: Clock,
    path: str,
):
    await signed_in(aw)
    await removed_from_team(aw)
    clock.expire_evidence()
    refused = await aw.client.get(path)
    assert refused.status_code == 403
    action = Html(refused.text).all("a", id="console-recovery-action")[0]
    # The way on ends at a page: the refused session is closed, so nothing loops.
    after = await aw.client.get(action["href"])
    assert after.status_code == 200
    assert not Html(after.text).all("a", id="console-recovery-action")


@pytest.mark.parametrize("path", PAGES)
async def test_a_page_that_cannot_check_membership_retries_itself(
    aw: Aw,  # noqa: F811
    clock: Clock,
    path: str,
):
    await signed_in(aw)
    clock.expire_evidence()
    aw.world.registry.transport.down = True
    refused = await aw.client.get(path)
    assert refused.status_code == 503
    action = Html(refused.text).all("a", id="console-recovery-action")[0]
    assert action["href"] == ""
    aw.world.registry.transport.down = False
    retried = await aw.client.get(path, follow_redirects=True)
    assert retried.status_code == 200
    assert not Html(retried.text).all("a", id="console-recovery-action")


async def held_state(aw: Aw) -> list[list[dict]]:  # noqa: F811
    """Every holder's credentials, holdings and governance events, but not the
    certificates the holdings retain."""
    db = aw.world.db
    state = [
        await db.fetch_all("SELECT * FROM {{tables.passkey_approvers}} ORDER BY scope, subject"),
        await db.fetch_all("SELECT * FROM {{tables.passkey_credentials}} ORDER BY credential_id"),
        await db.fetch_all(
            "SELECT * FROM {{tables.role_assignments}} ORDER BY team_id, principal_did, role"
        ),
        await db.fetch_all(
            "SELECT b3_scope, installation_id, team_id, role, principal_did, ended_in"
            " FROM {{tables.role_holdings}} ORDER BY b3_scope"
        ),
        await db.fetch_all("SELECT * FROM {{tables.outbox_events}} ORDER BY position"),
    ]
    return [[dict(row) for row in rows] for rows in state]


async def retained(aw: Aw) -> bytes:  # noqa: F811
    return await aw.world.db.fetch_value(
        "SELECT certificate FROM {{tables.role_holdings}} WHERE b3_scope = $1",
        reader_scope(aw.principal),
    )


async def reissued(aw: Aw) -> None:  # noqa: F811
    """The member's certificate is replaced, under the same team key."""
    renewed = replace(aw.member, certificate_id="cert-reissued")
    registry = aw.world.registry
    await registry.add_certificate(renewed.certificate(), team_key=renewed.team_key)
    await registry.revoke(aw.member.certificate_id, team_id=TEAM_ID)
    aw.member = renewed


async def rotated(aw: Aw) -> None:  # noqa: F811
    """The team's key is rotated, and the member certified under the new one."""
    renewed = replace(
        aw.member, team_key=SigningKey.generate(), certificate_id="cert-after-rotation"
    )
    registry = aw.world.registry
    await registry.rotate_team_key_by_controller(
        TEAM_ID, renewed.team_did_key, SigningKey(aw.world.namespace.controller_seed)
    )
    await registry.add_certificate(renewed.certificate(), team_key=renewed.team_key)
    aw.member = renewed


@pytest.mark.parametrize("change", [reissued, rotated])
async def test_the_declared_action_lets_a_current_member_sign_in_again(aw: Aw, change):  # noqa: F811
    await change(aw)
    assert outcome(await login(aw)) == NOT_A_MEMBER
    (action,) = OWNER_ACTS["session_actions"]
    assert (action["method"], action["role"]) == ("GET", READER_ROLE)
    key, issued = await aw.open()
    answer = await aw.get(key, issued, action["path"])
    assert answer.status_code == 200, answer.text
    assert set(answer.json()) == {"scope", "expires_at"}
    assert answer.json()["scope"] == reader_scope(aw.principal)
    assert (await login(aw)).status_code == 200


async def test_a_session_handoff_gives_a_removed_member_nothing(aw: Aw):  # noqa: F811
    await removed_from_team(aw)
    before, certificate = await held_state(aw), await retained(aw)
    started, _, _ = await aw.start()
    assert started.status_code in (401, 403), started.text
    assert (await held_state(aw), await retained(aw)) == (before, certificate)
    assert outcome(await login(aw)) == NOT_A_MEMBER


async def test_an_abandoned_session_handoff_changes_nothing_held(aw: Aw):  # noqa: F811
    await reissued(aw)
    before, certificate = await held_state(aw), await retained(aw)
    started, _, _ = await aw.start()
    assert started.status_code == 201, started.text
    assert (await held_state(aw), await retained(aw)) == (before, certificate)
