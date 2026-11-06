"""Member requests grant nothing; admin approval and retries are transactional."""

from uuid import uuid4

import pytest
import test_verified_installations as store_fixture

from aweb.audit import AuditActor
from aweb.installation_requests import (
    approve_installation_request_on,
    get_installation_request_on,
    queue_installation_verification_on,
    request_installation_on,
    run_installation_verifications,
)
from aweb.installations import InstallationError

origin = store_fixture.origin
db = store_fixture.db
pytestmark = pytest.mark.asyncio
TEAM = store_fixture.TEAM


async def request(db, evidence):
    async with db.transaction() as tx:
        return await request_installation_on(
            tx, team_id=TEAM, fetched=evidence, requested_scopes=["fixture:read"],
            actor=AuditActor(team_id=TEAM, principal_type="u", auth_mode="internal", user_id=str(uuid4())),
        )


async def test_member_request_grants_nothing_then_approval_writes_the_same_verified_pin(db, origin):
    evidence = await store_fixture.fetched(origin)
    pending = await request(db, evidence)
    assert pending["state"] == "pending"
    assert await store_fixture.current(db) is None
    async with db.transaction() as tx:
        installed = await approve_installation_request_on(
            tx, team_id=TEAM, request_id=pending["request_id"], fetched=evidence,
            granted_scopes=["fixture:read"], expected_generation=None,
        )
    assert installed["digest"] == pending["digest"]
    async with db.transaction() as tx:
        resolved = await get_installation_request_on(tx, team_id=TEAM, request_id=pending["request_id"])
    assert resolved["state"] == "approved"
    assert resolved["installation_id"] == installed["installation_id"]


async def test_approval_failure_rolls_back_request_and_installation_together(db, origin):
    evidence = await store_fixture.fetched(origin)
    pending = await request(db, evidence)
    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            await approve_installation_request_on(
                tx, team_id=TEAM, request_id=pending["request_id"], fetched=evidence,
                granted_scopes=[], expected_generation=None,
            )
            raise RuntimeError("commit failed")
    assert await store_fixture.current(db) is None
    async with db.transaction() as tx:
        assert (await get_installation_request_on(tx, team_id=TEAM, request_id=pending["request_id"]))["state"] == "pending"


async def test_approval_cannot_substitute_a_new_manifest_for_the_member_pin(db, origin):
    pending = await request(db, await store_fixture.fetched(origin))
    changed = await store_fixture.fetched(origin, "2.0.0")
    with pytest.raises(InstallationError, match="changed manifest"):
        async with db.transaction() as tx:
            await approve_installation_request_on(
                tx, team_id=TEAM, request_id=pending["request_id"], fetched=changed,
                granted_scopes=[], expected_generation=None,
            )
    assert await store_fixture.current(db) is None


async def test_reverification_queues_without_network_and_worker_activates_the_pending_pin(db, origin):
    before = await store_fixture.install(db, await store_fixture.fetched(origin))
    await store_fixture.make_pending(db)
    origin.tls.seen.clear()
    async with db.transaction() as tx:
        first = await queue_installation_verification_on(tx, team_id=TEAM, app_id="fixture", expected_generation=1)
        same = await queue_installation_verification_on(tx, team_id=TEAM, app_id="fixture", expected_generation=1)
    assert first["job_id"] == same["job_id"]
    assert not origin.tls.seen
    assert (await store_fixture.current(db))["state"] == "pending_origin_verification"
    reports = await run_installation_verifications(db, fetcher=origin.fetcher)
    assert reports[0]["outcome"] == "verified"
    assert (await store_fixture.current(db))["installation_id"] == before["installation_id"]
    assert (await store_fixture.current(db))["state"] == "active"


async def test_old_queued_verification_cannot_activate_a_replaced_installation(db, origin):
    await store_fixture.install(db, await store_fixture.fetched(origin))
    await store_fixture.make_pending(db)
    async with db.transaction() as tx:
        await queue_installation_verification_on(tx, team_id=TEAM, app_id="fixture", expected_generation=1)
    await db.execute("UPDATE {{tables.team_app_installs}} SET state='uninstalled'")
    replacement = await store_fixture.install(db, await store_fixture.fetched(origin), 1)
    origin.tls.seen.clear()
    assert (await run_installation_verifications(db, fetcher=origin.fetcher))[0]["outcome"] == "superseded"
    assert not origin.tls.seen
    assert await store_fixture.current(db) == replacement
