"""Fenced decisions finish using their five retained connections, on real PG.

The scheduling checkpoint is after real F6 admission. Four other real effects
retain the remaining pool connections while waiting on that same fence. The
observer uses its own connection, so observing starvation never needs the pool.
"""

import asyncio
import json
from contextlib import asynccontextmanager

import asyncpg
import pytest
from aweb_naapp_testing.webauthn import SoftAuthenticator
from pgdbm import AsyncDatabaseManager

from aweb_naapp.runtime.approvals import (
    Approvals,
    ApprovalState,
    Assurance,
    Decision,
    DispatchOutcome,
    PgApprovalStore,
)
from aweb_naapp.runtime.installation import InstallationFence, apply_installation_migrations
from tests.runtime.approvals.support import policy
from tests.runtime.approvals.test_passkeys import (
    ORIGIN,
    ceremony,
    designate,
    passkey_world,
)
from tests.runtime.test_installation_fence import Source, grant


class DatabasePolicies:
    """A real SQL policy provider, with the same tx contract as app providers."""

    def __init__(self, db):
        self.db = db

    async def current(self, policy_ref, *, tx=None):
        scope = await (tx or self.db).fetch_value(
            "SELECT scope FROM {{tables.approval_test_policies}} WHERE policy_ref=$1",
            policy_ref,
        )
        return None if scope is None else policy(policy_ref=policy_ref, approver_scopes=(scope,))


class FencedEffects:
    """Actual admission/check; only the first admitted effect is paused."""

    def __init__(self, fence, current):
        self.fence, self.current = fence, current
        self.pids = set()
        self.admitted = {}
        self.first = asyncio.Event()
        self.release = asyncio.Event()
        self.holder = None
        self.holder_task = None
        self.lock_timeouts = {}

    async def prepare(self, tx):
        pid = await tx.fetch_value("SELECT pg_backend_pid()")
        self.pids.add(pid)
        self.lock_timeouts[pid] = await tx.fetch_value("SHOW lock_timeout")
        self.admitted[id(tx)] = await self.fence.admit(tx, self.current)
        if self.holder is None:
            self.holder = pid
            self.holder_task = asyncio.current_task()
            self.first.set()
            await self.release.wait()

    async def check(self, tx):
        await self.fence.check(tx, self.admitted[id(tx)])


async def snapshot(observer, effects):
    return [
        dict(row)
        for row in await observer.fetch(
            "SELECT pid,state,wait_event_type,wait_event,pg_blocking_pids(pid) AS blockers "
            "FROM pg_stat_activity WHERE datname=current_database() AND pid=ANY($1::int[]) "
            "ORDER BY pid",
            sorted(effects.pids),
        )
    ]


def waits_for(rows, pid, holder):
    """Follow real holders AND PostgreSQL's soft queue blockers."""
    graph = {row["pid"]: row["blockers"] for row in rows}
    pending, seen = list(graph.get(pid, ())), {pid}
    while pending:
        blocker = pending.pop()
        if blocker == holder:
            return True
        if blocker not in seen:
            seen.add(blocker)
            pending.extend(graph.get(blocker, ()))
    return False


class PoolAcquireExpired(Exception):
    """A real checkout expired; evidence was captured before its caller unwound."""


class ObservedDatabase(AsyncDatabaseManager):
    """Borrow the factory's real pool; bound only the F6 holder's next checkout.

    Pool.acquire(timeout=...) is the real asyncpg operation. No SQL, provider
    or verifier is substituted, and the original factory still owns cleanup.
    """

    def __init__(self, original):
        assert original._pool is not None
        super().__init__(pool=original._pool, schema=original.schema)
        self.config = original.config
        self.effects = self.observer = self.starvation = None
        self.borrowers = {}

    @asynccontextmanager
    async def acquire(self):
        task = asyncio.current_task()
        holder = self.effects is not None and self.effects.holder_task is task
        try:
            connection = await self._pool.acquire(timeout=0.5 if holder else None)
        except TimeoutError:
            if not holder:
                raise
            # The original effect transaction STILL holds F6 here. Capture
            # before raising, releasing its connection or cancelling any task.
            self.starvation = {
                "holder_pid": self.effects.holder,
                "holder_task": self.effects.holder_task is task,
                "holder_connections": self.borrowers.get(task, 0),
                "pool_max": self._pool.get_max_size(),
                "pool_size": self._pool.get_size(),
                "pool_idle": self._pool.get_idle_size(),
                "acquire_timeout_s": 0.5,
                "lock_timeouts": self.effects.lock_timeouts.copy(),
                "rows": await snapshot(self.observer, self.effects),
                "locks": [
                    dict(row)
                    for row in await self.observer.fetch(
                        "SELECT pid,locktype,mode,granted,relation::regclass::text AS relation,"
                        "transactionid::text AS xid FROM pg_locks WHERE pid=ANY($1::int[]) "
                        "ORDER BY pid,locktype,mode",
                        sorted(self.effects.pids),
                    )
                ],
            }
            raise PoolAcquireExpired() from None
        self.borrowers[task] = self.borrowers.get(task, 0) + 1
        try:
            yield connection
        finally:
            self.borrowers[task] -= 1
            await self._pool.release(connection)


@pytest.mark.parametrize("database_policy", [False, True], ids=["directory", "policy"])
@pytest.mark.parametrize("phase", ["mint", "decide", "admit", "retry"])
async def test_five_fenced_operations_do_not_checkout_a_sixth_connection(
    test_db_factory, registry, database_policy, phase
):
    # pgdbm's fixture already caps the pool at five. Its factory supplies the
    # pool keywords explicitly, so passing them again is not an override.
    world = await passkey_world(test_db_factory, registry)
    db = ObservedDatabase(world.passkeys.db)
    world.passkeys.db = db
    await apply_installation_migrations(db)
    await db.execute(
        "CREATE TABLE {{tables.approval_test_policies}} (policy_ref text PRIMARY KEY, scope text)"
    )
    world.approvals = Approvals(
        store=PgApprovalStore(db),
        policies=DatabasePolicies(db) if database_policy else world.policies,
        approvers=world.approvers,
        delivery=world.contacts,
        authenticators=[world.passkeys.authenticator()],
        audit=world.audit,
        clock=world.clock,
    )
    pending = []
    for index in range(5):
        # Independent real credentials avoid counter races masking pool starvation.
        scope, contact, ref = f"installation-{index}", f"owner{index}@example.com", f"p{index}"
        await designate(world, contact, scope)
        token = world.contacts.last(contact)
        device = SoftAuthenticator(ORIGIN)
        registration = device.create(await world.passkeys.enrolment_options(token))
        await world.passkeys.complete_enrolment(token, registration)
        world.policies.set(policy(policy_ref=ref, approver_scopes=(scope,)))
        await db.execute("INSERT INTO {{tables.approval_test_policies}} VALUES($1,$2)", ref, scope)
        view = await world.approvals.mint(
            request={"operation": "charge", "item": index},
            policy_ref=ref,
            requested_by="agent-1",
        )
        approval = await world.approvals.for_request(view.request_id)
        proof = await ceremony(world, approval, device)
        if phase in ("admit", "retry"):
            await world.approvals.decide(
                approval.approval_id,
                Decision.APPROVE,
                Assurance.PASSKEY,
                proof,
                link_token=world.contacts.by_approval[approval.approval_id],
            )
        if phase == "retry":
            await world.approvals.admit(
                approval.approval_id, {"operation": "charge", "item": index}, str(index)
            )
            await world.approvals.record_outcome(
                approval.approval_id, str(index), DispatchOutcome.NOT_SENT
            )
        pending.append((approval, proof, ref, index))

    current = grant(ttl=60)
    effects = FencedEffects(
        InstallationFence(db, app_id="fixture", grants=Source(current)), current
    )
    # Use an existing fence row, as concurrent requests of an installed team do.
    await effects.fence.refresh(current.team_id)
    observer = await asyncpg.connect(db.config.get_dsn())
    db.effects, db.observer = effects, observer
    pool = db._pool
    assert pool is not None and pool.get_max_size() == 5
    tasks = []

    async def run(approval, proof, ref, index):
        if phase == "decide":
            return await world.approvals.decide(
                approval.approval_id,
                Decision.APPROVE,
                Assurance.PASSKEY,
                proof,
                link_token=world.contacts.by_approval[approval.approval_id],
                fence=effects,
            )
        async with db.transaction() as tx:
            await effects.prepare(tx)
            request = {"operation": "charge", "item": index}
            if phase == "mint":
                result = await world.approvals.mint(
                    request={**request, "round": "fenced"},
                    policy_ref=ref,
                    requested_by="agent-1",
                    tx=tx,
                )
            else:
                result = await world.approvals.admit(
                    approval.approval_id, request, str(index), tx=tx
                )
            await effects.check(tx)
            return result

    try:
        for arguments in pending:
            tasks.append(asyncio.create_task(run(*arguments)))
        await asyncio.wait_for(effects.first.wait(), 5)
        async with asyncio.timeout(5):
            while True:
                rows = await snapshot(observer, effects)
                blocked = [r for r in rows if waits_for(rows, r["pid"], effects.holder)]
                if len(blocked) == 4:
                    break
                if any(task.done() for task in tasks):
                    await asyncio.gather(*[task for task in tasks if task.done()])
                    pytest.fail("a decider finished before the five-connection checkpoint")
                await asyncio.sleep(0.01)
        assert pool.get_size() == 5 and pool.get_idle_size() == 0
        effects.release.set()
        _, unfinished = await asyncio.wait(tasks, timeout=5)
        if (evidence := db.starvation) is not None:
            assert evidence["holder_task"] and evidence["holder_connections"] == 1, evidence
            assert evidence["pool_max"] == evidence["pool_size"] == 5, evidence
            assert evidence["pool_idle"] == 0, evidence
            rows = evidence["rows"]
            waiters = {r["pid"] for r in rows if waits_for(rows, r["pid"], effects.holder)}
            assert len(waiters) == 4, rows
            assert {r["pid"] for r in evidence["locks"] if not r["granted"]} == waiters, evidence
            holder = next(r for r in rows if r["pid"] == effects.holder)
            assert holder["state"] == "idle in transaction" and not holder["blockers"], rows
            pytest.fail(
                "pool starvation: F6 holder's sixth checkout expired with all five occupied; "
                + json.dumps(evidence)
            )
        assert not unfinished, "effects did not finish; no holder checkout expiry was captured"
        results = [task.result() for task in tasks]
        if phase == "decide":
            assert all(result.state is ApprovalState.APPROVED for result in results)
            kind, count = "approval_decided", 5
        elif phase == "mint":
            assert all(result.approval.state is ApprovalState.PENDING for result in results)
            kind, count = "approval_requested", 10
        else:
            assert all(result.may_send and result.first == (phase == "admit") for result in results)
            kind, count = "dispatch_admitted", 10 if phase == "retry" else 5
        assert (
            await db.fetch_value("SELECT count(*) FROM {{tables.audit_outbox}} WHERE kind=$1", kind)
            == count
        )
    finally:
        effects.release.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await observer.close()
