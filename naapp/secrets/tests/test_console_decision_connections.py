"""Real console requests cannot retain F6 while requesting a verifier connection.

One connection is sufficient once verification precedes the effect checkout.
Five duplicate HTTP decisions also require exactly one committed decision;
the other ceremonies remain refused, rather than rearming the assertion.
"""

import asyncio
import json

import asyncpg
import pytest
from aweb_naapp.runtime.approvals import ApprovalState
from pgdbm.core import TransactionManager

from tests.test_console_changes import sign_in
from tests.test_console_reconciliation import clients as reconciliation_clients
from tests.test_console_use_approvals import clients as use_clients
from tests.test_console_use_approvals import pending_use
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world


@pytest.mark.parametrize("world", [{"min_connections": 1, "max_connections": 1}], indirect=True)
@pytest.mark.parametrize("kind", ["use", "reconciliation"])
async def test_console_decisions_verify_before_retaining_the_only_pool_connection(uses, kind):
    w = uses.world
    if kind == "use":
        approval_id, token, scope = await pending_use(uses)
        contact, root = "finance@acme.com", "/use-approvals"
        clients = use_clients(uses)
    else:
        root, contact = "/reconciliation-approvals", "alice@acme.com"
        clients = reconciliation_clients(uses)

    async with clients as connected:
        human = connected[0]
        if kind == "reconciliation":
            original, current = connected[3:]
            scope = current.scope
        headers = await sign_in(w, human, scope, contact)
        if kind == "reconciliation":
            minted = await human.post(
                "/reconciliations/" + original.original.reconcile_ref + "/controls",
                json={"outcome": "unknown-closed"},
                headers=headers,
            )
            assert minted.status_code == 201
            token = minted.json()["personal_token"]
            approval_id = minted.json()["status"]["control"]["approval_id"]
        options = await human.post(
            root + "/decision-options",
            json={"token": token, "decision": "approve"},
            headers=headers,
        )
        assert options.status_code == 200
        proof = w.devices[contact].get(options.json())
        db = w.db
        pool = db._pool
        assert pool is not None and pool.get_max_size() == 1
        pid = await db.fetch_value("SELECT pg_backend_pid()")
        observer = await asyncpg.connect(db.config.get_dsn())
        tasks = []
        try:
            for _ in range(5):
                tasks.append(
                    asyncio.create_task(
                        human.post(
                            root + "/decide",
                            json={"token": token, "decision": "approve", "assertion": proof},
                            headers=headers,
                        )
                    )
                )
            _, unfinished = await asyncio.wait(tasks, timeout=5)
            if unfinished:
                # Measure the actual retained F6 and sole occupied connection
                # before cancellation; an observation timeout alone is not RED.
                assert pool.get_size() == 1 and pool.get_idle_size() == 0
                row = await observer.fetchrow(
                    "SELECT pid,state,wait_event_type,wait_event,pg_blocking_pids(pid) AS blockers "
                    "FROM pg_stat_activity WHERE pid=$1",
                    pid,
                )
                assert (
                    row is not None
                    and row["state"] == "idle in transaction"
                    and not row["blockers"]
                )
                async with observer.transaction():
                    probe = TransactionManager(observer, db)
                    with pytest.raises(asyncpg.LockNotAvailableError):
                        await probe.fetch_value(
                            "SELECT installation_id FROM {{tables.installation_fences}} "
                            "WHERE app_id=$1 AND team_id=$2 FOR UPDATE NOWAIT",
                            w.admitted.app_id,
                            w.admitted.team_id,
                        )
                pytest.fail(
                    "pool starvation with the console's F6 still held: " + json.dumps(dict(row))
                )
            responses = [task.result() for task in tasks]
            assert sorted(response.status_code for response in responses) == [
                200,
                409,
                409,
                409,
                409,
            ]
            assert (await uses.approvals.get(approval_id)).state is ApprovalState.APPROVED
            table = (
                "use_approval_audit_proofs" if kind == "use" else "reconciliation_control_proofs"
            )
            assert (
                await db.fetch_value(
                    "SELECT count(*) FROM {{tables." + table + "}} WHERE approval_id=$1",
                    approval_id,
                )
                == 1
            )
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await observer.close()
