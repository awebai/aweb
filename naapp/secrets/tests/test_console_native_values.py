"""Native owner ingress and change/1 activation, without seeded value rows."""

import asyncio
import json
import os

import pytest
from aweb_naapp.roles import unassign
from aweb_naapp.runtime.approvals import ApprovalState
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets.broker import broker
from aweb_secrets.custody import CustodyUnavailable, SealContext, decode_value
from aweb_secrets.custody.opening import UseSecretOpener
from aweb_secrets.owners import OWNER_ROLE
from aweb_secrets.response_audit import ResponseKey
from tests.harness import running_upstream
from tests.test_change_sets import ALICE, SECRET, TEAM, enrol_owner
from tests.test_change_sets import world as world
from tests.test_console_changes import ROOT, approve, sign_in
from tests.test_console_changes import clients as change_clients
from tests.test_console_values import clients, no_value

PATH = f"/installations/{INSTALLATION_ID}/native/versions"


def opener(w):
    return UseSecretOpener(
        w.db, native=w.custody.opener, credential_opener=w.custody.backend_credential_opener
    )


def context(version):
    return SealContext(INSTALLATION_ID, TEAM, SECRET["secret_id"], version)


async def stage(human, headers, value):
    response = await human.post(PATH, json={"secret": SECRET, "value": value}, headers=headers)
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    assert set(response.json()) == {"secret_id", "version"}
    for entered in value.values():
        no_value(response, entered)
    return response.json()


async def draft(human, headers, staged, *, create=False):
    changes = (
        [{"kind": "secret", "op": "create", "ref": SECRET["ref"], "after": SECRET}]
        if create
        else []
    )
    changes.append(
        {
            "kind": "secret_value",
            "op": "create",
            "ref": SECRET["ref"],
            "after": {"v": 1, "secret_ref": SECRET["ref"], "version": staged["version"]},
        }
    )
    response = await human.post(
        ROOT,
        json={"changes": changes, "sealed": [staged], "reason": "Set the native credential"},
        headers=headers,
    )
    assert response.status_code == 201
    return response.json()


async def assert_unallocated(w):
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.custody_secrets}}") == 0
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.sealed_versions}}") == 0


async def test_native_owner_stages_confirms_and_broker_uses_without_seeded_values(world, tmp_path):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    async with running_upstream(tmp_path) as upstream, change_clients(w) as (human, agent):
        headers = await sign_in(w, human, scope)
        value = {"value": upstream.creds.bearer}
        staged = await stage(human, headers, value)
        assert staged == {"secret_id": SECRET["secret_id"], "version": 1}
        assert await w.db.fetch_value("SELECT count(*) FROM {{tables.secrets}}") == 0
        assert await w.db.fetch_value("SELECT count(*) FROM {{tables.grants}}") == 0
        for row in await w.db.fetch_all("SELECT * FROM {{tables.sealed_versions}}"):
            if value["value"] in str(dict(row)):
                raise AssertionError("entered native value stored as plaintext")
        with pytest.raises(CustodyUnavailable):
            await opener(w).open(context(1))
        assert (await agent.post(PATH, json={"secret": SECRET, "value": value})).status_code == 404
        assert (await human.get(PATH)).status_code == 405
        drafted = await draft(human, headers, staged, create=True)
        path = ROOT + "/" + drafted["change_id"]
        no_value(await human.get(path), value["value"])
        assert (await human.post(path + "/confirm", json={}, headers=headers)).status_code == 409
        await approve(w, human, headers, drafted)
        assert (await w.approvals.get(drafted["approval_id"])).state is ApprovalState.APPROVED
        with pytest.raises(CustodyUnavailable):
            await opener(w).open(context(1))
        result = await human.post(path + "/confirm", json={}, headers=headers)
        assert result.status_code == 200
        no_value(result, value["value"])
        assert (await w.approvals.get(drafted["approval_id"])).state is ApprovalState.CONSUMED
        plaintext = await opener(w).open(context(1))
        call = await broker(
            upstream.egress,
            method="GET",
            url=upstream.url("/bearer/echo"),
            destination=upstream.destination(),
            headers=[],
            body=b"",
            kind="bearer",
            value=decode_value("bearer", plaintext.reveal()),
            kind_params={},
            secret_ref=SECRET["ref"],
            max_bytes=4096,
            projection=None,
            token_issuing=False,
            response_key=ResponseKey(os.urandom(32)),
        )
        assert call.result.status == 200 and call.result.disposition == "returned"
        assert json.loads(call.result.body)["scheme"] == "bearer"
        if value["value"].encode() in call.result.body:
            raise AssertionError("broker exposed the stored native value")
        assert upstream.paths == ["/bearer/echo"]


async def test_native_replacement_confirms_before_destroying_the_previous_version(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    async with change_clients(w) as (human, _):
        headers = await sign_in(w, human, scope)
        for version in (1, 2):
            value = {"value": os.urandom(24).hex()}
            staged = await stage(human, headers, value)
            assert staged == {"secret_id": SECRET["secret_id"], "version": version}
            drafted = await draft(human, headers, staged, create=version == 1)
            if version == 2:
                assert await w.db.fetch_value("SELECT active_version FROM {{tables.secrets}}") == 1
                assert (
                    await w.db.fetch_value("SELECT count(*) FROM {{tables.sealed_versions}}") == 2
                )
            await approve(w, human, headers, drafted)
            assert (
                await human.post(
                    ROOT + "/" + drafted["change_id"] + "/confirm", json={}, headers=headers
                )
            ).status_code == 200
            assert (
                await w.db.fetch_value("SELECT active_version FROM {{tables.secrets}}") == version
            )
            assert await w.db.fetch_value("SELECT count(*) FROM {{tables.sealed_versions}}") == 1
            opened = await opener(w).open(context(version))
            if decode_value("bearer", opened.reveal()) != value:
                raise AssertionError("confirmed native value differs from owner input")
        with pytest.raises(CustodyUnavailable):
            await opener(w).open(context(1))


async def test_native_ingress_requires_owner_login_csrf_and_the_human_origin(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    value = {"value": os.urandom(24).hex()}
    async with clients(w) as (human, agent):
        assert (await human.post(PATH, json={"secret": SECRET, "value": value})).status_code == 401
        headers = await sign_in(w, human, scope)
        response = await human.post(PATH, json={"secret": SECRET, "value": value})
        assert response.status_code == 403
        no_value(response, value["value"])
        assert (
            await agent.post(PATH, json={"secret": SECRET, "value": value}, headers=headers)
        ).status_code == 404
        response = await human.post(
            PATH.replace(INSTALLATION_ID, "another-installation"),
            json={"secret": SECRET, "value": value},
            headers=headers,
        )
        assert response.status_code == 403
        no_value(response, value["value"])
    await assert_unallocated(w)


@pytest.mark.parametrize(
    "invalid", ["missing", "extra", "backend", "value", "secret", "content_type"]
)
async def test_native_invalid_inputs_are_constant_and_allocate_nothing(world, invalid):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    value = os.urandom(24).hex()
    body = {"secret": dict(SECRET), "value": {"value": value}}
    if invalid == "missing":
        body.pop("secret")
    elif invalid == "extra":
        body["team_id"] = "another-team"
    elif invalid == "backend":
        body["secret"]["backend"] = "onepassword"
    elif invalid == "value":
        body["value"] = {"value": ""}
    elif invalid == "secret":
        body["secret"]["kind"] = value
    async with clients(w) as (human, _):
        headers = await sign_in(w, human, scope)
        response = (
            await human.post(PATH, content=value, headers={**headers, "Content-Type": "text/plain"})
            if invalid == "content_type"
            else await human.post(PATH, json=body, headers=headers)
        )
        assert response.status_code == (415 if invalid == "content_type" else 400)
        no_value(response, value)
    await assert_unallocated(w)


@pytest.mark.parametrize("withdrawal", ["role", "login", "logout"])
async def test_native_authority_is_rechecked_after_installation_lookup(world, withdrawal):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    ready, resume = asyncio.Event(), asyncio.Event()
    async with clients(w, lookup_ready=ready, resume=resume) as (human, _):
        headers = await sign_in(w, human, scope)
        holder = await w.passkeys.designated_approver(scope)
        posting = asyncio.create_task(
            human.post(
                PATH,
                json={"secret": SECRET, "value": {"value": os.urandom(24).hex()}},
                headers=headers,
            )
        )
        try:
            await asyncio.wait_for(ready.wait(), 5)
            if withdrawal == "role":
                async with w.db.transaction() as tx:
                    await unassign(tx, ALICE, OWNER_ROLE)
            elif withdrawal == "login":
                from tests.test_console_changes import retire_owner

                await retire_owner(w, scope, holder.subject)
            else:
                assert (await human.post("/logout", headers=headers)).status_code == 200
            resume.set()
            response = await asyncio.wait_for(posting, 5)
            assert response.status_code == (403 if withdrawal == "role" else 401)
        finally:
            resume.set()
            if not posting.done():
                posting.cancel()
            await asyncio.gather(posting, return_exceptions=True)
    await assert_unallocated(w)


async def test_native_ingress_rechecks_fence_after_waiting_for_the_allocator(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    async with clients(w) as (human, _):
        headers = await sign_in(w, human, scope)
        await stage(human, headers, {"value": os.urandom(24).hex()})
        await w.db.execute(
            "UPDATE {{tables.installation_fences}} SET fresh_until=clock_timestamp()+interval '2 seconds' WHERE installation_id=$1",
            INSTALLATION_ID,
        )
        posting = None
        try:
            async with w.db.transaction() as gate:
                gate_pid = await gate.fetch_value("SELECT pg_backend_pid()")
                await gate.fetch_value(
                    "SELECT secret_id FROM {{tables.custody_secrets}} WHERE secret_id=$1 FOR UPDATE",
                    SECRET["secret_id"],
                )
                posting = asyncio.create_task(
                    human.post(
                        PATH,
                        json={"secret": SECRET, "value": {"value": os.urandom(24).hex()}},
                        headers=headers,
                    )
                )
                async with asyncio.timeout(5):
                    while not await w.db.fetch_value(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
                        gate_pid,
                    ):
                        if posting.done():
                            await posting
                            pytest.fail("native ingress did not reach its allocator wait")
                        await asyncio.sleep(0.01)
                    while await w.db.fetch_value(
                        "SELECT fresh_until>clock_timestamp() FROM {{tables.installation_fences}} WHERE installation_id=$1",
                        INSTALLATION_ID,
                    ):
                        await asyncio.sleep(0.02)
            response = await asyncio.wait_for(posting, 5)
            assert response.status_code == 503
            assert response.json() == {"detail": "authority_unavailable"}
        finally:
            if posting is not None and not posting.done():
                posting.cancel()
            if posting is not None:
                await asyncio.gather(posting, return_exceptions=True)
    assert await w.db.fetch_value("SELECT last_version FROM {{tables.custody_secrets}}") == 1
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.sealed_versions}}") == 1
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.secrets}}") == 0
