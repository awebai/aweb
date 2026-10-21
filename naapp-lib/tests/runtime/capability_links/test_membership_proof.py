"""Two-phase N5 checks consume runtime's proof locally after locking."""

import pytest

from aweb_naapp.runtime.capability_links import LinkRefused, read

from .conftest import SCOPE, T0
from .test_lifecycle import holder


async def test_missing_proof_refuses_before_authority(db, authority):
    caller = await holder(db, authority)
    async with db.transaction() as tx:
        with pytest.raises(LinkRefused) as refused:
            await read(tx, authority, caller=caller, page_id=SCOPE.page_id, now=T0)
        assert (refused.value.code, refused.value.status) == ("current_member_required", 403)


async def test_preflight_returns_frozen_internal_evidence_without_a_lifecycle_lock(db, authority):
    import asyncio
    from dataclasses import FrozenInstanceError

    from aweb_naapp.runtime.capability_links import load_link_creator

    from .conftest import CREATOR, TEAM_KEY

    caller = await holder(db, authority)
    async with db.transaction() as tx:
        await tx.fetch_value(
            "SELECT link_id FROM {{tables.capability_links}} WHERE link_id=$1 FOR UPDATE",
            caller.link_id,
        )
        creator = await asyncio.wait_for(load_link_creator(db, link_id=caller.link_id), 2)
        assert creator.scope == SCOPE and creator.principal_did == CREATOR
        assert creator.team_did_key == TEAM_KEY
        with pytest.raises(FrozenInstanceError):
            creator.certificate_id = "other"


@pytest.mark.parametrize("operation", ["exchange", "read", "admit"])
@pytest.mark.parametrize(
    "fault", ["team", "certificate", "key", "expired", "future", "unbounded", "nan", "serialized"]
)
async def test_locked_use_requires_the_exact_original_runtime_proof(
    db, authority, operation, fault
):
    from dataclasses import asdict, replace

    from aweb_naapp.runtime.capability_links import admit, exchange

    from .conftest import proof_for_link
    from .test_exchange import body
    from .test_lifecycle import action_body

    caller = await holder(db, authority)
    proof = await proof_for_link(db, caller.link_id)
    proof = replace(proof, checked_at=10.0, fresh_until=70.0)
    changes = {
        "team": {"team_id": "other:acme.com"},
        "certificate": {"certificate_id": "other-cert"},
        "key": {"team_did_key": "other-key"},
        "expired": {"fresh_until": 39.0},
        "future": {"checked_at": 41.0},
        "unbounded": {"fresh_until": 71.0},
        "nan": {"fresh_until": float("nan")},
    }
    proof = asdict(proof) if fault == "serialized" else replace(proof, **changes[fault])

    async def forbidden(tx, **kwargs):
        raise AssertionError("proof refusal must precede the authority callback")

    authority.require_current_creator = forbidden
    with pytest.raises(LinkRefused) as refused:
        if operation == "exchange":
            # Obtain the secret from a newly minted link (secrets are never stored).
            from .conftest import mint_link

            minted = await mint_link(db, authority)
            await exchange(
                db,
                authority,
                link_id=minted.link_id,
                body=body(minted.secret),
                client="203.0.113.7",
                now=T0,
                proof=proof,
                proof_clock=lambda: 40.0,
            )
        else:
            async with db.transaction() as tx:
                if operation == "read":
                    await read(
                        tx,
                        authority,
                        caller=caller,
                        page_id=SCOPE.page_id,
                        now=T0,
                        proof=proof,
                        proof_clock=lambda: 40.0,
                    )
                else:
                    await admit(
                        tx,
                        authority,
                        None,
                        caller=caller,
                        page_id=SCOPE.page_id,
                        body=action_body(),
                        client="203.0.113.7",
                        now=T0,
                        proof=proof,
                        proof_clock=lambda: 40.0,
                    )
        assert (refused.value.code, refused.value.status) == ("current_member_required", 403)


@pytest.mark.parametrize("operation", ["read", "admit"])
async def test_real_link_lock_wait_cannot_extend_proof_expiry(db, authority, operation):
    import asyncio
    from dataclasses import replace

    from aweb_naapp.runtime.capability_links import admit

    from .conftest import proof_for_link
    from .test_lifecycle import action_body

    caller = await holder(db, authority)
    proof = replace(await proof_for_link(db, caller.link_id), checked_at=10.0, fresh_until=70.0)
    clock_value = [40.0]
    clock_reads = []
    backend = asyncio.Future()

    def clock():
        clock_reads.append(clock_value[0])
        return clock_value[0]

    async def blocked_use():
        async with db.transaction() as tx:
            backend.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            kwargs = dict(
                caller=caller, page_id=SCOPE.page_id, now=T0, proof=proof, proof_clock=clock
            )
            if operation == "read":
                await read(tx, authority, **kwargs)
            else:
                await admit(tx, authority, None, body=action_body(), client="203.0.113.7", **kwargs)

    async with db.transaction() as blocking:
        await blocking.fetch_value(
            "SELECT link_id FROM {{tables.capability_links}} WHERE link_id=$1 FOR UPDATE",
            caller.link_id,
        )
        pending = asyncio.create_task(blocked_use())
        pid = await asyncio.wait_for(backend, 2)
        try:
            for _ in range(100):
                if await db.fetch_value("SELECT cardinality(pg_blocking_pids($1)) > 0", pid):
                    break
                await asyncio.sleep(0.01)
            else:
                pytest.fail("holder query did not wait on the real link row lock")
            assert not pending.done() and clock_reads == []
            clock_value[0] = 80.0
        except BaseException:
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
            raise
    with pytest.raises(LinkRefused) as refused:
        await asyncio.wait_for(pending, 2)
    assert (refused.value.code, refused.value.status) == ("current_member_required", 403)
    assert clock_reads == [80.0]


async def test_scope_and_stored_creator_team_must_both_match(db, authority):
    from .conftest import proof_for_link

    caller = await holder(db, authority)
    proof = await proof_for_link(db, caller.link_id)
    await db.execute(
        "UPDATE {{tables.capability_links}} SET record=jsonb_set(record, '{created_by,team_id}', to_jsonb('other:acme.com'::text)) WHERE link_id=$1",
        caller.link_id,
    )
    async with db.transaction() as tx:
        with pytest.raises(LinkRefused, match="current_member_required"):
            await read(tx, authority, caller=caller, page_id=SCOPE.page_id, now=T0, proof=proof)


async def test_freshness_boundary_accepts_original_expiry_without_refresh(db, authority):
    from dataclasses import replace

    from .conftest import proof_for_link

    caller = await holder(db, authority)
    proof = replace(await proof_for_link(db, caller.link_id), checked_at=10.0, fresh_until=70.0)
    observed = []

    async def local(tx, *, creator, proof):
        observed.append(proof)

    authority.require_current_creator = local
    async with db.transaction() as tx:
        await read(
            tx,
            authority,
            caller=caller,
            page_id=SCOPE.page_id,
            now=T0,
            proof=proof,
            proof_clock=lambda: 70.0,
        )
    assert observed == [proof]
    assert observed[0] is proof  # No replacement or freshness extension under the lock.


@pytest.mark.parametrize(
    "status,code", [(403, "current_member_required"), (503, "current_membership_unavailable")]
)
async def test_http_phase_one_refusal_precedes_transaction_and_keeps_privacy_headers(
    db, authority, monkeypatch, status, code
):
    import httpx
    from fastapi import FastAPI, HTTPException

    from aweb_naapp.runtime.capability_links import routes

    from .conftest import mint_link
    from .test_exchange import body
    from .test_exchange_route import _has_link_headers

    minted = await mint_link(db, authority)
    checked = []

    async def phase_one(creator):
        checked.append(creator)
        raise HTTPException(status_code=status, detail={"code": code})

    async def forbidden(*args, **kwargs):
        raise AssertionError("phase-one refusal must precede exchange transactions")

    monkeypatch.setattr(routes, "exchange", forbidden)
    app = FastAPI()
    routes.mount_link_exchange(
        app,
        db=db,
        authority=authority,
        check_current_member=phase_one,
        client_address=lambda request: "203.0.113.7",
        clock=lambda: T0,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://pages.example"
    ) as client:
        malformed = await client.post("/v1/links/unknown/session", content=b"{}")
        assert malformed.status_code == 422 and checked == []
        response = await client.post(
            f"/v1/links/{minted.link_id}/session", content=body(minted.secret)
        )
    assert response.status_code == status
    assert response.json() == {"detail": {"code": code}}
    assert _has_link_headers(response)
    assert len(checked) == 1 and checked[0].scope == SCOPE
    assert checked[0].certificate_id not in response.text
