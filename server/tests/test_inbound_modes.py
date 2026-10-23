"""Public mode normalization shared by embedding hosts and OSS adapters."""
import pytest

from aweb.inbound_modes import normalize_inbound_mode


@pytest.mark.parametrize("value,want", [(None, "open"), ("", "open"), ("  ", "open"), (" OPEN ", "open"), ("team_and_contacts", "team_and_contacts"), (" contacts_only ", "contacts_only")])
def test_normalize_inbound_mode(value, want):
    assert normalize_inbound_mode(value) == want


def test_caller_owns_default():
    assert normalize_inbound_mode(None, default="team_and_contacts") == "team_and_contacts"
    assert normalize_inbound_mode("", default="contacts_only") == "contacts_only"


@pytest.mark.parametrize("value", ["contacts-only", "contacts_or_teammates", "team", "bogus"])
def test_normalize_inbound_mode_rejects_unknown_wire_value(value):
    with pytest.raises(ValueError, match="inbound_mode must be one of"):
        normalize_inbound_mode(value)


def test_default_must_be_canonical():
    with pytest.raises(ValueError):
        normalize_inbound_mode(None, default="unknown")


async def _memberships(manager, modes):
    from test_messages import _insert_team, _insert_agent, _make_did_key
    key = _make_did_key()
    ids = []
    for index, mode in enumerate(modes):
        team = f"team{index}:policy.example"
        await _insert_team(manager, team)
        ids.append(await _insert_agent(manager, team_id=team, alias=f"member{index}", did_key=key,
                                       did_aw="did:aw:policy", address="policy.example/member", inbound_mode=mode))
    return ids, key


@pytest.mark.asyncio
@pytest.mark.parametrize("modes,want", [
    (["open", "contacts_only"], "contacts_only"),
    (["team_and_contacts", "open"], "team_and_contacts"),
    (["contacts_only", "team_and_contacts", "open"], "contacts_only"),
])
async def test_effective_identity_policy(aweb_cloud_db, modes, want):
    from aweb.inbound_modes import effective_inbound_mode
    manager = aweb_cloud_db.aweb_db
    ids, _ = await _memberships(manager, modes)
    await manager.execute("UPDATE {{tables.agents}} SET status='retired' WHERE agent_id=$1", ids[0])
    assert await effective_inbound_mode(manager, "did:aw:policy") == want


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", [None, "unknown"])
async def test_identity_policy_rejects_null_but_ignores_deleted_rows(aweb_cloud_db, invalid):
    from aweb.inbound_modes import effective_inbound_mode
    from aweb.service_errors import ForbiddenError
    manager = aweb_cloud_db.aweb_db
    if invalid is not None:
        await manager.execute("ALTER TABLE {{tables.agents}} DROP CONSTRAINT agents_inbound_mode_valid")
    ids, _ = await _memberships(manager, ["open", invalid])
    with pytest.raises(ForbiddenError, match="inbound_mode migration required"):
        await effective_inbound_mode(manager, "did:aw:policy")
    await manager.execute("UPDATE {{tables.agents}} SET deleted_at=clock_timestamp() WHERE agent_id=$1", ids[1])
    assert await effective_inbound_mode(manager, "did:aw:policy") == "open"
    with pytest.raises(ForbiddenError, match="inbound_mode migration required"):
        await effective_inbound_mode(manager, "did:aw:unknown")
    assert await effective_inbound_mode(manager, "did:aw:new", default="open") == "open"


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["team_and_contacts", "contacts_only"])
async def test_identity_writer_unifies_rows_and_connect_inherits(aweb_cloud_db, mode):
    from aweb.inbound_modes import effective_inbound_mode, set_identity_inbound_mode
    from aweb.routes.connect import _ensure_agent
    from test_messages import _insert_team
    manager = aweb_cloud_db.aweb_db
    ids, key = await _memberships(manager, ["contacts_only", "open"])
    async with manager.transaction() as tx:
        await set_identity_inbound_mode(tx, "did:aw:policy", mode)
    assert await effective_inbound_mode(manager, "did:aw:policy") == mode
    rows = await manager.fetch_all("SELECT inbound_mode FROM {{tables.agents}} WHERE did_aw='did:aw:policy'")
    assert [row["inbound_mode"] for row in rows] == [mode] * 2
    await _insert_team(manager, "third:policy.example")
    async with manager.transaction() as tx:
        agent_id = await _ensure_agent(tx, "third:policy.example", key, "did:aw:policy", "policy.example/member",
                                       "third", "global", "", "agent", "developer", "third-certificate")
    assert await manager.fetch_value("SELECT inbound_mode FROM {{tables.agents}} WHERE agent_id=$1", agent_id) == mode


@pytest.mark.asyncio
@pytest.mark.parametrize("lock", ["for_share", "for_update"])
async def test_identity_policy_locks_every_membership(aweb_cloud_db, lock):
    import asyncio
    from aweb.inbound_modes import effective_inbound_mode
    manager = aweb_cloud_db.aweb_db
    ids, _ = await _memberships(manager, ["open", "contacts_only"])
    tasks = []
    try:
        async with manager.transaction() as tx:
            assert await effective_inbound_mode(tx, "did:aw:policy", **{lock: True}) == "contacts_only"
            for agent_id in ids:
                tasks.append(asyncio.create_task(manager.execute(
                    "UPDATE {{tables.agents}} SET inbound_mode='open' WHERE agent_id=$1", agent_id,
                )))
            await asyncio.sleep(0.05)
            assert all(not task.done() for task in tasks), "every identity membership must remain locked"
        await asyncio.wait_for(asyncio.gather(*tasks), 5)
        assert await effective_inbound_mode(manager, "did:aw:policy") == "open"
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.asyncio
async def test_delivery_policy_reads_raw_did_not_gated_authority(aweb_cloud_db):
    from aweb.messaging.messages import _effective_inbound_mode
    from test_messages import _DbShim

    manager = aweb_cloud_db.aweb_db
    await _memberships(manager, ["contacts_only", "open"])
    # A missing verified routing identity does not erase stored global policy.
    recipient = {"policy_did_aw": "did:aw:policy", "did_aw": None, "identity_scope": "global"}
    assert await _effective_inbound_mode(_DbShim(manager), recipient) == "contacts_only"
    # Direct service fixtures without the policy projection remain supported.
    assert await _effective_inbound_mode(_DbShim(manager), {"did_aw": "did:aw:policy"}) == "contacts_only"


@pytest.mark.asyncio
@pytest.mark.parametrize("verified_did", ["", "did:aw:authorized"])
async def test_policy_patch_uses_authenticated_identity_scope(aweb_cloud_db, verified_did):
    from fastapi import HTTPException
    from aweb.routes.agents import update_my_inbound_mode, UpdateAgentInboundModeRequest
    from aweb.team_auth_deps import TeamIdentity
    from test_messages import _DbShim, _insert_agent, _make_did_key

    manager = aweb_cloud_db.aweb_db
    ids, key = await _memberships(manager, ["contacts_only", "open"])
    # The caller's stored row claims another identity. Only authentication may
    # select an identity-wide write target, even when the raw row says global.
    await _insert_agent(manager, team_id="team1:policy.example", alias="authorized", did_key=_make_did_key(),
                        did_aw="did:aw:authorized", address="policy.example/authorized", inbound_mode="contacts_only")
    identity = TeamIdentity(team_id="team0:policy.example", alias="member0", did_key=key,
                            did_aw=verified_did, address="", agent_id=ids[0],
                            identity_scope="global", certificate_id="policy-test")
    payload = UpdateAgentInboundModeRequest(inbound_mode="open")
    if not verified_did:
        with pytest.raises(HTTPException) as error:
            await update_my_inbound_mode(None, payload, _DbShim(manager), identity)
        assert error.value.status_code == 409
        assert error.value.detail == "Agent identity migration required"
    else:
        await update_my_inbound_mode(None, payload, _DbShim(manager), identity)
        assert await manager.fetch_value("SELECT inbound_mode FROM {{tables.agents}} WHERE did_aw=$1", verified_did) == "open"
    rows = await manager.fetch_all("SELECT inbound_mode FROM {{tables.agents}} WHERE did_aw='did:aw:policy' ORDER BY alias")
    assert [row["inbound_mode"] for row in rows] == ["contacts_only", "open"]


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["open", "team_and_contacts", "contacts_only", None, "unknown"])
async def test_global_policy_without_raw_did_uses_only_its_own_mode(aweb_cloud_db, mode):
    from aweb.messaging.messages import _effective_inbound_mode
    from aweb.service_errors import ForbiddenError
    from test_messages import _DbShim

    recipient = {"identity_scope": "global", "policy_did_aw": None, "did_aw": None, "inbound_mode": mode}
    if mode is None or mode == "unknown":
        with pytest.raises(ForbiddenError, match="inbound_mode migration required"):
            await _effective_inbound_mode(_DbShim(aweb_cloud_db.aweb_db), recipient)
    else:
        assert await _effective_inbound_mode(_DbShim(aweb_cloud_db.aweb_db), recipient) == mode
