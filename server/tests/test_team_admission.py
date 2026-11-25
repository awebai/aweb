"""Embedding hosts share the server's first-admission persistence owner."""

from datetime import datetime, timezone

import pytest
from nacl.signing import SigningKey

from awid.did import did_from_public_key


def _key():
    return did_from_public_key(bytes(SigningKey.generate().verify_key))


@pytest.mark.asyncio
async def test_invalid_team_id_is_actionable_before_storage():
    from aweb.team_admission import admit_team

    with pytest.raises(ValueError) as refused:
        await admit_team(db=None, team_id="not-a-canonical-team", team_did_key=_key())
    assert (
        str(refused.value)
        == "Invalid team ID. Use a canonical <team>:<namespace> team ID, then retry."
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("enforce", ["false", "true"])
async def test_admission_preserves_existing_pin_and_identity(
    aweb_cloud_db, monkeypatch, enforce
):
    from aweb.team_admission import admit_team
    from aweb.team_key_pins import AdmittedTeamKeys, TeamKeyPin

    monkeypatch.setenv("AWEB_ENFORCE_TEAM_KEY_PINS", enforce)
    db = aweb_cloud_db.aweb_db
    team_id = "engineering:admission.example"
    original_key, moved_key, served_key = _key(), _key(), _key()

    assert await admit_team(db=db, team_id=team_id, team_did_key=original_key)
    keys = AdmittedTeamKeys(db)
    before = await keys.pin(team_id)
    assert before is not None
    act_at = datetime.now(timezone.utc)
    assert await keys.move(team_id, expected=before, new=TeamKeyPin(moved_key, act_at))
    assert not await admit_team(db=db, team_id=team_id, team_did_key=served_key)

    row = await db.fetch_one(
        "SELECT namespace, team_name, team_did_key, team_key_act_at "
        "FROM {{tables.teams}} WHERE team_id=$1",
        team_id,
    )
    assert dict(row) == {
        "namespace": "admission.example",
        "team_name": "engineering",
        "team_did_key": moved_key,
        "team_key_act_at": act_at,
    }


@pytest.mark.asyncio
async def test_host_admission_then_native_connect_reuses_team(aweb_cloud_db):
    from aweb.routes.connect import connect_agent
    from aweb.team_admission import admit_team

    db = aweb_cloud_db.aweb_db
    team_id, team_key, member_key = "engineering:admission.example", _key(), _key()
    await admit_team(db=db, team_id=team_id, team_did_key=team_key)
    arguments = dict(
        db=db,
        cert_info={
            "team_id": team_id,
            "did_key": member_key,
            "alias": "builder",
            "identity_scope": "local",
            "certificate_id": "admitted-member",
        },
        team_did_key=team_key,
        hostname="",
        workspace_path="",
        repo_origin="",
        role="",
        human_name="",
        agent_type="agent",
    )
    connected = await connect_agent(**arguments)
    reconnected = await connect_agent(**arguments)
    assert reconnected == connected
    assert (
        await db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.teams}} WHERE team_id=$1", team_id
        )
        == 1
    )
    row = await db.fetch_one(
        "SELECT certificate_id, accepted_team_did_key, did_aw_verified_key, human_verified_key "
        "FROM {{tables.agents}} WHERE agent_id=$1::uuid",
        connected["agent_id"],
    )
    assert dict(row) == {
        "certificate_id": "admitted-member",
        "accepted_team_did_key": team_key,
        "did_aw_verified_key": None,
        "human_verified_key": None,
    }
