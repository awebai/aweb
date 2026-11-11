"""An app's own owner act recorded by the shared credential recorder, on real
PostgreSQL with a real AWID registry and real owner acts. Only an act the
app's reviewed code exempts, and only for an app that writes each event to its
own record in the transaction that enqueued it, is recorded with no registered
hook target; it is still enqueued for delivery (ruling ed36580d)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from aweb_naapp.hooks.owner_act import Refused
from aweb_naapp.runtime.credential_audit import CredentialAudit
from tests.runtime.credential_audit.support import (
    SELF_RECORDED_ACTS,
    World,
    events,
    hold_subject,
    record_app_act,
)

HOLD = {"act": "logs.legal_hold.set", "direction": "widening", "hold_id": "hold-1",
        "hold_scope": "all", "reason_code": "litigation"}  # fmt: skip


async def test_an_exempt_act_is_recorded_and_owed_with_no_registered_target(world: World):
    world.target_registered[0] = False
    event_id = await record_app_act(world, "logs.legal-hold.set", hold_subject("hold-1"), HOLD)
    [(recorded_id, recorded)] = await events(world)
    assert recorded_id == event_id
    assert [handed for _, handed in world.handed] == [event_id]
    payload = recorded["payload"]
    assert {name: payload[name] for name in HOLD} == HOLD
    assert payload["authority"] == "owner_act"
    signing = await world.db.fetch_value(
        "SELECT act_sha256 FROM {{tables.owner_act_nonces}} WHERE team_id = $1",
        recorded["team_id"],
    )
    assert payload["owner_act_sha256"] == signing


async def test_a_widening_act_not_exempt_is_refused_with_no_registered_target(world: World):
    world.target_registered[0] = False
    installation = {key: hold_subject("hold-1")[key] for key in ("app_id", "installation_id")}
    lengthened = {"act": "logs.retention.lengthened", "direction": "widening",
                  "event_class": "all", "retention": "keep"}  # fmt: skip
    with pytest.raises(Refused):
        await record_app_act(
            world,
            "logs.retention.set",
            {**installation, "event_class": "all", "retention": "keep"},
            lengthened,
        )
    assert await events(world) == []
    assert world.handed == []
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.owner_act_nonces}}") == 0


async def test_an_exemption_needs_the_apps_own_record_in_the_same_transaction(world: World):
    with pytest.raises(ValueError):
        CredentialAudit(
            db=world.db,
            app_id=world.admitted.app_id,
            fence=world.fence,
            contexts=world.recorder._contexts,
            owner_act_scope=world.owner.verifier.scope,
            producer=world.recorder._producer,
            passkeys=lambda: world.passkeys,
            role_of=world.recorder._role_of,
            registration_view=world.recorder._view,
            max_backlog_age=timedelta(minutes=5),
            migration_module="example_credential_audit",
            ungated_acts=SELF_RECORDED_ACTS,
        )
