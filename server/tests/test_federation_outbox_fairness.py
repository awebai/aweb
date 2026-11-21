"""A poison prefix cannot starve a healthy committed federation mutation."""

from uuid import UUID, uuid4

import pytest

from aweb.federation.delivery import deliver_federated_phase_b
from aweb.outbox_recovery import recover_outboxes
from test_federation_activation_delivery import (
    _DB,
    _envelope,
    _seed_recipient_and_authority,
)


@pytest.mark.asyncio
async def test_recovery_attempts_healthy_101st_row_past_100_failing_callbacks(
    aweb_cloud_db,
):
    manager = aweb_cloud_db.aweb_db
    first = _envelope()
    recipient, authority = await _seed_recipient_and_authority(manager, first)
    envelopes = [
        first.model_copy(
            update={"message_id": str(uuid4()), "conversation_id": str(uuid4())}
        )
        for _ in range(101)
    ]
    for envelope in envelopes:
        await deliver_federated_phase_b(
            _DB(manager),
            envelope=envelope,
            signature="signed-message",
            recipient=recipient,
            authority_token=authority,
            registry_client=None,
        )
    poison = {item.message_id for item in envelopes[:100]}
    healthy = envelopes[-1].message_id
    calls = []
    accepted = []

    async def publisher(event_type, payload):
        assert event_type == "message.sent"
        message_id = payload["message_id"]
        calls.append(message_id)
        if message_id in poison:
            raise RuntimeError("test publisher unavailable for this committed mutation")
        accepted.append(message_id)

    # This is the serving host's callback fault; no recovery/writer code is replaced.
    await recover_outboxes(aweb_db=manager, redis=None, on_mutation=publisher)
    assert len(calls) == 100 and set(calls) == poison
    assert accepted == []
    await recover_outboxes(aweb_db=manager, redis=None, on_mutation=publisher)
    assert accepted == [healthy]
    healthy_row = await manager.fetch_one(
        "SELECT delivered_at,attempt_count,last_error FROM {{tables.federation_mutation_outbox}} WHERE message_id=$1",
        UUID(healthy),
    )
    assert healthy_row["delivered_at"] is not None
    assert healthy_row["attempt_count"] == 1 and healthy_row["last_error"] is None
    assert (
        await manager.fetch_value(
            "SELECT count(*) FROM {{tables.federation_mutation_outbox}} WHERE delivered_at IS NULL"
        )
        == 100
    )

    poison.clear()
    await recover_outboxes(aweb_db=manager, redis=None, on_mutation=publisher)
    assert len(accepted) == 101 and len(set(accepted)) == 101
    assert accepted.count(healthy) == 1
    assert (
        await manager.fetch_value(
            "SELECT count(*) FROM {{tables.federation_mutation_outbox}} WHERE delivered_at IS NULL"
        )
        == 0
    )
    assert await manager.fetch_value("SELECT count(*) FROM {{tables.messages}}") == 101
