"""A simultaneous exact remote create must reread the accepted local projection."""

import asyncio

import pytest

from chat_pair_support import route_pair, _submission  # noqa: F401
from test_actl_fresh_chat import _post


@pytest.mark.asyncio
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_concurrent_federated_chat_create_returns_one_committed_projection(
    route_pair, monkeypatch, encrypted
):
    import aweb.messaging.chat_send as owner

    pair = route_pair
    sender, recipient = pair.source.global_actor, pair.target.global_actor
    request = _submission(sender, recipient, "chat", encrypted=encrypted)
    original = owner._stored_exact_chat_send
    arrivals = 0
    both = asyncio.Event()

    async def held_read(db, payload, **kwargs):
        nonlocal arrivals
        result = await original(db, payload, **kwargs)
        if payload.message_id == str(request[2].mid) and arrivals < 2:
            assert result is None
            arrivals += 1
            if arrivals == 2:
                both.set()
            await asyncio.wait_for(both.wait(), 10)
        return result

    monkeypatch.setattr(owner, "_stored_exact_chat_send", held_read)
    results = await asyncio.gather(_post(sender, request), _post(sender, request))
    assert arrivals == 2
    assert [result.status_code for result in results] == [200, 200], [
        result.text for result in results
    ]
    assert results[0].json() == results[1].json()
    for node in (pair.source, pair.target):
        assert (
            await node.db.fetch_value(
                "SELECT count(*) FROM {{tables.chat_messages}} WHERE message_id=$1",
                request[2].mid,
            )
            == 1
        )
    assert (
        await pair.target.db.fetch_value(
            "SELECT count(*) FROM {{tables.federation_mutation_outbox}} WHERE message_id=$1",
            request[2].mid,
        )
        == 1
    )
