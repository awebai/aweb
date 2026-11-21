"""Distinct send intents still conflict on a caller-selected fresh conversation.

Database/HTTP component coverage; the imported fixture overrides authentication.
"""

import asyncio
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from test_mail_send_retry import _sender, _both_past_the_lookup


@pytest.mark.asyncio
async def test_distinct_concurrent_mail_intents_keep_the_conversation_collision(
    aweb_cloud_db, monkeypatch
):
    db, app, events, *_ = await _sender(aweb_cloud_db)
    conversation_id = str(uuid4())
    _both_past_the_lookup(monkeypatch)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        results = await asyncio.gather(
            *(
                client.post(
                    "/v1/messages",
                    json={
                        "to_alias": "bob",
                        "new_conversation": True,
                        "conversation_id": conversation_id,
                        "body": body,
                    },
                )
                for body in ("first distinct intent", "second distinct intent")
            )
        )
    assert sorted(result.status_code for result in results) == [200, 409]
    refused = next(result for result in results if result.status_code == 409)
    assert refused.json()["detail"] == "conversation_exists"
    assert (
        await db.fetch_value(
            "SELECT count(*) FROM {{tables.messages}} WHERE conversation_id=$1",
            UUID(conversation_id),
        )
        == 1
    )
    assert len(events) == 1
