from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

import pytest

from .harness import AwebTarget, SSEEvent, sse_events


def _now_deadline(seconds: int = 10) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


async def _wait_for_matching_event(
    *,
    aweb_client,
    url: str,
    params: dict[str, Any],
    predicate: Callable[[SSEEvent, dict[str, Any]], bool],
    timeout_seconds: float = 3.0,
) -> tuple[SSEEvent, dict[str, Any]]:
    async def _run() -> tuple[SSEEvent, dict[str, Any]]:
        async for event in sse_events(aweb_client, url, params=params):
            try:
                payload = json.loads(event.data)
            except json.JSONDecodeError:
                continue
            if predicate(event, payload):
                return event, payload
        raise RuntimeError("SSE stream ended before matching event arrived")

    return await asyncio.wait_for(_run(), timeout=timeout_seconds)


@pytest.mark.aweb_conformance
@pytest.mark.asyncio
async def test_chat_sse_replays_recent_history(aweb_client, aweb_client_2, aweb_target: AwebTarget) -> None:
    body = f"replay-{uuid.uuid4().hex}"
    create = await aweb_client.post(
        "/v1/chat/sessions",
        json={
            "to_aliases": [aweb_target.agent_2.alias],
            "message": body,
            "leaving": False,
        },
    )
    assert create.status_code == 200, create.text
    create_data = create.json()
    session_id = create_data["session_id"]
    sent_message_id = create_data["message_id"]

    sse_url = f"/v1/chat/sessions/{session_id}/stream"

    event, payload = await _wait_for_matching_event(
        aweb_client=aweb_client_2,
        url=sse_url,
        params={"deadline": _now_deadline(10)},
        predicate=lambda ev, pl: ev.event == "message" and pl.get("message_id") == sent_message_id,
        timeout_seconds=5.0,
    )

    assert event.event == "message"
    assert payload.get("type") == "message"
    assert payload.get("session_id") == session_id
    assert payload.get("message_id") == sent_message_id
    assert payload.get("from_agent") == aweb_target.agent_1.alias
    assert payload.get("body") == body
    assert isinstance(payload.get("timestamp"), str) and payload["timestamp"]


@pytest.mark.aweb_conformance
@pytest.mark.asyncio
async def test_chat_sse_delivers_live_messages_after_connect(
    aweb_client, aweb_client_2, aweb_target: AwebTarget
) -> None:
    msg_1 = f"baseline-{uuid.uuid4().hex}"
    msg_2 = f"live-{uuid.uuid4().hex}"

    # Create (or find) the session and establish a message baseline.
    create = await aweb_client.post(
        "/v1/chat/sessions",
        json={
            "to_aliases": [aweb_target.agent_2.alias],
            "message": msg_1,
            "leaving": False,
        },
    )
    assert create.status_code == 200, create.text
    create_data = create.json()
    session_id = create_data["session_id"]

    sse_url = f"/v1/chat/sessions/{session_id}/stream"

    sent_message_id: dict[str, str | None] = {"value": None}

    async def _send_second_message() -> str:
        # Small delay to ensure the SSE connection is established.
        await asyncio.sleep(0.15)
        resp = await aweb_client.post(
            "/v1/chat/sessions",
            json={
                "to_aliases": [aweb_target.agent_2.alias],
                "message": msg_2,
                "leaving": False,
            },
        )
        assert resp.status_code == 200, resp.text
        return resp.json()["message_id"]

    wait_task = asyncio.create_task(
        _wait_for_matching_event(
            aweb_client=aweb_client_2,
            url=sse_url,
            params={"deadline": _now_deadline(10)},
            predicate=lambda ev, pl: ev.event == "message"
            and pl.get("message_id") == sent_message_id["value"],
            timeout_seconds=5.0,
        )
    )
    sent_message_id["value"] = await _send_second_message()

    event, payload = await wait_task

    assert event.event == "message"
    assert payload.get("type") == "message"
    assert payload.get("session_id") == session_id
    assert payload.get("message_id") == sent_message_id["value"]
    assert payload.get("from_agent") == aweb_target.agent_1.alias
    assert payload.get("body") == msg_2


@pytest.mark.aweb_conformance
@pytest.mark.asyncio
async def test_chat_sse_emits_read_receipt_when_other_side_marks_read(
    aweb_client, aweb_client_2, aweb_target: AwebTarget
) -> None:
    body = f"rr-{uuid.uuid4().hex}"

    # Create session + message from agent 1 to agent 2.
    create = await aweb_client.post(
        "/v1/chat/sessions",
        json={
            "to_aliases": [aweb_target.agent_2.alias],
            "message": body,
            "leaving": False,
        },
    )
    assert create.status_code == 200, create.text
    create_data = create.json()
    session_id = create_data["session_id"]
    message_id = create_data["message_id"]

    sse_url = f"/v1/chat/sessions/{session_id}/stream"

    async def _mark_read() -> None:
        await asyncio.sleep(0.15)
        resp = await aweb_client_2.post(
            f"/v1/chat/sessions/{session_id}/read",
            json={"up_to_message_id": message_id},
        )
        assert resp.status_code == 200, resp.text

    mark_task = asyncio.create_task(_mark_read())

    event, payload = await _wait_for_matching_event(
        aweb_client=aweb_client,
        url=sse_url,
        params={"deadline": _now_deadline(10)},
        predicate=lambda ev, pl: ev.event == "read_receipt"
        and pl.get("type") == "read_receipt"
        and pl.get("up_to_message_id") == message_id,
        timeout_seconds=5.0,
    )

    await mark_task

    assert event.event == "read_receipt"
    assert payload.get("session_id") == session_id
    assert payload.get("reader_alias") == aweb_target.agent_2.alias
    assert payload.get("up_to_message_id") == message_id
    assert isinstance(payload.get("extends_wait_seconds", 0), int)
    assert isinstance(payload.get("timestamp"), str) and payload["timestamp"]
