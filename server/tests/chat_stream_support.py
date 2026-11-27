"""A chat session and its SSE stream between fixture actors, for the real serving test stacks."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from test_dashboard_privacy import _request
from test_messages_http import _signed_identity_headers


async def _session(env, sender, *recipients):
    response = await _request(
        env,
        sender,
        "POST",
        "/v1/chat/sessions",
        {
            "to_dids": [env.actors[alias].did for alias in recipients],
            "message": "hello",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["session_id"]


def _stream(env, viewer, session_id, *, seconds=8):
    identity = env.actors[viewer]
    deadline = (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()
    return env.client.stream(
        "GET",
        f"/v1/chat/sessions/{session_id}/stream",
        params={"deadline": deadline},
        headers=_signed_identity_headers(identity.sk, identity.did, "", b""),
    )
