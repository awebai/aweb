"""A team-certificate-signed HTTP request from a fixture actor, for the real serving test stacks."""

from __future__ import annotations

import json

from test_dashboard_privacy import TEAM
from test_messages_http import _signed_team_headers


async def _team_request(
    env, actor, method, path, body=None, *, team_id=TEAM, certificate=None
):
    identity = env.actors[actor]
    content = json.dumps(body).encode() if body is not None else b""
    headers = _signed_team_headers(
        identity.sk,
        identity.did,
        team_id,
        identity.certificate if certificate is None else certificate,
        content,
    )
    headers["Content-Type"] = "application/json"
    return await env.client.request(method, path, content=content, headers=headers)
