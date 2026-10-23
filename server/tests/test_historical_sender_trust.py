"""Accepted authorship survives real workspace retirement (Athena73973a96)."""
from __future__ import annotations

import pytest

from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_e2ee_local_sender_read_trust import _local_sender_mail
from test_cli_human_reply import _cli
from test_messages_http import _signed_team_headers


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
async def test_verified_mail_survives_workspace_retirement(privacy_app, tmp_path):
    env = privacy_app
    async with _local_sender_mail(env, tmp_path, False, False, False) as (
            message_id, _, binary, command_dir, command_env, _):
        before = await _cli(binary, command_dir, command_env, "mail", "show", "--message-id", message_id, "--json")
        assert before["messages"][0]["verification_status"] == "verified"
        actor = env.actors["alice"]
        retired = await env.client.delete(f"/v1/workspaces/{actor.workspace}", headers=_signed_team_headers(
            actor.sk, actor.did, TEAM, actor.certificate, b""))
        assert retired.status_code == 200, retired.text
        after = await _cli(binary, command_dir, command_env, "mail", "show", "--message-id", message_id, "--json")
        shown = after["messages"][0]
        assert shown["verification_status"] == "verified", shown
        assert shown["sender_membership"]["current_status"] == "retired"
