"""MCP preserves membership metadata independently of encrypted content access."""

from datetime import datetime, timezone
from uuid import uuid4

from aweb.mcp.tools.mail import mcp_mail_message_from_row
from aweb.messaging.sender_membership import SenderMembership


def test_mcp_encrypted_mail_retains_removed_sender_state_without_exposing_content():
    row = dict(
        message_id=uuid4(),
        conversation_id=uuid4(),
        from_agent_id=uuid4(),
        from_alias="sender",
        from_address="",
        to_alias="recipient",
        subject="",
        body="",
        priority="normal",
        read_at=None,
        created_at=datetime.now(timezone.utc),
        content_mode="encrypted_v2",
        message_version=2,
    )
    membership = SenderMembership(team_id="team:example.test", state="inactive")
    message = mcp_mail_message_from_row(
        row, include_bodies=False, sender_membership=membership
    )
    assert message["sender_membership"] == membership.model_dump()
    assert message["sender_membership"]["state"] == "inactive"
    assert not message["decryptable"]
    assert message["subject"] == ""
    assert "body" not in message
