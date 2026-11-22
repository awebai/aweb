"""Transport adaptation retains the original messaging credential evidence."""

from datetime import datetime, timezone

from aweb.auth_context import GrantContext
from aweb.identity_address import AddressResolution
from aweb.identity_auth_deps import MessagingAuth
from aweb.mcp.auth import AuthContext
from aweb.mcp.tools.federation import mcp_messaging_auth


def test_mcp_adapter_retains_the_complete_original_messaging_auth():
    original = MessagingAuth(
        did_key="did:key:subject",
        did_aw="did:aw:subject",
        address=None,
        team_id="agents:example.test",
        agent_id="member-uuid",
        alias="subject",
        certificate_id="issuing-certificate",
        verified_team_id="agents:example.test",
        grant=GrantContext(
            grant_id="grant-id",
            session_did_key="did:key:session",
            issuing_certificate_id="issuing-certificate",
            scopes=("mail.read",),
            expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
        ),
        id_chain={"type": "aweb.id-chain", "certificates": []},
        address_resolution=AddressResolution(
            state="unknown", cause=OSError("address discovery unavailable")
        ),
    )
    context = AuthContext.from_messaging_auth(identity=original)
    assert mcp_messaging_auth(context) is original
    assert context.address_resolution is original.address_resolution
    assert context.certificate_id == original.certificate_id
