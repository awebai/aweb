"""Native mail tool registration."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from aweb.mcp.tools.mail import check_inbox as _check_inbox_impl
from aweb.mcp.tools.mail import list_threads as _list_threads_impl
from aweb.mcp.tools.mail import send_mail as _send_mail_impl

from .dependencies import ToolDependencies


def register_tools(mcp: FastMCP, dependencies: ToolDependencies) -> None:
    """Register the native mail tools with the serving dependencies."""

    @mcp.tool(
        name="send_mail",
        description="Send async mail with a required body by recipient, or continue an existing mail conversation by conversation_id. A recipient send starts a new thread. Use list_threads to find a conversation to continue. Hosted custodial sends use managed encryption by default when the recipient has an encryption key. The hosted service can read the mail; this is not end-to-end encryption. Set plaintext=true to store message content unencrypted.",
    )
    async def send_mail(
        to: str = "",
        body: str = "",
        conversation_id: str = "",
        subject: str = "",
        priority: str = "normal",
        plaintext: bool = False,
    ) -> str:
        """Send async mail with a required body by recipient, or continue an existing mail conversation by conversation_id. A recipient send starts a new thread. Use list_threads to find a conversation to continue. Hosted custodial sends use managed encryption by default when the recipient has an encryption key. The hosted service can read the mail; this is not end-to-end encryption. Set plaintext=true to store message content unencrypted."""
        return await _send_mail_impl(
            dependencies.db_infra,
            registry_client=dependencies.registry_client,
            federation_authority=dependencies.federation_authority,
            hosted_signer=dependencies.hosted_signer,
            hosted_encryptor=dependencies.hosted_encryptor,
            to=to,
            conversation_id=conversation_id,
            subject=subject,
            body=body,
            priority=priority,
            plaintext=plaintext,
            federation_transport=dependencies.federation_mail_transport,
            public_origin=dependencies.public_origin,
        )

    @mcp.tool(
        name="list_threads",
        description="List your mail threads without acknowledging messages, newest activity first. Returns title (first-message subject; empty for E2EE), first_message_id, participants, last activity, unread count and conversation_id. Filters only narrow your participant access. Continue a chosen thread with send_mail conversation_id.",
    )
    async def list_threads(
        limit: int = 50,
        cursor: str = "",
        participant_did: str = "",
        participant_address: str = "",
    ) -> str:
        """List your mail threads without acknowledging messages, newest activity first. Returns title (first-message subject; empty for E2EE), first_message_id, participants, last activity, unread count and conversation_id. Filters only narrow your participant access. Continue a chosen thread with send_mail conversation_id."""
        return await _list_threads_impl(
            dependencies.db_infra,
            limit=limit,
            cursor=cursor,
            participant_did=participant_did,
            participant_address=participant_address,
        )

    @mcp.tool(
        name="check_mail",
        description="Check hosted mail. The tool marks returned unread messages read before returning. The hosted service decrypts managed encrypted mail for this MCP session; self-custodial encrypted content remains metadata-only.",
    )
    async def check_mail(
        unread_only: bool = True, limit: int = 50, include_bodies: bool = True
    ) -> str:
        """Check hosted mail. The tool marks returned unread messages read before returning. The hosted service decrypts managed encrypted mail for this MCP session; self-custodial encrypted content remains metadata-only."""
        return await _check_inbox_impl(
            dependencies.db_infra,
            hosted_decryptor=dependencies.hosted_decryptor,
            unread_only=unread_only,
            limit=limit,
            include_bodies=include_bodies,
        )
