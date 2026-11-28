"""Native chat tool registration."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from aweb.mcp.tools.chat import chat_history as _chat_history_impl
from aweb.mcp.tools.chat import chat_pending as _chat_pending_impl
from aweb.mcp.tools.chat import chat_read as _chat_read_impl
from aweb.mcp.tools.chat import chat_send as _chat_send_impl

from .dependencies import ToolDependencies


def register_tools(mcp: FastMCP, dependencies: ToolDependencies) -> None:
    """Register the native chat tools with the serving dependencies."""

    @mcp.tool(
        name="send_chat",
        description="Send a real-time chat message to an agent. Humans are reached by mail; chat to an authoritative human refuses recipient_human_mail_only. Provide to for a routable address, DID, hosted handle, or same-team local alias, or conversation_id to reply in an existing conversation. Set wait=true to block until the other agent replies (recommended for conversations). Hosted custodial sends use managed encryption by default. The hosted service can read the chat; this is not end-to-end encryption. Set plaintext=true to store message content unencrypted.",
    )
    async def send_chat(
        to: str = "",
        message: str = "",
        conversation_id: str = "",
        wait: bool = False,
        wait_seconds: int = 120,
        leaving: bool = False,
        hang_on: bool = False,
        plaintext: bool = False,
    ) -> str:
        """Send a real-time chat message to an agent. Humans are reached by mail; chat to an authoritative human refuses recipient_human_mail_only. Provide to for a routable address, DID, hosted handle, or same-team local alias, or conversation_id to reply in an existing conversation. Set wait=true to block until the other agent replies (recommended for conversations). Hosted custodial sends use managed encryption by default. The hosted service can read the chat; this is not end-to-end encryption. Set plaintext=true to store message content unencrypted."""
        recipient_ref = to.strip()
        to_alias = ""
        to_did = ""
        to_address = ""
        if recipient_ref.startswith("did:aw:") or recipient_ref.startswith("did:key:"):
            to_did = recipient_ref
        elif "/" in recipient_ref or recipient_ref.startswith("@"):
            to_address = recipient_ref
        else:
            to_alias = recipient_ref
        return await _chat_send_impl(
            dependencies.db_infra,
            dependencies.redis,
            registry_client=dependencies.registry_client,
            federation_authority=dependencies.federation_authority,
            hosted_signer=dependencies.hosted_signer,
            hosted_encryptor=dependencies.hosted_encryptor,
            hosted_decryptor=dependencies.hosted_decryptor,
            message=message,
            to_alias=to_alias,
            to_did=to_did,
            to_address=to_address,
            session_id=conversation_id,
            wait=wait,
            wait_seconds=wait_seconds,
            leaving=leaving,
            hang_on=hang_on,
            plaintext=plaintext,
            federation_transport=dependencies.federation_chat_transport,
            public_origin=dependencies.public_origin,
        )

    @mcp.tool(
        name="check_chats",
        description="List chat conversations with unread messages waiting for you.",
    )
    async def check_chats() -> str:
        """List chat conversations with unread messages waiting for you."""
        return await _chat_pending_impl(
            dependencies.db_infra,
            dependencies.redis,
            hosted_decryptor=dependencies.hosted_decryptor,
        )

    @mcp.tool(name="read_chat", description="Get message history for a chat session.")
    async def read_chat(
        conversation_id: str, unread_only: bool = False, limit: int = 50
    ) -> str:
        """Get message history for a chat session."""
        return await _chat_history_impl(
            dependencies.db_infra,
            session_id=conversation_id,
            unread_only=unread_only,
            limit=limit,
            hosted_decryptor=dependencies.hosted_decryptor,
        )

    @mcp.tool(
        name="mark_chat_read",
        description="Mark chat messages read using up_to_message_id, message_ids, or both; message_ids takes precedence.",
    )
    async def mark_chat_read(
        conversation_id: str,
        up_to_message_id: str | None = None,
        message_ids: list[str] | None = None,
    ) -> str:
        """Mark chat messages read using up_to_message_id, message_ids, or both; message_ids takes precedence."""
        return await _chat_read_impl(
            dependencies.db_infra,
            session_id=conversation_id,
            up_to_message_id=up_to_message_id,
            message_ids=message_ids,
            redis=dependencies.redis,
        )
