"""Native contacts tool registration."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from aweb.mcp.tools.contacts import add_contact_by_email as _add_contact_by_email_impl
from aweb.mcp.tools.contacts import add_contact_by_handle as _add_contact_by_handle_impl
from aweb.mcp.tools.contacts import contacts_add as _contacts_add_impl
from aweb.mcp.tools.contacts import contacts_list as _contacts_list_impl
from aweb.mcp.tools.contacts import contacts_remove as _contacts_remove_impl
from aweb.mcp.tools.contacts import list_contacts_tool as _list_contacts_tool_impl
from aweb.mcp.tools.contacts import (
    read_messages_from_contact as _read_messages_from_contact_impl,
)
from aweb.mcp.tools.contacts import (
    send_message_to_contact as _send_message_to_contact_impl,
)

from .dependencies import ToolDependencies


def register_tools(mcp: FastMCP, dependencies: ToolDependencies) -> None:
    """Register the native contacts tools with the serving dependencies."""

    @mcp.tool(
        name="list_contacts",
        description="List saved contacts for the authenticated identity.",
    )
    async def list_contacts() -> str:
        """List saved contacts for the authenticated identity."""
        return await _list_contacts_tool_impl(dependencies.db_infra)

    @mcp.tool(name="add_contact", description="Add a contact by routable address.")
    async def add_contact(address: str, label: str = "") -> str:
        """Add a contact by routable address."""
        return await _contacts_add_impl(
            dependencies.db_infra,
            contact_address=address,
            label=label,
            federation_authority=dependencies.federation_authority,
        )

    @mcp.tool(
        name="add_contact_by_handle",
        description="Add a pending contact by @handle or @handle/agent.",
    )
    async def add_contact_by_handle(handle: str, label: str = "") -> str:
        """Add a pending contact by @handle or @handle/agent."""
        return await _add_contact_by_handle_impl(
            dependencies.db_infra, handle=handle, label=label
        )

    @mcp.tool(name="remove_contact", description="Remove a saved contact.")
    async def remove_contact(contact_id: str) -> str:
        """Remove a saved contact."""
        return await _contacts_remove_impl(dependencies.db_infra, contact_id=contact_id)

    @mcp.tool(
        name="read_contact_messages",
        description="Read hosted mail or chat messages exchanged with a saved contact. Encrypted E2E mail content is returned as metadata only; read it in a local aw client.",
    )
    async def read_contact_messages(
        contact_id: str, channel: str = "mail", limit: int = 50
    ) -> str:
        """Read hosted mail or chat messages exchanged with a saved contact. Encrypted E2E mail content is returned as metadata only; read it in a local aw client."""
        return await _read_messages_from_contact_impl(
            dependencies.db_infra,
            registry_client=dependencies.registry_client,
            contact_id=contact_id,
            channel=channel,
            limit=limit,
        )

    @mcp.tool(
        name="contacts_list",
        description="Compatibility alias for list_contacts. Prefer list_contacts. Retained for cached MCP clients; removal is considered in the release after deployed native and hosted measurement shows zero calls for 30 consecutive days.",
    )
    async def contacts_list() -> str:
        "Compatibility alias for list_contacts. Prefer list_contacts. Retained for cached MCP clients; removal is considered in the release after deployed native and hosted measurement shows zero calls for 30 consecutive days."
        return await _contacts_list_impl(dependencies.db_infra)

    @mcp.tool(
        name="contacts_add",
        description="Compatibility alias for add_contact. Prefer add_contact. Retained for cached MCP clients; removal is considered in the release after deployed native and hosted measurement shows zero calls for 30 consecutive days.",
    )
    async def contacts_add(contact_address: str, label: str = "") -> str:
        "Compatibility alias for add_contact. Prefer add_contact. Retained for cached MCP clients; removal is considered in the release after deployed native and hosted measurement shows zero calls for 30 consecutive days."
        return await _contacts_add_impl(
            dependencies.db_infra,
            contact_address=contact_address,
            label=label,
            federation_authority=dependencies.federation_authority,
        )

    @mcp.tool(
        name="contacts_remove",
        description="Compatibility alias for remove_contact. Prefer remove_contact. Retained for cached MCP clients; removal is considered in the release after deployed native and hosted measurement shows zero calls for 30 consecutive days.",
    )
    async def contacts_remove(contact_id: str) -> str:
        "Compatibility alias for remove_contact. Prefer remove_contact. Retained for cached MCP clients; removal is considered in the release after deployed native and hosted measurement shows zero calls for 30 consecutive days."
        return await _contacts_remove_impl(dependencies.db_infra, contact_id=contact_id)

    @mcp.tool(
        name="add_contact_by_email",
        description="Compatibility alias for email contact requests. Retained for cached MCP clients; removal is considered in the release after deployed native and hosted measurement shows zero calls for 30 consecutive days.",
    )
    async def add_contact_by_email(email: str, label: str = "") -> str:
        "Compatibility alias for email contact requests. Retained for cached MCP clients; removal is considered in the release after deployed native and hosted measurement shows zero calls for 30 consecutive days."
        return await _add_contact_by_email_impl(
            dependencies.db_infra, email=email, label=label
        )

    @mcp.tool(
        name="send_message_to_contact",
        description="Compatibility alias for hosted server-readable mail or chat to a saved contact. This hosted MCP tool is not E2E; use local aw clients for E2E messaging. Retained for cached MCP clients; removal is considered in the release after deployed native and hosted measurement shows zero calls for 30 consecutive days.",
    )
    async def send_message_to_contact(
        contact_id: str,
        message: str,
        subject: str = "",
        channel: str = "mail",
        priority: str = "normal",
        wait: bool = False,
        wait_seconds: int = 120,
    ) -> str:
        "Compatibility alias for hosted server-readable mail or chat to a saved contact. This hosted MCP tool is not E2E; use local aw clients for E2E messaging. Retained for cached MCP clients; removal is considered in the release after deployed native and hosted measurement shows zero calls for 30 consecutive days."
        return await _send_message_to_contact_impl(
            dependencies.db_infra,
            redis=dependencies.redis,
            registry_client=dependencies.registry_client,
            federation_authority=dependencies.federation_authority,
            hosted_signer=dependencies.hosted_signer,
            hosted_encryptor=dependencies.hosted_encryptor,
            contact_id=contact_id,
            message=message,
            subject=subject,
            channel=channel,
            priority=priority,
            wait=wait,
            wait_seconds=wait_seconds,
            federation_mail_transport=dependencies.federation_mail_transport,
            federation_chat_transport=dependencies.federation_chat_transport,
            public_origin=dependencies.public_origin,
        )

    @mcp.tool(
        name="read_messages_from_contact",
        description="Compatibility alias for read_contact_messages. Prefer read_contact_messages. Hosted MCP cannot decrypt E2E contents. Retained for cached MCP clients; removal is considered in the release after deployed native and hosted measurement shows zero calls for 30 consecutive days.",
    )
    async def read_messages_from_contact(
        contact_id: str, channel: str = "mail", limit: int = 50
    ) -> str:
        "Compatibility alias for read_contact_messages. Prefer read_contact_messages. Hosted MCP cannot decrypt E2E contents. Retained for cached MCP clients; removal is considered in the release after deployed native and hosted measurement shows zero calls for 30 consecutive days."
        return await _read_messages_from_contact_impl(
            dependencies.db_infra,
            registry_client=dependencies.registry_client,
            contact_id=contact_id,
            channel=channel,
            limit=limit,
        )
