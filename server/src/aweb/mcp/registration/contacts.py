"""Native contacts tool registration."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from aweb.mcp.tools.contacts import add_contact_by_handle as _add_contact_by_handle_impl
from aweb.mcp.tools.contacts import contacts_add as _contacts_add_impl
from aweb.mcp.tools.contacts import contacts_remove as _contacts_remove_impl
from aweb.mcp.tools.contacts import list_contacts_tool as _list_contacts_tool_impl
from aweb.mcp.tools.contacts import (
    read_messages_from_contact as _read_messages_from_contact_impl,
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
