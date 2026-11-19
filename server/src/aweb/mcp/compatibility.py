"""Measure published MCP names before deciding whether they can be removed.

Observe at the serving call_tool entry, before validation, quota or delegation.
The default Prometheus registry can be collected by a configured host exporter.
A bounded log event also reaches the serving process's configured log sink.
Neither observation includes tool arguments, identities or client metadata.
"""

import logging
from types import MappingProxyType

from prometheus_client import Counter

logger = logging.getLogger(__name__)

COMPATIBILITY_TOOL_REPLACEMENTS = MappingProxyType(
    {
        "check_inbox": "check_mail",
        "chat_send": "send_chat",
        "chat_pending": "check_chats",
        "chat_history": "read_chat",
        "chat_read": "mark_chat_read",
        "contacts_list": "list_contacts",
        "contacts_add": "add_contact",
        "contacts_remove": "remove_contact",
        "add_contact_by_email": None,
        "send_message_to_contact": "send_mail or send_chat with the resolved contact address",
        "read_messages_from_contact": "read_contact_messages",
    }
)

MCP_COMPATIBILITY_TOOL_CALLS = Counter(
    "aweb_mcp_compatibility_tool_calls_total",
    "Attempts to call a published MCP compatibility name, including refused calls.",
    ("tool",),
)


def observe_compatibility_tool_call(*, tool_name: str) -> None:
    """Observe one fixed compatibility name without changing its result."""
    if tool_name not in COMPATIBILITY_TOOL_REPLACEMENTS:
        return
    logger.info("mcp_compatibility_tool_call tool=%s", tool_name)
    try:
        MCP_COMPATIBILITY_TOOL_CALLS.labels(tool=tool_name).inc()
    except Exception:
        logger.exception("MCP compatibility usage measurement failed")
