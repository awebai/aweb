"""Compatibility observations count attempts at the real serving tool entry."""

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from aweb.mcp.compatibility import (
    COMPATIBILITY_TOOL_REPLACEMENTS,
    MCP_COMPATIBILITY_TOOL_CALLS,
    observe_compatibility_tool_call,
)
from aweb.mcp.server import _NudgingFastMCP, register_tools


def _counts():
    return {
        sample.labels["tool"]: sample.value
        for metric in MCP_COMPATIBILITY_TOOL_CALLS.collect()
        for sample in metric.samples
        if sample.name == "aweb_mcp_compatibility_tool_calls_total"
    }


@pytest.mark.asyncio
async def test_serving_entry_counts_compatibility_attempt_before_argument_refusal():
    mcp = _NudgingFastMCP("compatibility-test", db_infra=None)
    register_tools(mcp, None, None, None)
    before = _counts().get("contacts_add", 0)
    with pytest.raises(ToolError):
        await mcp.call_tool("contacts_add", {})
    assert _counts()["contacts_add"] == before + 1


def test_observer_labels_are_bounded_and_do_not_capture_arguments_or_unknown_names(
    caplog,
):
    caplog.set_level("INFO", logger="aweb.mcp.compatibility")
    before = _counts()
    observe_compatibility_tool_call(tool_name="unknown-tool-with-private-input")
    observe_compatibility_tool_call(tool_name="send_mail")
    assert _counts() == before
    assert caplog.records == []
    observe_compatibility_tool_call(tool_name="chat_pending")
    assert _counts()["chat_pending"] == before.get("chat_pending", 0) + 1
    assert set(_counts()) <= set(COMPATIBILITY_TOOL_REPLACEMENTS)

    assert [record.getMessage() for record in caplog.records] == [
        "mcp_compatibility_tool_call tool=chat_pending"
    ]
