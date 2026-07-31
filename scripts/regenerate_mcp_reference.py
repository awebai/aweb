#!/usr/bin/env python3
"""Generate the public MCP tool reference from the live OSS registration."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SERVER_SRC = ROOT / "server" / "src"
AWID_SRC = ROOT / "awid" / "src"
for source_root in (SERVER_SRC, AWID_SRC):
    if str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))

from mcp.server.fastmcp import FastMCP  # noqa: E402

from aweb.mcp.server import register_tools  # noqa: E402

OUTPUT = ROOT / "docs" / "mcp-tools-reference.md"

CANONICAL_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Identity", ("whoami",)),
    ("Mail", ("send_mail", "check_mail")),
    ("Presence", ("list_agents", "heartbeat")),
    ("Chat", ("send_chat", "check_chats", "read_chat", "mark_chat_read")),
    (
        "Tasks",
        (
            "task_create",
            "task_list",
            "task_ready",
            "task_get",
            "task_close",
            "task_update",
            "task_reopen",
            "task_claim",
            "task_comment_add",
            "task_comment_list",
        ),
    ),
    ("Instructions", ("instructions_show", "instructions_history")),
    ("Roles", ("roles_show", "roles_list")),
    ("Work Discovery", ("work_ready", "work_active", "work_blocked")),
    ("Workspace Coordination", ("workspace_status",)),
    (
        "Contacts",
        (
            "list_contacts",
            "add_contact",
            "add_contact_by_handle",
            "remove_contact",
            "read_contact_messages",
        ),
    ),
)

LEGACY_TOOLS: tuple[str, ...] = (
    "check_inbox",
    "chat_send",
    "chat_pending",
    "chat_history",
    "chat_read",
    "contacts_list",
    "contacts_add",
    "contacts_remove",
    "add_contact_by_email",
    "send_message_to_contact",
    "read_messages_from_contact",
)


class CoverageError(RuntimeError):
    """The explicit public grouping does not cover the live registration exactly."""


def classified_names() -> tuple[str, ...]:
    canonical = tuple(name for _, names in CANONICAL_GROUPS for name in names)
    return canonical + LEGACY_TOOLS


async def load_registered_tools() -> dict[str, Any]:
    """Build the real FastMCP registry without executing a tool or touching I/O."""
    mcp = FastMCP("aweb-reference-introspection")
    register_tools(mcp, None, None, None)
    tools = await mcp.list_tools()
    return {tool.name: tool for tool in tools}


def validate_coverage(tools: Mapping[str, Any]) -> None:
    registered = set(tools)
    classified = set(classified_names())

    unclassified = sorted(registered - classified)
    absent = sorted(classified - registered)
    if unclassified:
        raise CoverageError(f"unclassified registered tool: {unclassified[0]}")
    if absent:
        raise CoverageError(f"documented tool absent from registration: {absent[0]}")
    if len(classified_names()) != len(classified):
        raise CoverageError("tool appears in more than one reference category")

    for name in classified_names():
        tool = tools[name]
        if not isinstance(tool.description, str) or not tool.description.strip():
            raise CoverageError(f"registered tool has no description: {name}")
        schema = tool.inputSchema
        if not isinstance(schema, dict) or not isinstance(schema.get("properties"), dict):
            raise CoverageError(f"registered tool has unsupported input schema: {name}")
        output_schema = tool.outputSchema
        result = (output_schema or {}).get("properties", {}).get("result", {})
        if result.get("type") != "string":
            raise CoverageError(f"registered tool does not return a string: {name}")


def format_default(value: Any) -> str:
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if value is True:
        return "True"
    if value is False:
        return "False"
    if value is None:
        return "None"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def render_parameters(tool: Any) -> str:
    properties = tool.inputSchema["properties"]
    if not properties:
        return "none"

    parameters: list[str] = []
    for name, schema in properties.items():
        rendered = name
        if "default" in schema:
            rendered += f"={format_default(schema['default'])}"
        parameters.append(f"`{rendered}`")
    return ", ".join(parameters)


def escape_table_text(value: str) -> str:
    return " ".join(value.split()).replace("|", "\\|")


def render_table(names: Sequence[str], tools: Mapping[str, Any]) -> str:
    lines = [
        "| Tool | Parameters | Registered description |",
        "| --- | --- | --- |",
    ]
    for name in names:
        tool = tools[name]
        lines.append(
            f"| `{name}` | {render_parameters(tool)} | "
            f"{escape_table_text(tool.description)} |"
        )
    return "\n".join(lines)


def render_reference(tools: Mapping[str, Any]) -> str:
    validate_coverage(tools)
    sections = [
        """---
title: "MCP tools reference"
kicker: "Reference"
description: "The OSS MCP tool surface, generated from the live server registration."
weight: 95
---

# MCP Tools Reference

<!-- Generated by scripts/regenerate_mcp_reference.py; do not edit by hand. -->

This reference is generated from the live OSS MCP registration in
[`server/src/aweb/mcp/server.py`](https://github.com/awebai/aweb/blob/main/server/src/aweb/mcp/server.py).
Run `make regenerate-mcp-tools-reference` after changing registration, parameters,
or descriptions. `make test-mcp-tools-reference` checks freshness and proves that
unclassified or removed tools fail closed. For the canonical contract, see the
MCP section of [`aweb-sot.md`](https://aweb.ai/docs/aweb-sot.md).

## Transport and Auth

- FastAPI mounts the MCP app at `/mcp`.
- With the default `streamable_http_path="/"`, clients use `/mcp/`.
- The transport is Streamable HTTP via FastMCP with `stateless_http=True`.
- The canonical auth contract lives in the MCP and Authentication sections of
  [`aweb-sot.md`](https://aweb.ai/docs/aweb-sot.md); this reference does not
  restate request headers or the signature envelope.
- All tools require authenticated identity context.
- Identity, mail, chat, and contact operations can run without team context
  where their operation permits it.
- Team-scoped coordination families require resolved team context.
- Every currently registered tool returns a string. Treat results as
  human-readable output rather than a stable JSON contract.
- If a connected client cached an older tool list, refresh its tools. If
  authorization changed, disconnect and reconnect it."""
    ]

    for heading, names in CANONICAL_GROUPS:
        sections.append(f"## {heading}\n\n{render_table(names, tools)}")

    sections.append(
        """## Legacy Compatibility Aliases

The OSS server still registers these older names so clients with cached tool
lists do not fail with "Unknown tool." New clients should use the canonical
names above. Their parameters and descriptions below also come from the live
registration."""
        + "\n\n"
        + render_table(LEGACY_TOOLS, tools)
    )

    sections.append(
        """## Deployment-Specific Composition

An operator may compose additional deployment-specific tools around the OSS MCP
server. Those tools are outside this OSS registration inventory, and that
operator owns their documentation.

## Mapping to the REST API

- Tools wrap the same coordination primitives exposed by the REST API.
- Tool auth resolves caller context through
  [`server/src/aweb/mcp/auth.py`](https://github.com/awebai/aweb/blob/main/server/src/aweb/mcp/auth.py);
  the canonical contract remains
  [`aweb-sot.md`](https://aweb.ai/docs/aweb-sot.md).
- To add an OSS MCP tool, implement behavior under
  [`server/src/aweb/mcp/tools/`](https://github.com/awebai/aweb/tree/main/server/src/aweb/mcp/tools),
  register it in
  [`server/src/aweb/mcp/server.py`](https://github.com/awebai/aweb/blob/main/server/src/aweb/mcp/server.py),
  classify it in the generator, and regenerate this file."""
    )
    return "\n\n".join(sections) + "\n"


def reference_is_current(output: Path, expected: str) -> bool:
    try:
        return output.read_text(encoding="utf-8") == expected
    except FileNotFoundError:
        return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail without writing when the committed reference is stale",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        expected = render_reference(asyncio.run(load_registered_tools()))
    except CoverageError as exc:
        print(f"MCP reference generation failed: {exc}", file=sys.stderr)
        return 1

    if args.check:
        if reference_is_current(OUTPUT, expected):
            print("MCP tools reference is up to date")
            return 0
        print(
            "MCP tools reference is stale; run 'make regenerate-mcp-tools-reference'",
            file=sys.stderr,
        )
        return 1

    OUTPUT.write_text(expected, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
