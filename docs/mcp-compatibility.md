---
title: "MCP compatibility names"
description: "Published tool names, their replacements and the measured removal condition."
---

# MCP compatibility names

The eleven names below were advertised by the released `server-v1.27.50`
registration. MCP clients may retain a previously discovered tool list.
The native channel, channel-core and Pi implementations have no calls to these
names; `aw` uses REST for these operations. Cloud hides the names from fresh
discovery while still accepting cached-name calls. There is no historical
per-tool production usage evidence identifying a specific external client or
version. Source searches therefore cannot establish that a name is unused.
All eleven remain callable in this release, under the coordinator's disposition
`2754b8cd-9a85-46e9-88d4-ddfcf5577d17`.

| Retained name | Replacement or current operation |
|---|---|
| `check_inbox` | `check_mail` |
| `chat_send` | `send_chat` |
| `chat_pending` | `check_chats` |
| `chat_history` | `read_chat` |
| `chat_read` | `mark_chat_read` |
| `contacts_list` | `list_contacts` |
| `contacts_add` | `add_contact` |
| `contacts_remove` | `remove_contact` |
| `add_contact_by_email` | No available email-contact operation; this name already returns the server's unsupported-operation response. |
| `send_message_to_contact` | Resolve the saved contact, then use `send_mail` or `send_chat` with its address. |
| `read_messages_from_contact` | `read_contact_messages` |

For each row, removal can be considered in the release **after** deployed
native and hosted measurement shows **zero calls for 30 consecutive days**.
The observation must cover every serving entry for that window, including
refused attempts. An absent collector, an uninstrumented host or a failed
measurement does not establish zero calls. Removal remains a separate reviewed
change; deployment of this observer removes no tool.

`aweb.mcp.compatibility.observe_compatibility_tool_call(*, tool_name: str) -> None`
is the sole observer. The native `call_tool` entry invokes it before framework
validation. Hosts overriding that entry invoke it once before their own sender,
quota, tool or delegation checks. Native registration and alias bodies add no
second observation. Cloud's wrapper delegates directly to the framework, so its
entry and the native wrapper do not nest.

The bounded-label counter is
`aweb_mcp_compatibility_tool_calls_total{tool="<one of the eleven names>"}`
in the default Prometheus registry. Hosts choose how to expose that registry,
as for native request-auth metrics. Other tool names create no labels. The
observer records no tool arguments, content, identity or client metadata;
measurement failure logs a fixed message and permits the invocation.

The observer also emits one INFO log event, `mcp_compatibility_tool_call tool=NAME`,
where `NAME` is one of the eleven fixed names above. It contains no arguments,
identity or client metadata. Operators can count those events in their existing
native and hosted process log sinks. The Prometheus counter is available to an
operator-configured exporter; this library does not install a scrape endpoint.
Choose one observation source per serving entry to avoid counting the log and
counter twice. Establish collection, INFO-level retention and complete serving
coverage before starting the thirty-day window. Missing exports, filtered logs,
shorter retention or an unobserved entry cannot establish zero use.
