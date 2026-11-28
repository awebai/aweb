---
type: Lesson
title: A rename to the canonical name can shadow an imported name
description: When a compatibility name is removed and the implementation takes the public name, check the module's imported names as well as its defs; a def named like an imported service rebinds it and the tool silently calls itself. Resolve it by importing the service under a name that says what it is.
tags: [lesson, removal, rename, python, lint]
timestamp: 2026-11-28
---

Removing a compatibility name usually leaves the shared implementation named
after the removed alias. Renaming it to the public name is the natural last
step of the removal. In aweb that step is likely to collide: the MCP tools sit
over messaging services that use the same domain verbs, and a tool module
imports the service it wraps under exactly the name the tool is about to
take.

In Python the new `def` rebinds the imported name. Nothing fails at import or
collection time. The tool calls itself, and the failure is runtime recursion
on whichever paths a test happens to drive. A collision check that looks only
at other defs, or only at the registered tool names, misses it.

In the E1.4 removal (November 2026), renaming nine MCP tool implementations
to their tool names collided with five imported services: `add_contact`,
`list_contacts` and `remove_contact` from `messaging.contacts`, `send_chat`
from `messaging.chat_send`, and `mark_chat_read` from `messaging.chat_read`.
`ruff` F811 flagged it before anything ran.

# How to apply

- Before the rename, list every name the module imports as well as the ones
  it defines: run `ruff check --select F811` on the touched files, or grep
  their import lines for each target name.
- Resolve a collision by importing the service under a name that says what it
  is (`add_contact_record`, `send_chat_message`, `mark_chat_messages_read`),
  and update its call sites.
- Rejected: giving the tool a second-best public name, or keeping the old
  implementation names behind the canonical registrations. Both leave two
  names for one thing, which is what the removal set out to end.

The mechanism is not Python-specific: any language where a local definition
can shadow an imported binding without an error has the same trap.

# Elimination route

This should be a gate check rather than a lesson. Both `ruff check` (F811,
in the `F` set `server/pyproject.toml` already selects) and `mypy`
(`no-redef`, "Name already defined (possibly by an import)") report the
collision. At main 27aad41a0 neither runs over `server/src/aweb`: server CI
and `make test-server` run the build and pytest only, and the pre-commit hook
runs `ruff format`, not `ruff check`. Until a static check for redefinitions
is in the server gate, run it yourself on any rename.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-e1-removals, 2026-11-28;
notes/rename-to-canonical-name-can-shadow-an-import.md. Checked by the
harvester: commit 7eef639b8 on the E1.4 MCP removal branch (not on main at
27aad41a0) records the five collisions and the aliased imports; aweb main
`server/src/aweb/mcp/tools/chat.py` imports `mark_chat_read` from
`aweb.messaging.chat_read`; on a minimal module, `ruff check --select F811`
and `mypy` both flag a `def` that redefines an imported name. The passing
MCP and full server runs are source-reported.
