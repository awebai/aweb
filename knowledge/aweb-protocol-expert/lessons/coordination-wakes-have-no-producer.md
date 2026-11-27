---
type: Lesson
title: Coordination wakes have no producer, and tool use is not measured
description: No aweb server emits the agent events work_available, claim_update or claim_removed, which only clients parse, so removing their handlers is a client-only change; coordination MCP tool use cannot be measured as built, because only the 11 compatibility tool names are counted.
tags: [lesson, coordination, event-stream, mcp, measurement, removal]
timestamp: 2026-11-27
---

When removing coordination from aweb, do not look for producers of the work
and claim wakes. Do not look for counts of coordination MCP tool calls either.
Neither exists.

# No producer for the work and claim wakes

- aw (`cli/go/awid/events.go`) and channel-core (`channel-core/src/channel.ts`)
  parse the agent event types `work_available`, `claim_update` and
  `claim_removed`.
- The OSS server emits none of them. The agent event stream offers only
  `mail`, `chat`, `control`, `app` and `room` (`STREAM_KINDS` in
  `server/src/aweb/routes/events.py`). The harvester found no match in
  `server/src`, and `git log -S work_available -- server/src` finds no
  commit, at aweb main 5c2ee7bad.
- The hosted service emits none either. This is the source's report from a
  hosted-code read. The harvester did not check it.

So removing those handlers changes only the clients. No server change is
involved, and there is no producer traffic to measure first.

# Coordination tool use cannot be measured as built

- The OSS MCP server logs and counts only calls to the 11 published
  compatibility names (`observe_compatibility_tool_call` in
  `server/src/aweb/mcp/compatibility.py`). It does not record other
  `tools/call` names. The source reports the same for the hosted service.
- Request lines in the hosted service's logs carry the raw path, method and
  user-agent, but no team. This is source-reported.

To decide the removal of coordination MCP tools on measured use, the
measurement has to be built first. Otherwise, decide without it and say so.
Do not infer zero use from missing logs.

Related:
[a shared command keeps a zero-use feature's route alive](/aweb-protocol-expert/lessons/a-shared-command-keeps-a-zero-use-route-alive.md)
and
[shared team instructions stay in aweb](/aweb-protocol-expert/decisions/team-instructions-stay-in-aweb.md).

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-oss-classify, 2026-11-27; notes/coordination-wakes-have-no-oss-producer.md.
