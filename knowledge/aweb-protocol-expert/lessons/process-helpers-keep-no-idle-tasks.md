---
type: Lesson
title: Process helpers keep no idle tasks
description: A process-level helper in shared library code runs its background task only while it has work; an idle forever-waiting task outlives host runtimes that close later than their event loop's task checks, and only the host's leak check catches it.
tags: [lesson, asyncio, background-tasks, cloud, mounting, testing]
timestamp: 2026-11-04
---

Found on 2026-11-04 in the agent wake publisher's retry task. The task
originally waited forever for work. Cloud's channel worker closes its host
runtime later than its event loop's pending-task checks run, so the idle task
outlived the runtime. OSS tests passed; Cloud's test leak check, which drains
pending tasks, caught it.

# How to apply

- A background task owned by shared library code starts when work arrives and
  exits when the work is done. It does not park waiting for the next item.
- Prove it under the host that embeds the library: the leak check that catches
  this lives in the host's tests, not in the library's.

Related:
[a mounted app gets no lifespan](/aweb-protocol-expert/lessons/a-mounted-app-gets-no-lifespan.md),
[the agent event stream is push-driven](/aweb-protocol-expert/decisions/agent-event-stream-is-push-driven.md).

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-stream-push, 2026-11-04; notes/stream-reconcile-redis-counters.md.
