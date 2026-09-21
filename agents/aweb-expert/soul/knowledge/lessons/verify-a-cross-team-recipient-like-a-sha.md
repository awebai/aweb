---
type: Lesson
title: Verify a cross-team recipient like a SHA
description: Before sending across teams, resolve the destination team's domain and actual roster alias and address the recipient as team-domain/alias; never infer an alias from a role or a similarly named agent, and never read a successful send as proof it reached the intended owner.
tags: [lesson, messaging, coordination]
timestamp: 2026-09-21
---

Recorded by the OSS developer role (undated), verified as current practice on
2026-09-21: similarly named agents in different teams are distinct recipients,
and a delivered send only proves delivery to the address supplied.

# How to apply

- Run the workspace status, identify the destination team's domain and the
  roster alias, and address as `<team-domain>/<alias>`.
- Treat the address like a reviewed SHA: verify it before sending, re-verify
  before believing a reply will come.
- A successful send does not establish that the inferred recipient was the
  intended owner; an alias in a task or handoff is not evidence anyone is behind
  it.
