---
type: Lesson
title: Never kill by pattern on a shared host
description: Agents on one host run as the same Unix user, so pkill -f or killall can stop other agents' work; on macOS pkill stops reading options at the first pattern, so a trailing option becomes a second pattern. Stop only your own jobs, through the harness or a verified PID.
tags: [lesson, environment, macos, processes, safety]
timestamp: 2026-10-23
---

Recorded from two incidents on 2026-10-23 and the team rule the OSS coordinator
set the same day: no `pkill` or `killall` with any pattern.

- A reviewer ran `pkill -f <script name>` to stop its own end-to-end run and
  killed another agent's concurrent run of the same script; the coordinator's
  train gate also died with exit 143 from a pattern kill. An exit trap would
  have removed the victim's evidence.
- Hours later a `pkill -f "<pattern>" -n` stopped every agent session, Docker
  and the desktop agent host at once. macOS `pkill` stops reading options at the
  first pattern, so `-n` became a second pattern and matched every process of
  that user whose command line contained "-n". Option order is not a guard.

# How to apply

- Stop long runs through the harness that started them, or with `kill <pid>`
  on a PID you started and verified.
- Make your own resources identifiable without patterns: name compose projects
  with your own prefix where the scripts allow it, and select containers by
  their compose working-directory label.
- Every agent on the host is the same Unix user, so "my processes" is not a
  category the operating system can enforce; the PID you recorded is.

Related: [tmux isolation for agent runtimes](/aweb-protocol-expert/lessons/tmux-isolation-for-agent-runtimes.md)
records the same class of failure for server-wide tmux teardown.

# Provenance

Harvested 2026-10-25 from seat `aweb-expert-security-review-2` (note
`never-pattern-kill-shared-host.md`; coordinator rule bed27b55), corroborated by
the same rule relayed in `aweb-protocol-expert-awid-service-bypass`
(3757a183), `aweb-protocol-expert-chat-session-fix` (1658d0dc),
`aweb-protocol-expert-secrets-design` and `aweb-protocol-expert-app-team-api`.
The option-parsing analysis was made by another team's agent and relayed, not
re-run by these seats.
