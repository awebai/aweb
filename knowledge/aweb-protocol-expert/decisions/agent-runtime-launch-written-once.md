---
type: Decision
title: Agent-runtime launch is written once
description: Launching the whole roster, adding one agent with start, and removing one all call a single per-agent launch primitive and a single prompt-confirmation primitive in the aw CLI; call patterns differ, the logic is never copied.
tags: [decision, aw-cli, team, tmux, design]
timestamp: 2026-07-02
---

Decided by the OSS coordinator role with the operator on 2026-07-02, when three
surfaces were about to launch or tear down an agent runtime in a tmux window
and the first cut had the per-agent launch inline in the roster loop. The
operator's rule: "it is very easy to implement what we are scoping repeating
code that should be written once." Verified on 2026-09-21 that
`cli/go/cmd/aw/team_up.go` carries the shared launch and prompt-confirmation
primitives with their tests.

# Decision

- One per-agent launch unit ensures the tmux session, creates the window and
  runs the runtime command; one per-agent confirmation unit answers the
  runtime's channel prompt only once it is visible and verifies it advanced.
- Roster launch loops the launch unit, then loops the confirmation unit, so the
  runtimes' plugin loads overlap instead of serialising.
- Single add-with-start calls both units for one agent. Teardown wraps the
  existing workspace-delete and certificate-revoke primitives rather than
  re-implementing them.

# Why

The non-blind tmux prompt handshake is the trickiest code on that path; two
divergent copies of it would have been the failure mode. Extracting the
primitive before follow-ups built on it cost one small refactor.
