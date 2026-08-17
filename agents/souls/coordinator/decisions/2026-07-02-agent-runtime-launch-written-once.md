# Agent-runtime launch/teardown is written once (2026-07-02)

Juan: "make sure that the architecture is correct. it is very easy to
implement what we are scoping repeating code that should be written once."

The aaeq epic adds three surfaces that all launch or tear down an agent
runtime in a tmux window:

- `aw team up` — launch the whole roster.
- `aw team add --start` (aaeq.14) — launch one agent (globals too, not
  just locals).
- `aw team remove` (aaeq.15) — tear one down.

## Decision

One shared per-agent lifecycle, called by all three — never copied:

- **`launchAgentWindow(session, agent)`** — ensure the tmux session exists,
  create the window, run the runtime command (claude plugin channel / pi).
  The single per-agent launch unit.
- **`confirmClaudeChannelPrompt(session, agent)`** — answer the dev-channel
  prompt (poll capture-pane → send Enter only once the prompt is visible →
  verify it advanced). Already per-agent; kept.
- **`ensureChannelPlugin`** (channel_setup.go) — install/verify the plugin.
  Already shared with materialize/init; reused, not re-implemented.
- **cwd running-check** (`teamUpDetectActiveHomes`) — reused for the
  single-agent case.
- **Teardown** — `aw team remove` **wraps** the existing primitives
  (`workspace delete` for local home+id, `remove-agent` for the cert); it
  does not re-implement revoke/delete.

Call patterns differ, logic does not:

- `aw team up` = loop `launchAgentWindow` over the roster, **then** a second
  loop of `confirmClaudeChannelPrompt`. The two-phase shape is deliberate:
  the ~15–25s plugin loads overlap instead of serializing.
- `aw team add --start` = `launchAgentWindow(one)` + `confirmClaudeChannelPrompt(one)`.

## Why

The first cut (aaeq.12) had the per-agent launch **inline** in
`executeTeamUpPlan`'s loop, so aaeq.14 would have duplicated the
launch+prompt logic. Extracting the primitive **before** the follow-ups
build on it costs one small refactor now and prevents two divergent copies
of the trickiest code we have (the non-blind tmux prompt handshake).

Directed the extraction as part of aaeq.12 (before it hardens), re-review
by aw-reviewer, then merge the re-ACKed SHA. The channel launch mechanics
this rests on are in memory `aweb-channel-claude-launch-mechanism`; the tested
ground truth is now `cli/go/cmd/aw/team_up.go` and `team_human.go` with their
tests, and the `spawn-instance` skill.
