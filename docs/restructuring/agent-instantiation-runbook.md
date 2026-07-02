# Agent Instantiation Runbook — running a materialized agent on the channel

Status: v1 (2026-06-22), owned by the aw CLI lane (aw-coordinator). Pairs with
`agent-home-composition-contract.md` and `aw-command-surface.md`. **Proven
end-to-end** instantiating `ada` (the shipped `developer` profile) on the cli
team: materialized → started → reachable over `aw mail`, replying as its
profile.

## What this gives you

A **running, channel-connected agent** built from a shipped blueprint profile.
It reads its profile (`AGENTS.md`), connects to the aweb channel, and is
reachable over `aw mail`: it wakes on mail, acts as its profile, and replies.
This is how a coordinator spins up a teammate (developer, reviewer, …) from a
shipped profile.

## Prerequisites

- You are a member of a team and run `aw` from your own workspace.
- An `aw` binary with blueprint support (`aw team add … --runtime`).
- `claude` (Claude Code) on `PATH`. Setup can install the `aweb-channel`
  plugin from the `awebai-marketplace` marketplace (it loads as a *plugin*, see step 2).
- `tmux` — each agent runs `claude` interactively in its own window.

## The sequence (proven, exact)

### 1. Materialize the home from the shipped profile
```
aw team add NAME@aweb.development/<profile>=claude-code --home <HOME>
```
Produces a working home at `<HOME>`: `AGENTS.md` (profile body + the AWEB
coordination block), `CLAUDE.md -> AGENTS.md` symlink, `.aw/` (identity +
team-cert + the evolvable `.aw/profile/`), `.claude/settings.json` (the
`aw notify` hook), `skills/`. Runtime is the explicit `--runtime` (default
`claude-code`); it is never inferred from the profile (see the composition
contract).

### 2. Ensure the Claude Code channel plugin
```
claude plugin marketplace add awebai/claude-plugins
claude plugin install aweb-channel@awebai-marketplace
```
These commands are non-interactive and idempotent. The live agents have **no
channel `.mcp.json`**; the channel is loaded as a Claude Code **plugin**.

### 3. Start `claude` in a tmux window with the channel plugin
```
tmux new-window -a -t <session> -n NAME
tmux send-keys -t <session>:NAME \
  "cd <HOME> && claude --dangerously-skip-permissions --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace" Enter
```
- `--dangerously-skip-permissions` — the agent runs unattended.
- `--dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace`
  — loads the aweb channel as a development channel (it is not yet on Claude
  Code's approved allowlist; see "Deterministic path").

Plugin load takes ~15-25s.

### 4. Confirm the development-channel prompt
On first start `claude` shows:
```
WARNING: Loading development channels
  ❯ 1. I am using this for local development
    2. Exit
  Enter to confirm · Esc to cancel
```
Option 1 is pre-highlighted, so the key is **Enter** (not `y`). Driving it from
a script/agent, do it deterministically by **reading before sending**:
```
tmux capture-pane -t <session>:NAME -p        # confirm the prompt is showing
tmux send-keys   -t <session>:NAME Enter      # confirm option 1
tmux capture-pane -t <session>:NAME -p        # verify it advanced
```
On success the pane shows
`Channels (experimental) messages from plugin:aweb-channel@awebai-marketplace
inject directly in this session` and `⏵⏵ bypass permissions on`. The agent is
now live on the channel.

### 5. Coordinate over `aw mail` — do NOT drive the TUI further
Once it is live, leave the tmux window alone and talk to it over mail:
```
aw mail send --to NAME --subject "…" --body "…"
```
The channel injects the mail into the agent's session; it wakes, acts as its
profile, and replies (`aw mail reply <id> --body …`), which lands in your inbox.
Verified: `ada` injected the mail, woke, and replied quoting the developer
profile's mission.

## Dead ends — do not use these (and why)

- **Background launchers** — launching `claude` as a bare background process
  provides no TTY and no prompt, so claude falls into `--print` mode and dies
  with `Error: Input must be provided either through stdin or as a prompt
  argument when using --print`. It cannot run an interactive agent.
- **`aw run claude`** — the native wake-loop runner; it *does* run the agent,
  but it is explicitly out of scope for this flow (Juan's call). Use plain
  `claude` with the flags above.
- **Per-home `.mcp.json` channel servers** — wrong mechanism. The channel is a
  plugin, not an MCP server.

## Deterministic path (the goal; not yet available)

The dev-channel confirmation in step 4 **cannot be suppressed by any claude
argument or env var** — verified against `claude --help`, the plugin/marketplace
subcommands, `~/.claude.json` trust state, the official Claude Code channels
docs, and the claude binary itself. It is a deliberate research-preview gate.

The warning text points at the real fix: *"use `--channels` to run a list of
approved channels."* An **approved** channel loads with `--channels
plugin:aweb-channel@awebai-marketplace` and **no prompt**. So full determinism
(no tmux keystroke) arrives when `aweb-channel` is on Claude Code's channel
allowlist — Anthropic's list, not ours, during the research preview. Until then,
the Enter-keystroke pattern in step 4 is the way, or file `/feedback` for a
`--dangerously-load-development-channels --yes` / `CLAUDE_*` env.

## Lifecycle

- The agent is the `claude` process in its tmux window. Stop it by closing the
  window (or `/quit` in the pane). The process is supervised by the tmux
  session, not by the CLI.
- The home persists; restarting is step 3-4 again (the channel confirmation
  recurs each start until allowlisted).

## Open issues

- **Non-deterministic start** — the dev-channel confirmation (above) until
  allowlisting.

## For the AR (agent resources) profile

Staffing the team is the **AR (agent resources)** profile's job, not the
coordinator's. The coordinator decides what work and who is needed; AR
provisions, onboards, and runs the agents. So this runbook is the source for
the **AR profile's core instantiation skill**: the exact commands (steps 1-5),
the Enter-keystroke handling with read-before-send, the dead-ends so it does not
waste time on background launchers/`aw run`/per-home channel `.mcp.json`, and mail-based onboarding
after start. The coordinator profile only needs to know that it *requests*
staffing from AR.
