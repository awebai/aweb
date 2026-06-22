---
name: aweb-agent-instantiation
description: This skill should be used when staffing a team — instantiating, starting, onboarding, or retiring an agent built from a shipped blueprint profile. Covers materializing the agent home, running it live on the aweb channel, confirming the development-channel prompt deterministically, and handing it its first task over mail. The mechanics that turn a profile into a working teammate.
allowed-tools: "Bash(aw *), Bash(tmux *), Bash(claude *), Bash(rm *), Bash(mkdir *)"
---

# aweb Agent Instantiation

Use this skill to turn a shipped blueprint profile into a **live teammate**:
materialize its home, run it on the aweb channel, and hand it work over mail.
This is the **mechanics** layer. The role using this skill supplies the staffing
*judgment* — when to staff, who, and how to onboard. The **coordinator** uses it
for local, no-AWID agents; the **AR (agent resources)** role uses it for the same
local mechanics and additionally owns global, identity-bearing staffing through
`manage-team-identities`. This skill is the *how*.

For team coordination (tasks, work discovery, locks) load `aweb-coordination`;
for mail/chat policy load `aweb-messaging`. This skill assumes those and covers
only the instantiate-and-run mechanics they don't.

## What you produce

A running agent built from a profile: it reads its profile (`AGENTS.md`),
connects to the aweb channel, and is reachable over `aw mail` — it wakes on
mail, acts as its profile, and replies.

## Preconditions — check, don't assume

- You can run a **persistent TTY session** per agent (tmux is shown below; any
  persistent terminal works). The agent runs `claude` interactively and **dies
  without a TTY** — that is why the supervised path does not work.
- A recent `aw` on `PATH` with blueprint support (`aw team add … --runtime`);
  the agent itself uses the system `aw` for mail.
- `claude` (Claude Code) on `PATH`, and the **aweb-channel plugin** available
  from its marketplace (`claude plugin list` shows `aweb-channel`).
- You are a member of the team you are staffing into.

## The sequence

Set the variables once. `CHANNEL` is the single line that changes when the
channel is allowlisted (see "Deterministic path"):

```bash
NAME=...                       # the new agent's alias
PROFILE=...                    # e.g. aweb.engineering/developer
HOME_DIR=...                   # where this agent's home lives
CHANNEL="--dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace"
```

### 1. Materialize the home from the profile

```bash
aw team add "$NAME@$PROFILE" --runtime claude-code --home "$HOME_DIR"
```

Produces a working home: `AGENTS.md` (profile body + the injected aweb
coordination block), `CLAUDE.md` symlink, `.aw/` (identity + team-cert + the
evolvable profile), the wake hook. Runtime is the explicit `--runtime` (never
inferred from the profile).

**Scope — local agents only.** `aw team add` defaults to `--local` (a
team-scoped agent identity), which is exactly what staffing a team needs and is
the boundary of this skill. Do **not** pass `--global`. Global,
AWID-identity-backed agents (`aw team add --global`, or `aw id team add-member
--global`) are a separate identity-level operation owned by the **AR** role via
the `manage-team-identities` skill — not this one. Staffing creates local
team members; minting global identities is a distinct, gated responsibility.

### 2. Remove the materialized `.mcp.json` — workaround

```bash
rm -f "$HOME_DIR/.mcp.json"
```

The channel is a Claude Code **plugin** (step 3), not the npx MCP server
`aw team add` writes. *(Workaround for an open `SetupChannelMCP` bug — it writes
a non-working npx MCP server into the home; remove it. The step disappears when
that bug is fixed.)*

### 3. Start the agent in a persistent TTY session

```bash
tmux new-window -n "$NAME"
tmux send-keys -t "$NAME" "cd $HOME_DIR && claude --dangerously-skip-permissions $CHANNEL" Enter
```

Plugin load takes ~15-25s.

### 4. Confirm the development-channel prompt — read before you send

```bash
tmux capture-pane -t "$NAME" -p     # 1. confirm the prompt is showing
tmux send-keys   -t "$NAME" Enter   # 2. option 1 ("local development") is pre-highlighted -> Enter
tmux capture-pane -t "$NAME" -p     # 3. verify it advanced
```

Success shows `messages from plugin:aweb-channel@… inject directly in this
session` and `bypass permissions on`. **Never fire the key blind** — capture,
verify the prompt text, send, capture again. The prompt is a numbered selector
(`1. I am using this for local development` / `2. Exit`) with option 1
pre-highlighted, so the key is **Enter**, not `y`. (When the channel is
allowlisted this whole step is gone — see below.)

### 5. Onboard over mail — then leave the TTY alone

```bash
aw mail send --to "$NAME" --subject "onboarding" --body "<role + project context + first scoped task>"
```

The channel injects the mail; the agent wakes, acts as its profile, and replies.
From here coordinate only over mail/chat (`aweb-messaging`) — never by driving
the TUI.

## Guardrails — do NOT use these (each is a known dead-end)

- **`aw agent start`** — launches `claude` with no TTY and no prompt; it falls
  into `--print` mode and dies with `Input must be provided … --print`. It
  cannot run an interactive agent.
- **`aw run`** — runs the agent, but is out of scope for this flow.
- **The materialized `.mcp.json`** — the wrong channel mechanism; remove it
  (step 2). The live agents have no `.mcp.json`.

## Deterministic path — no prompt

The development-channel confirmation in step 4 has **no suppressing flag or env**
— it is a deliberate research-preview gate (verified against `claude --help`,
the plugin/marketplace subcommands, the trust config, and the claude binary).
When `aweb-channel` is on Claude Code's channel allowlist, change the single
`CHANNEL` line to:

```bash
CHANNEL="--channels plugin:aweb-channel@awebai-marketplace"
```

An approved channel loads with **no prompt** and step 4 disappears entirely.
That is the only line that changes.

## Lifecycle

- The agent is the `claude` process in its TTY session. Stop/retire it by
  `/quit` in the pane or closing the window. There is no `aw agent stop` for
  this path (it supervised a bare process, which does not work — see guardrails).
- The home persists; restarting is steps 3-4 again (the confirmation recurs each
  start until allowlisted).

## References

- `docs/restructuring/agent-instantiation-runbook.md` (aweb repo) — the source
  runbook with the full evidence trail and open issues.
- The **AR (agent resources)** blueprint profile — the role that orchestrates
  this skill: when to staff, onboarding content, roster tracking, retire.
