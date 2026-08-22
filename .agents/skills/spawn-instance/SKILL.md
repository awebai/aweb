---
name: spawn-instance
description: Add a teammate — one command (`aw team admin add … --start`) materializes an instance's home from a blueprint profile, sets up its isolated git worktree, and launches it. Use when a human asks for a teammate or assigned work needs one.
---

# Spawn an instance (a teammate)

An **instance** is a runnable teammate with its own aweb identity, a home, and —
for code roles — an isolated git worktree. Since aw 1.31, **`aw team admin add … --start`
does the whole thing in one command**: it materializes the home from a blueprint
profile, sets up the worktree isolation, and launches the runtime — no manual
invite / accept / init / symlink / `git worktree add` dance.

Spawn when a human asks, or when assigned work needs a teammate — not on your own
initiative to "get help".

## Spawn — one command, from your own instance home

`aw` reads your identity from the current directory's `.aw`, so run this from
your own home (it uses your team's authority to add the member):

```bash
aw team admin add <name>@aweb.team/<role>=<runtime> --start \
  --home <abs/path/to/agents/instances/<name>> \
  --session <tmux-session> --no-attach
```

- **`<role>`** is a profile in the blueprint (`developer`, `reviewer`,
  `proofreader`, …); **`<runtime>`** is `claude-code` or `pi`. Override the
  blueprint with `--blueprint` / `AWEB_BLUEPRINT` (default `aweb.team`).
- **`--start`** materializes the home from the **public blueprint** (an
  auth-less read), sets up **`<home>/worktree/`** — a git worktree on the
  agent's own branch — plus a **`work-main/`** symlink for coordination roles
  (`works_on_main`), then launches the runtime in tmux with channel preflight,
  trust/dev-channel prompt auto-answering, and `pi --approve`. It connects to
  the channel on its own.
- **`--session <name>` + `--no-attach`** — put the window in a named tmux
  session and don't attach. Use a **fresh/throwaway** session so you never touch
  a live team's session. `--recreate` is refused when the target session holds
  running agent windows; `--force-kill` is the explicit override that kills
  them. Prefer a fresh `--session` over ever reaching for `--force-kill`.
- **`--home`** overrides the default `agents/instances/<name>`. Never move or
  rename a home after materialization — aweb registers the identity at its path.

The agent runs `aw` from its home and does all `git`/builds from `worktree/`.

Verify: `aw workspace status` shows the new member active; the tmux pane shows
the runtime up (claude: `bypass permissions on`; pi: `✓ aweb connected`).

## Materialize now, run later (two-step)

Drop `--start` to just materialize + isolate the home; launch it later with
`aw team admin up` (same launch path). Use this when you want the home staged before
running it.

## Retire

When the teammate is no longer needed, use the `retire-instance` skill (revoke
the membership, remove the worktree + home).
