---
title: "Running materialized agents"
kicker: "Agent runtime guide"
description: "How optional aw team add and aw team up helpers materialize homes and start local runtimes without owning their lifecycle."
weight: 27
---

# Running materialized agents

> **Status: advanced, optional runtime helper.** These commands can create a
> particular local layout and launch supported tools, but aweb does not own
> agent definitions, homes, worktrees, runtime choice, process lifecycle, or
> session UX. Existing agent directories can use communication without this
> workflow.

Use this guide after a workspace is already connected to a team. For the
communication-first path with two existing agent directories, start with the
[CLI tutorial](/docs/cli-tutorial/). For this optional materialization workflow,
see [Create and run your first team](/docs/create-and-run-team/) or
[Add an AI tool to a team](/docs/add-ai-tool/).

## 1. Materialize a member, not just a directory

Run `aw team add` from a directory whose own `.aw` state is connected to the
team you want to extend:

```bash
aw team add developer@aweb.team/developer=claude-code
aw team add reviewer@aweb.team/reviewer=pi
```

The command uses that active workspace as the membership authority. It creates
or connects a distinct team member, gives that member its own `.aw` identity and
membership state, materializes the selected profile, and records pinned
provenance under `.aw/profile/`. It does not copy or share the caller's `.aw`
directory.

Let `D` be the directory where you run the command. Let `R` be the Git
top-level when `D` is inside a Git worktree; outside Git, `R` is `D`. Default
homes are created at:

```text
R/agents/instances/<name>/
```

So running the command from `repo/src/` creates
`repo/agents/instances/<name>/`, not `repo/src/agents/instances/<name>/`. The
command prints the absolute home path when it finishes.

Each home contains the member's identity, profile, runtime adapters, and work
boundary:

```text
<name>/
  .aw/             # this member's identity, certificate, team, and connection
  .aw/profile/     # materialized profile and pinned source provenance
  AGENTS.md
  CLAUDE.md        # when the selected runtime needs this adapter
  worktree/        # isolated Git worktree when a work repository is available
```

Current materialization runtimes are `claude-code`, `codex`, `pi`, and
`local-shell`; if you omit `=RUNTIME` and `--runtime`, the CLI uses
`claude-code`. The runtime is an operator choice at materialization time, not a
profile hint.

When scope is omitted, the profile supplies the default. Every currently
published `aweb.team` profile defaults to local. Pass `:local` or `:global`
explicitly to override it:

```bash
aw team add local-dev@aweb.team/developer:local=claude-code
aw team add public-reviewer@aweb.team/reviewer:global=pi
```

- `:local` selects a team-scoped identity.
- `:global` creates or reuses a durable AWID identity that can hold public
  addresses and memberships in more than one team.

### Home isolation: `worktree/` and `work-main/`

`aw team add` separates the agent's **home** (identity + instructions, where
`aw` resolves its identity) from its **work** (where the agent runs `git` and
builds). When a work repository is available, it:

- creates **`<home>/worktree/`** — a Git worktree on a branch named after the
  agent — as the isolated place for Git and build work; and
- adds the generated home to the source repository's `.gitignore`.

Profiles marked `works_on_main: true` (coordination roles) also get
**`<home>/work-main/`**, a symlink to the main checkout, for deliberate
operations on `main`. Code roles (`works_on_main: false`) get `worktree/` only.
The operating rule is: **run `aw` from the home, run Git and builds from
`worktree/`, and touch main only through the named `work-main/`.**

Point the worktree at a separate project repository with `--work-dir`:

```bash
aw team add alice@aweb.team/developer=pi --work-dir ~/prj/my-project
```

The checkout at `~/prj/my-project` remains untouched. Its Git worktree is
created at `<home>/worktree/`; the home can live elsewhere. If the home is not
in a Git repository and no `--work-dir` is given, worktree setup is skipped and
the agent works directly in its home.

## 2. Materialization does not necessarily start a process

Plain `aw team add ...` stops after creating the membership, home, profile, and
worktree. No Claude Code, Pi, Codex, or shell process is running yet.

Use `--start` to materialize and launch exactly one supported agent:

```bash
aw team add alice@aweb.team/developer=pi --start
```

`--start` requires exactly one agent and is rejected with `--layout-only`. It
takes the same `--session`, `--attach`, and `--no-attach` options as
`aw team up`, and skips launching if the home is already a running process's
current working directory.

## 3. Start and access materialized agents

`aw team up` is a local tmux convenience. Run it from any directory in the Git
worktree that owns `R/agents/instances/`; outside Git, run it from the directory
that contains `agents/instances/`.

```bash
aw team up --dry-run
aw team up
```

The command resolves the same `R`, scans `R/agents/instances/`, and launches
homes that contain a materialized `.aw/profile/profile.yaml`. A profileless
founding workspace is not launched.

Every runtime process starts with the **agent home** as its current working
directory:

```text
cd <agent-home> && exec <runtime-command>
```

It does not start in `worktree/`. This is how the runtime loads the home's
instructions and resolves the correct aweb identity. The agent changes into
`worktree/` for Git, tests, and builds.

By default, `aw team up` launched from inside tmux uses the caller's current
session, so each launched agent is immediately reachable as a new window there.
Outside tmux, it uses the active-team-derived session name (or `aw-team`). Use
normal tmux window navigation to move between agents. `--session` overrides
both defaults. `--no-attach` leaves the session running in the background; the
command output names the session to attach to later.

If tmux is unavailable, the command prints the exact `cd <home> && <command>`
line for each agent. Run those commands in separate terminals. The output of
`aw workspace status` from an agent home also shows that member's path and host.

Current launch support is narrower than materialization support:

- `claude-code` starts with the aweb channel plugin;
- `pi` starts with the aweb extension and `--approve`;
- `codex` and `local-shell` can be materialized, but `aw team up` currently
  rejects them. Start those runtimes manually from the materialized home and
  have the agent poll `aw mail inbox` and `aw chat pending`.

Before starting windows, `aw team up` installs or verifies the supported
runtime channel and handles the known trust and development-channel prompts.
For Pi, this is deliberately install-if-missing: the launcher does not silently
replace executable extension code in Pi's `~/.pi/agent/npm` package tree.

Pi 0.82+ checks unpinned packages at startup. A stale cache produces a warning
headed `Package Updates Available` with `Package updates are available. Run pi
update --extensions` and a package list. Update `@awebai/pi` narrowly with
`pi update npm:@awebai/pi`; pre-0.82 Pi uses
`npm install @awebai/pi@latest --prefix ~/.pi/agent/npm` as the fallback. Then
fully stop and restart the affected Pi process. If a running session showed the
warning before the cache was refreshed, that process remains stale even when
the package.json on disk is now current.

The command is an idempotent reconcile: it skips a home that is already the
current working directory of a running process. Use `--force` to ignore that
running-process check. `--recreate` kills and recreates the tmux session only
when the target session has no running agent windows; otherwise it refuses
unless you pass `--force-kill`.

For an explicit `--session`, or for the generated default outside tmux,
live-agent tmux can be isolated from the human/default socket by setting
`AWEB_TMUX_TMPDIR` before `aw team up`, `aw team add --start`, or
`aw team extend --start`. The CLI maps that value to `TMUX_TMPDIR` for each
tmux child and strips inherited `TMUX`. The same value can be persisted as
`aweb_tmux_tmpdir` in `.aw/workspace.yaml`; the environment variable wins.

There is one deliberate exception: inside tmux with no explicit `--session`,
the caller's current session is the destination. The CLI resolves that session
before applying launcher socket configuration, then preserves the inherited
`TMUX` context for every launch, inspection, prompt, and attach operation. If
the caller session cannot be resolved, the command fails instead of falling
back to a team-derived session on another socket.

These names are deliberately different: **raw `tmux` ignores
`AWEB_TMUX_TMPDIR`**. A direct tmux command must receive `TMUX_TMPDIR` (or an
explicit socket), otherwise it silently reaches the default server. Launched
agents also receive a generated `~/.config/aw/guard-bin/tmux` first on `PATH`;
it rejects `kill-server`, including when the call is hidden in a script, trap,
or subshell. Claude/Pi command hooks are an additional visible-command gate,
not a substitute for the inherited PATH guard.

Tmux dogfood is never an ad-hoc command or inline cleanup trap. Add a committed,
reviewed harness, make it prepend `scripts/guard-bin`, use a throwaway named
session on an isolated socket, and tear down only that named session. Never use
`kill-server`. See [Agent tmux cutover](agent-tmux-cutover.md) for the reviewed
per-team migration procedure.

## 4. Public blueprint source

`aw team add` and `aw team create --agent ...` read public profile payloads from
the Library catalog API and materialize them locally. The public path does not
import to the private shelf, bind through the Library plugin, or call the
server-side `/v1/materialize` endpoint.

Defaults:

1. `--library-url`
2. `AWEB_LIBRARY_URL`
3. `https://library.aweb.ai`

For profile-only selectors, the blueprint default is:

1. `--blueprint`
2. `AWEB_BLUEPRINT`
3. `aweb.team`

The private Library shelf remains an opt-in app for the profile evolution loop:

```bash
aw plugin install https://library.aweb.ai/.well-known/aweb-app.json
```

For the wire contract and pin file shape, see
[`blueprint-materialization-contract.md`](https://github.com/awebai/aweb/blob/main/docs/blueprint-materialization-contract.md).

## Implementation anchors

These claims were checked against the current CLI implementation and the
released CLI's path behavior:

- Team creation, the exact invocation-directory root workspace, and roster
  materialization: `cli/go/cmd/aw/team_human.go`.
- Git-top-level fallback outside/inside Git: `cli/go/cmd/aw/inject_docs.go`.
- Member home creation, identity setup, `--home`, `--work-dir`, worktree
  isolation, `.gitignore`, `work-main`, and `--start`:
  `cli/go/cmd/aw/team_human.go`.
- Team-up root resolution, profile-home scan, runtime commands, home cwd,
  preflight, prompt handling, and tmux lifecycle: `cli/go/cmd/aw/team_up.go`.
- Public materialization selectors, source, and runtime validation:
  `cli/go/cmd/aw/library_profile.go`.
- Runtime channel installers: `cli/go/cmd/aw/channel_setup.go`.
