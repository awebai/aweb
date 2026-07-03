---
title: "Running materialized agents"
kicker: "Agent runtime guide"
description: "How aw team add materializes agent homes and how aw team up starts local agent runtimes."
weight: 27
---

# Running materialized agents

Use this guide after a workspace is already connected to a team with `aw init`
or `aw team join`.

## 1. Materialize local agent homes

`aw team add [NAME@]BLUEPRINT/PROFILE[:local|global][=RUNTIME]` creates or
connects a team member, materializes a profile into a local home, and records
profile provenance under `.aw/profile/`. By default homes are written under
`agents/instances/<name>`.

```bash
aw team add developer@aweb.team/developer=claude-code
aw team add reviewer@aweb.team/reviewer=pi
```

Current materialization runtimes are `claude-code`, `codex`, `pi`, and
`local-shell`; if you omit `=RUNTIME` and `--runtime`, the CLI uses
`claude-code`. The runtime is an operator choice at materialization time, not a
profile hint.

Identity scope is also explicit. Use `:local` for the default team-scoped local
identity, or `:global` for a global AWID identity/address-backed agent:

```bash
aw team add local-dev@aweb.team/developer:local=claude-code
aw team add public-reviewer@aweb.team/reviewer:global=pi
```

### Home isolation: `worktree/` and `work-main/`

`aw team add` separates the agent's **home** (identity + body, where `aw`
resolves its identity) from its **work** (where the agent runs `git` and
builds), so an agent's git work never touches the checkout it was created from.
When the home is inside a git repo, `aw team add`:

- creates **`<home>/worktree/`** — a git worktree on a branch named after the
  agent — as the agent's isolated place for `git`/build, and
- adds the home to that repo's `.gitignore`.

Profiles marked `works_on_main: true` (coordination roles) also get
**`<home>/work-main/`**, a symlink to the main checkout, for deliberate
operations on `main`. Code roles (`works_on_main: false`) get `worktree/` only.
The rule each profile instructs its agent to follow: **run `aw` from the home,
run all `git` and builds from `worktree/`, and touch `main` only through the
named `work-main/`.**

Point the worktree at a **separate** project repo with `--work-dir`:

```bash
aw team add alice@aweb.team/developer=pi --work-dir ~/prj/my-project
```

The worktree is then a worktree of `~/prj/my-project` (whose own checkout is
left untouched), while the home can live anywhere. If the home is **not** in a
git repo and no `--work-dir` is given, worktree setup is skipped and the agent
works in its home directly — so non-git setups still work, just without an
isolated worktree.

## 2. Public blueprint source

`aw team add` and `aw team create --agent ...` read public profile payloads from
the Library catalog API and materialize locally. The public materialization path
does not import to the private shelf, does not bind through the Library plugin,
and does not call the server-side `/v1/materialize` endpoint.

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
[`blueprint-materialization-contract.md`](blueprint-materialization-contract.md).

## 3. Start local agents with `aw team up`

`aw team up` is a local tmux convenience. It reads materialized
`agents/instances/<name>` homes, starts one tmux window per supported interactive
runtime, and leaves team definitions and profile provenance in aweb state and
`.aw/profile/ref.json`.

```bash
aw team up --dry-run
aw team up
```

Current `aw team up` launch support is narrower than materialization support:

- `claude-code` starts:

  ```bash
  claude --dangerously-skip-permissions --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace
  ```

- `pi` starts:

  ```bash
  pi --approve
  ```

- `codex` and `local-shell` can be materialized, but `aw team up` currently
  rejects them; start those runtimes manually from the materialized home and
  have the agent poll `aw mail inbox` and `aw chat pending`.

Before starting windows, `aw team up` preflights the runtime channel:

- for Claude Code, it installs/verifies the `aweb-channel` plugin via the
  Claude plugin marketplace;
- for Pi, it installs/verifies `npm:@awebai/pi@latest`.

`aw team up` then auto-answers the known Claude Code trust-folder and
development-channel prompts in tmux. Pi startup is unattended: `pi --approve`
trusts the project-local files, so Pi does not show its trust-folder prompt.

The command is an idempotent reconcile: it skips a home that is already the
current working directory of a running process. Use `--force` to ignore that
running-process check, or `--recreate` to kill and recreate the tmux session.

## 4. One command: `aw team add --start`

`aw team add … --start` materializes the home, sets up the worktree isolation
above, and launches the agent in tmux in a single step — the same launch path
as `aw team up` (channel preflight, trust/dev-channel prompt auto-answering,
`pi --approve`). Use it to instantiate and run one agent at once:

```bash
aw team add alice@aweb.team/developer=pi --start
```

`--start` requires exactly one agent and is rejected with `--layout-only`. It
takes the same `--session` / `--attach` / `--no-attach` options as `aw team up`,
and skips launching if the home is already a running process's cwd.

## Implementation anchors

These claims were checked against the current CLI implementation:

- Public materialization defaults and selectors: `cli/go/cmd/aw/library_profile.go:21`, `cli/go/cmd/aw/library_profile.go:23`, `cli/go/cmd/aw/library_profile.go:24`, `cli/go/cmd/aw/library_profile.go:25`, `cli/go/cmd/aw/library_profile.go:424`, `cli/go/cmd/aw/library_profile.go:434`.
- Public catalog GET endpoint: `cli/go/cmd/aw/library_profile.go:466`, `cli/go/cmd/aw/library_profile.go:471`.
- Shelf/plugin path remains separate from public materialization: `cli/go/cmd/aw/library_profile.go:265`, `cli/go/cmd/aw/library_profile.go:612` versus `cli/go/cmd/aw/team_human.go:1204`; regression coverage asserts public team materialization does not import to shelf or call `/v1/materialize` at `cli/go/cmd/aw/local_surface_e2e_test.go:422` and `cli/go/cmd/aw/local_surface_e2e_test.go:426`.
- Supported materialization runtimes: `cli/go/cmd/aw/library_profile.go:597`.
- `aw team add` specs, local/global flags, runtime/library/blueprint flags, and `agents/instances` root: `cli/go/cmd/aw/team_human.go:74`, `cli/go/cmd/aw/team_human.go:161`, `cli/go/cmd/aw/team_human.go:162`, `cli/go/cmd/aw/team_human.go:165`, `cli/go/cmd/aw/team_human.go:166`, `cli/go/cmd/aw/team_human.go:167`, `cli/go/cmd/aw/team_human.go:1089`.
- `aw team up` tmux scope, active-home reconcile, runtime commands, preflight, and prompt auto-answering: `cli/go/cmd/aw/team_up.go:30`, `cli/go/cmd/aw/team_up.go:165`, `cli/go/cmd/aw/team_up.go:175`, `cli/go/cmd/aw/team_up.go:209`, `cli/go/cmd/aw/team_up.go:222`, `cli/go/cmd/aw/team_up.go:420`, `cli/go/cmd/aw/team_up.go:463`.
- Home worktree isolation, `--work-dir` resolution, `.gitignore` update, and `work-main`: `cli/go/cmd/aw/team_human.go:1317`, `cli/go/cmd/aw/team_human.go:1375`, `cli/go/cmd/aw/team_human.go:1447`, and the `--work-dir` flag at `cli/go/cmd/aw/team_human.go:177`.
- `aw team add --start` (materialize + isolate + launch via the team-up path): `cli/go/cmd/aw/team_human.go:172`, `cli/go/cmd/aw/team_human.go:1269`.
- Channel installers: `cli/go/cmd/aw/channel_setup.go:14`, `cli/go/cmd/aw/channel_setup.go:17`, `cli/go/cmd/aw/channel_setup.go:41`, `cli/go/cmd/aw/channel_setup.go:63`.
