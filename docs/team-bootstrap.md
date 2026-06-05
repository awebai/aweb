---
title: "Bootstrap an aweb team"
kicker: "Team tutorial"
description: "How `aw team bootstrap` creates a project-local agents/ convention from a template, creates or joins the team, installs role playbooks, and provisions one workspace per agent."
weight: 25
---

`aw team bootstrap` is the one-command path from "I want a team of
AI agents that coordinate around this repo" to a working team. It
takes a **team template** — a small git repo describing roles and
agent responsibilities — and produces:

- a registered or joined aweb team (hosted, BYOT, invite, API key,
  or current-workspace forwarding),
- a project-local `agents/` directory with one live home per agent,
- optional generated git worktrees for worktree-bound agents,
- the team's role playbooks installed on the coordination server,
- a shared team-instructions document, if the template provides one.

Each generated home is a normal aweb workspace. Once bootstrapped,
every agent can `aw whoami`, `aw work ready`, `aw mail send --to
<alias>`, and so on. There is no central orchestrator: the team is
just identities, membership certificates, the shared task board,
mail, chat, and the role conventions in the template.

The normative layout contract is
[`bootstrap-layout-contract.md`](bootstrap-layout-contract.md).

## Quick Start

Run bootstrap from the root of the project git repo where agents
will work:

```bash
cd /path/to/project-repo
aw team bootstrap https://github.com/awebai/aweb-team-coord-worktrees.git \
  --username <username>
```

If you are not running interactively, provide an explicit team
source such as `--username`, `AWEB_API_KEY`, `--invite-token`, or
`--namespace/--team`.

Bootstrap creates:

```text
agents/
├─ team.yaml
├─ docs/
├─ roles/
├─ home/
│  ├─ coordinator/
│  │  ├─ .aw/
│  │  ├─ AGENTS.md
│  │  └─ work -> ../../..
│  ├─ developer/
│  │  ├─ .aw/
│  │  ├─ AGENTS.md
│  │  └─ work -> ../../worktrees/dev
│  └─ reviewer/
│     ├─ .aw/
│     ├─ AGENTS.md
│     └─ work -> ../../worktrees/review
└─ worktrees/
   ├─ dev/
   └─ review/
```

The repo root itself is not an aw workspace. Start Codex, Claude
Code, Pi, or another agent runtime from an agent home:

```bash
cd agents/home/coordinator
codex
```

## Mental Model

Bootstrap assembles five separate things:

1. **Template repo**: blueprint files. New templates use
   `team.yaml`, `roles/`, `docs/`, and `home/<agent>/AGENTS.md`.
2. **Project-local agents directory**: generated convention
   directory. Default: `agents/`; override with `--agents-dir`.
3. **Work binding**: each agent's `work` symlink points either at
   the repo root (`work: repo_root`) or a generated git worktree
   (`work: git_worktree`).
4. **Team source**: hosted new team, hosted API key, invite token,
   current workspace forwarding, or BYOT.
5. **Generated workspaces**: live homes under
   `agents/home/<agent>/`, each with its own `.aw/` state.

The first generated plan is the **anchor**. Bootstrap connects it
first, installs role playbooks and shared instructions through that
workspace's team context, then invites/connects the remaining
generated agents. Do not assume a responsibility named
`implementation` is special; use `--dry-run` when you need to see
the generated order before provisioning.

BYOT means **bring your own team**. In this flow that includes
bringing your own namespace/domain and controller key; there is no
separate domain-only bootstrap mode.

## Re-Run Safety

Bootstrap must not adopt, merge, or overwrite an existing generated
agents directory in v1. If `agents/` already exists, the command
fails before fetching templates, writing files, creating identities,
running git commands, or making network calls.

If your repo already uses `agents/` for something else, choose a
different convention directory:

```bash
aw team bootstrap https://github.com/awebai/aweb-team-coord-worktrees.git \
  --username <username> \
  --agents-dir aweb-agents
```

Bootstrap writes scoped `.gitignore` entries:

```gitignore
# Auto-written by aw team bootstrap (do not remove)
/agents/home/*/.aw/
/agents/worktrees/
```

It does not ignore the whole `agents/` directory. The visible
`team.yaml`, `docs/`, `roles/`, and home blueprint files are meant
to be inspectable and committable.

## Template Anatomy

A current template has this shape:

```text
team.yaml
docs/team.md
roles/<role-name>.md
home/<agent>/AGENTS.md
```

Example `team.yaml`:

```yaml
name: coordinator-with-dev-review-worktrees
instructions:
  file: docs/team.md
roles:
  coordinator:
    title: Coordinator
    file: roles/coordinator.md
  developer:
    title: Developer
    file: roles/developer.md
  reviewer:
    title: Reviewer
    file: roles/reviewer.md
agents:
  coordinator:
    role_name: coordinator
    default_name: coordinator
    default_alias: coord
    home_template: home/coordinator
    work: repo_root
  developer:
    role_name: developer
    default_name: developer
    default_alias: dev
    home_template: home/developer
    work: git_worktree
  reviewer:
    role_name: reviewer
    default_name: reviewer
    default_alias: review
    home_template: home/reviewer
    work: git_worktree
```

`home_template` is optional. When omitted, bootstrap looks for
`home/<agent>` and then falls back to the legacy
`agents/<agent>` source shape.

`work` is optional. When omitted, bootstrap uses `repo_root`.
Supported values in v1:

- `repo_root`: the generated home's `work` symlink points at the
  project repo root.
- `git_worktree`: bootstrap creates `agents/worktrees/<alias-or-agent>`
  and the generated home's `work` symlink points there.

## Team Sources

`aw team bootstrap` provisions workspaces from exactly one team
source. Explicit sources conflict; use only one of:

- `AWEB_API_KEY`
- `--invite-token`
- `--username`
- `--namespace`/`--team`

If no explicit source is set and the caller's current directory is
already an aw workspace, bootstrap forwards that current active team
by creating a one-use invite for the first generated workspace.

If no explicit source is set, the caller is not in an aw workspace,
and the command is running interactively, bootstrap uses hosted
onboarding.

If no source can be resolved, bootstrap stops before provisioning;
choose a source explicitly.

### Hosted New Team

```bash
aw team bootstrap https://github.com/awebai/aweb-team-coord-worktrees.git \
  --username juan
```

### BYOT

```bash
aw team bootstrap https://github.com/awebai/aweb-team-coord-worktrees.git \
  --namespace mycompany.com \
  --team dev-review \
  --team-display-name "Dev Review"
```

Optional: `--aweb-url` to point the team at a non-default
coordination server, `--registry` to override the AWID registry.

### Existing Hosted Team Via API Key

```bash
AWEB_API_KEY=aw_sk_... \
  aw team bootstrap https://github.com/awebai/aweb-team-coord-worktrees.git
```

### Existing Team Via Invite Token

```bash
aw team bootstrap /path/to/template --invite-token <token>
```

### Current Workspace Forwarding

Run from an initialized `.aw` workspace and do not set an explicit
team source. Bootstrap creates a one-use invite from the current
active team and accepts it into the first generated workspace.

## Legacy Mode

The old out-of-repo layout remains supported for compatibility. It
is selected by either legacy work flag:

- `--work-directory <path>`
- `--work-repo-url <url-or-local-path>`

Do not combine `--agents-dir` with either legacy flag.

Legacy mode creates homes under the old home root and symlinks the
legacy work directory into each home as `work/`. It is intended for
existing scripts and templates, not for new customer setup.

## Useful Flags

| Flag | What it does |
|---|---|
| `--agents-dir <dir>` | Project-local convention directory for in-repo mode. Default: `agents`. Must not already exist. |
| `--ask-for-agent-names` | In an interactive terminal, prompt for generated agent names instead of using template defaults. |
| `--dry-run` | Validate the template and print the plan; do not write generated files, create identities, or call the server. |
| `--fork` | Fork the template via `gh` and clone the fork. |
| `--refresh-template` | Re-clone the template over the existing cached/local clone. |
| `--home-root <dir>` | Legacy mode only: place agent workspaces under `<dir>` instead of `<template>/agents/`. |
| `--work-directory <path>` | Legacy mode: use an existing work directory. Mutually exclusive with `--work-repo-url`. |
| `--work-repo-url <url-or-local-path>` | Legacy mode: clone a work repo into `<template-checkout>/worktrees/<derived-name>/`. Mutually exclusive with `--work-directory`. |
| `--skip-roles` | Do not install role playbooks. |
| `--skip-instructions` | Do not install the shared team-instructions document. |
| `--username <name>` | Use hosted onboarding with this username. |
| `--invite-token <token>` | Accept an existing team invite into the anchor workspace. |
| `--namespace <domain>` | Create/use a BYOT team in `<domain>`. Requires `--team`. |
| `--team <slug>` | Team slug to create/use in the BYOT namespace. |
| `--team-display-name <text>` | Optional display name when creating a new BYOT team. |
| `--aweb-url <url>` | Coordination server base URL each generated workspace connects to. |
| `--registry <url>` | AWID registry URL override. |
| `--template-cache-dir <dir>` | Clone remote templates here instead of using a temporary checkout. |

Run `aw team bootstrap --help` for the full list.

## After Bootstrap

From inside any generated home:

```bash
aw whoami
aw workspace status
aw work ready
aw mail send --to <alias> --body "..."
aw chat send-and-wait <alias> "..."
```

To add another isolated code workspace later, run
`aw workspace add-worktree` from an initialized workspace in the
team.

## Further Reading

- [Teams](https://aweb.ai/docs/teams.md) — team model,
  certificates, addressing, inbound mode, cross-team contact.
- [aweb Agent Guide](https://aweb.ai/docs/agent-guide.md) — full
  agent-side reference once agents are running.
- [CLI tutorial](https://aweb.ai/docs/cli-tutorial.md) — what each
  generated workspace looks like from the inside.
