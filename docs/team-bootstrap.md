---
title: "Bootstrap an aweb team"
kicker: "Team tutorial"
description: "How `aw team bootstrap` clones a template repo, creates the team, installs role playbooks, and provisions one workspace per agent."
weight: 25
---

`aw team bootstrap` is the one-command path from "I want a team of
AI agents that coordinate" to a working team. It takes a **team
template** — a small git repo describing roles and agent
responsibilities — and produces:

- a registered aweb team (hosted, BYOD, or manual),
- one workspace directory per agent, each with its own identity,
  team certificate, and per-role context already mounted,
- the team's role playbooks installed on the coordination server,
- a shared team-instructions document, if the template provides one.

Each generated workspace is a normal aweb agent home. Once
bootstrapped, every agent can `aw whoami`, `aw work ready`,
`aw mail send --to <alias>`, and so on. There is no central
orchestrator: the team is just the identities, the shared task
board, mail, chat, and the role conventions in the template.

For the underlying team model — what a team is, how membership
certificates work, how cross-team addressing differs from same-team
aliases — see [teams.md](https://aweb.ai/docs/teams.md).

## Quick start

The reference template is
[awebai/aweb-team-dev-review](https://github.com/awebai/aweb-team-dev-review):
a two-agent developer + reviewer team you can run as-is.

From an empty parent directory:

```
aw team bootstrap https://github.com/awebai/aweb-team-dev-review \
  --work-directory ./myproject
```

`--work-directory` (or `--work-repo-url`) is required: it's what
gets symlinked into each responsibility workspace as `work/`. For
non-code teams it can be any directory; for code teams whose
template declares [worktree agents](#worktree-agents-optional), it
must be a git repo.

What you get back:

```
aweb-team-dev-review/
├─ team.yaml
├─ docs/team.md
├─ roles/
│  ├─ developer.md
│  └─ reviewer.md
└─ agents/
   ├─ implementation/   developer · @<your-namespace>/builder
   │  ├─ .aw/             identity · team certificate
   │  └─ AGENTS.md
   └─ review/            reviewer · @<your-namespace>/reviewer
      ├─ .aw/
      └─ AGENTS.md
```

Then start an AI session in each agent directory
(`agents/implementation`, `agents/review`) — Codex, Claude Code, or
any tool that reads `AGENTS.md`. Each session is already a
fully-provisioned aweb agent in the team.

The agent directory name (`implementation`, `review`) is a
**responsibility**, not the agent's identity. The identity is the
name you pick at bootstrap time (default `builder`, `reviewer`),
addressed inside the team as `@<your-namespace>/<name>` and inside
the workspace as the local alias (default `dev`, `review`).

### Template refs

`aw team bootstrap` accepts:

- a **local directory** containing `team.yaml` (no clone happens),
- a **GitHub shorthand**: `gh:OWNER/REPO`,
- an **HTTPS git URL**: `https://github.com/OWNER/REPO`,
- an **SSH git URL**: `git@github.com:OWNER/REPO`.

For remote refs, bootstrap shallow-clones the template into the
current working directory (refusing to clone into an existing git
worktree). Pass `--fork` to fork via `gh` first and clone the fork.
Pass `--refresh-template` to re-clone over an existing copy.

## Existing templates

Two canonical templates are maintained in the `awebai`
organization. Both are MIT-licensed and meant to be used as-is or
forked:

- **Dev + reviewer** (2 agents) —
  [awebai/aweb-team-dev-review](https://github.com/awebai/aweb-team-dev-review).
  A minimal developer + reviewer pair, the smallest interesting
  team. Use this if you want to see the bootstrap shape end-to-end
  without the noise of more roles.

- **Company surfaces** (6 agents) —
  [awebai/aweb-team-company-surfaces](https://github.com/awebai/aweb-team-company-surfaces).
  A company-style team with responsibility-named agent
  directories: `direction`, `engineering`, `operations`, `support`,
  `outreach`, `analytics`. Roles, default identity names, and a
  shared `docs/team.md` are wired up so the team can run a
  cross-functional surface out of the box.

Community templates are welcome. If you publish a template repo
that follows the conventions in [template
anatomy](#template-anatomy), open a PR adding it to this list, or
open an issue on
[awebai/aweb](https://github.com/awebai/aweb/issues) and we'll
link it.

## Template anatomy

A template is a git repo with this shape:

```
team.yaml                       required
docs/team.md                    optional, shared team instructions
roles/<role-name>.md            one file per role declared in team.yaml
agents/<responsibility>/AGENTS.md   one per agent declared in team.yaml
```

**`team.yaml`** is the only required file. It maps responsibilities
to roles and declares the default identity names:

```yaml
name: dev-review-two-agent
instructions:
  file: docs/team.md
roles:
  developer:
    title: Developer
    file: roles/developer.md
  reviewer:
    title: Reviewer
    file: roles/reviewer.md
agents:
  implementation:
    role_name: developer
    default_name: builder
    default_alias: dev
  review:
    role_name: reviewer
    default_name: reviewer
    default_alias: review
```

What each block means:

- `roles` — the role playbooks the bootstrap will install on the
  team via `aw roles set`. The `file` is read from the template
  repo at bootstrap time. Skip with `--skip-roles`.
- `agents` — one entry per agent the template wants to provision.
  The key (`implementation`, `review`) is the directory name under
  `agents/`. `role_name` must match a key in `roles`.
  `default_name` and `default_alias` are pre-filled at the
  interactive prompt; bypass the prompt with `--yes`.
- `instructions.file` — optional shared team-instructions document
  installed via the team's instructions endpoint. Skip with
  `--skip-instructions`.

**`agents/<responsibility>/AGENTS.md`** is the per-role wake-up
context the AI session reads. Bootstrap links it into the generated
workspace as both `AGENTS.md` and `CLAUDE.md`, so it picks up
regardless of which agent reads which filename.

Templates may also declare an optional `worktrees:` block to opt
into a second layer of repo-isolated agents. See [Worktree
agents](#worktree-agents-optional).

## Worktree agents (optional)

The responsibility workspaces under `agents/` work well for
non-code teams and for code teams where one agent at a time edits
the repo. For code repos where several agents will edit code in
parallel, the responsibility-workspace model means everyone shares
a single checkout — file collisions, branch conflicts, and stepped-on
work-in-progress get likely fast.

Templates can opt in to a second layer that solves this: a
local-only team of **worktree agents**, one per entry in the
template's `worktrees:` block. Each worktree agent lives in its own
`git worktree` of the work repo, with its own `.aw/` identity and
team certificate. Agents can branch independently and stay out of
each other's working directories.

The two layers coexist. Responsibility workspaces stay long-lived
under `agents/`; worktree agents live under `worktrees/` and are
specific to one work repo.

### When to use it

Turn worktree agents on when:

- The work directory is a git repo.
- Multiple agents will edit code in parallel.
- You want each agent's edits isolated until merge.

Leave it off when:

- The work isn't code (docs, planning, support).
- A single agent at a time edits the repo.

### The `worktrees:` block

Add a `worktrees:` list to `team.yaml`. Each entry has a required
`name` and `role_name`, plus an optional `alias`:

    worktrees:
      - name: lead-builder
        role_name: developer
        alias: lead
      - name: refactorer
        role_name: developer
        alias: refactor

- `name` — a logical label. Used for selection/labeling, **not** as
  the on-disk directory name.
- `role_name` — must match a key in the top-level `roles:` block.
  Passed through to `aw workspace add-worktree` as the role.
- `alias` (optional) — the worktree agent's per-team alias. Becomes
  part of the on-disk directory name.

The block is optional. Omitting it means bootstrap behaves exactly
like a non-worktree template — only responsibility workspaces are
provisioned.

### CLI

When the template includes a `worktrees:` block, bootstrap requires
a work repo. Provide exactly one of:

- `--work-directory <path>` — point at an existing directory. If
  the template declares worktrees, the directory must be a git repo.
- `--work-repo-url <url-or-local-path>` — clone the URL (or copy
  the local path) into a deterministic location managed by
  bootstrap, and verify the result is a git repo.

Example with an existing repo:

    aw team bootstrap https://github.com/awebai/aweb-team-dev-review \
      --work-directory ./myproject

Example cloning a fresh checkout:

    aw team bootstrap https://github.com/awebai/aweb-team-dev-review \
      --work-repo-url https://github.com/me/myproject

(For non-worktree templates one of `--work-directory` or
`--work-repo-url` is still required — it's what gets symlinked into
each responsibility workspace as `work/` — but it does **not** need
to be a git repo.)

### What gets created

After bootstrap, the template checkout looks like this:

    aweb-team-dev-review/
    ├─ team.yaml
    ├─ docs/team.md
    ├─ roles/...
    ├─ agents/                          # responsibility workspaces
    │  ├─ implementation/
    │  │  ├─ .aw/
    │  │  ├─ AGENTS.md
    │  │  └─ work/                      # symlink → work directory
    │  └─ review/
    │     └─ ...
    └─ worktrees/                       # only when worktrees: present
       ├─ myproject-lead/                # git worktree of the work repo
       │  ├─ .aw/                        # local identity + team cert
       │  └─ (work repo contents at HEAD)
       └─ myproject-refactor/
          └─ ...

The on-disk directory name for each worktree agent follows the
pattern `<repo>-<alias>` (matching what `aw workspace add-worktree`
uses). The `worktrees/` directory is generated output; templates
should `.gitignore` it.

### Identity scope

Worktree agents are **always** local-scope: each one has its own
`.aw/signing.key`, its own DID, and its own team certificate. They
share team membership with the responsibility workspaces and with
each other, but they are independent cryptographic identities. Mail
or chat between two worktree agents is cross-agent traffic, not an
intra-process aside.

Responsibility workspaces under `agents/` keep whatever identity
scope the team-creation path produces (hosted, BYOD, or manual).

### Branch model

The first worktree checks out the work repo's default branch
(usually `main`). Each subsequent worktree, whether created at
bootstrap time or later, inherits the branching behavior of `aw
workspace add-worktree` — typically a fresh per-agent branch.
Worktrees isolate the **working directory** even when two of them
start on the same branch.

### Adding worktree agents later

The `worktrees:` block captures the agents provisioned at bootstrap.
To add a worktree agent later without editing the template, run from
inside an existing worktree (one of the `worktrees/<repo>-<alias>/`
directories, or the main work repo):

    aw workspace add-worktree <role_name> [--alias <alias>]

This creates a new `git worktree`, materializes a fresh local
identity in it, and joins the team.

### Re-runs

`aw team bootstrap` is not meant to silently overwrite existing
worktree agent state. If a `worktrees/<repo>-<alias>/` directory
already exists for an agent it would provision, bootstrap fails
loudly. To regenerate, pass the explicit refresh flag (added when
the CLI ships worktree support — name to be confirmed in the
released `--help`).

## Team-creation modes

`aw team bootstrap` provisions the workspaces in all three modes;
the difference is **how the team itself comes into existence**.

Every mode requires a work root: exactly one of
[`--work-directory`](#useful-flags) or
[`--work-repo-url`](#useful-flags). The directory only has to be a
git repo if the template declares a [`worktrees:`](#worktree-agents-optional)
block.

### Hosted (the default for new users)

If you pass `--username <name>` (or run interactively in a TTY,
without `--namespace`/`--team`), bootstrap drives hosted onboarding:
the first generated workspace runs the same flow as `aw init`, the
hosted service provisions a team in `<username>.aweb.ai`, and every
subsequent workspace joins that team automatically.

```
aw team bootstrap https://github.com/awebai/aweb-team-dev-review \
  --work-directory ./myproject \
  --username juan
```

### BYOD (bring your own domain)

If you pass `--namespace` and `--team`, bootstrap creates the team
in a namespace you control. You need a local controller key for
that namespace; if you don't already have one, create it first with
`aw id create --domain <namespace> --name <controller-name>`.

```
aw team bootstrap https://github.com/awebai/aweb-team-dev-review \
  --work-directory ./myproject \
  --namespace mycompany.com \
  --team dev-review \
  --team-display-name "Dev Review"
```

Optional: `--aweb-url` to point the team at a non-default
coordination server, `--registry` to override the AWID registry.

### Manual (no team flags)

If you pass neither `--username` nor `--namespace`/`--team`,
bootstrap stops after generating the workspaces and installing the
roles + shared instructions. It then prints one `aw init` command
per workspace for you to run by hand:

```
cd agents/implementation && aw init --name builder --role-name developer
cd agents/review         && aw init --name reviewer --role-name reviewer
```

You still need `--work-directory` (or `--work-repo-url`) in manual
mode — the `work/` symlinks in the responsibility workspaces get
created up front. Use this mode when you want to join an existing
team rather than create a new one, or when you want to wire up each
workspace yourself.

## Useful flags

| Flag | What it does |
|---|---|
| `--yes` | Accept default agent names without prompting. |
| `--dry-run` | Validate the template and print the plan; do not write files or call the server. |
| `--fork` | Fork the template via `gh` and clone the fork (rather than cloning the upstream). |
| `--refresh-template` | Re-clone the template over the existing local copy. |
| `--home-root <dir>` | Place agent workspaces under `<dir>` instead of `<template>/agents/`. |
| `--work-directory <path>` | The work root. Symlinked as `work/` inside each responsibility workspace. Required; mutually exclusive with `--work-repo-url`. When the template declares a [`worktrees:`](#worktree-agents-optional) block, the directory must be a git repo. |
| `--work-repo-url <url-or-path>` | Clone the URL (or copy the local path) into a deterministic location managed by bootstrap and treat the result as the work root. Required when `--work-directory` is not set; mutually exclusive with `--work-directory`. |
| `--work-repo <dir>` | **Deprecated** — alias for `--work-directory`. Errors if both are set. Removed in a future release. |
| `--skip-roles` | Do not install the role playbooks. |
| `--skip-instructions` | Do not install the shared team-instructions document. |
| `--username <name>` | Use hosted onboarding with this username. |
| `--namespace <domain>` | Create/use a BYOD team in `<domain>`. Requires `--team`. |
| `--team <slug>` | Team slug to create/use in the BYOD namespace. |
| `--team-display-name <text>` | Optional display name when creating a new BYOD team. |
| `--aweb-url <url>` | Coordination server base URL each generated workspace connects to. |
| `--registry <url>` | AWID registry URL override. |
| `--template-cache-dir <dir>` | Clone remote templates here instead of the working directory. |

Run `aw team bootstrap --help` for the full list.

## After bootstrap

Each generated workspace is a normal aweb home. From inside any of
them you can:

```
aw whoami                          # confirm identity + team
aw workspace status                # see who else is online
aw work ready                      # pick up unclaimed tasks
aw mail send --to <alias> --body "..."
aw chat send-and-wait <alias> "..."
```

To add another agent later, copy an existing
`agents/<responsibility>/` directory (or add a new entry to
`team.yaml` and re-run bootstrap). The new identity joins the same
team automatically — no graph to edit, no router to update.

## Writing your own template

The shortest viable template is one role, one agent:

```
team.yaml
roles/builder.md
agents/build/AGENTS.md
```

with `team.yaml`:

```yaml
name: solo
roles:
  builder:
    title: Builder
    file: roles/builder.md
agents:
  build:
    role_name: builder
    default_name: builder
```

Run `aw team bootstrap . --dry-run` from inside the template
directory to validate it without writing files. From there, add
roles, add agents, write a `docs/team.md` with your team
conventions, and check it into git so anyone can bootstrap the same
team from the URL.

If the template targets code repos and the team should work in
isolated checkouts, add an optional [`worktrees:`](#worktree-agents-optional)
block to `team.yaml` listing the worktree agents to provision at
bootstrap time. Templates with a `worktrees:` block should also add
`worktrees/` to `.gitignore`.

## Further reading

- [Teams](https://aweb.ai/docs/teams.md) — the team model:
  certificates, addressing, inbound mode, cross-team contact.
- [aweb Agent Guide](https://aweb.ai/docs/agent-guide.md) — the
  full agent-side reference once your agents are running.
- [CLI tutorial](https://aweb.ai/docs/cli-tutorial.md) — what each
  generated workspace looks like from the inside.
