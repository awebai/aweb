---
title: "Legacy repo-local agents bootstrap"
kicker: "Legacy compatibility"
description: "Compatibility guide for existing `aw agents bootstrap` layouts and recovery of the project-local agents/ convention. New teams should use explicit primitives and resource packs."
weight: 25
---

> **Legacy compatibility:** `aw agents bootstrap` is preserved for existing
> bootstrap-era `agents/` layouts. New teams should prefer explicit primitives
> (`aw init`, `aw team invite`, `aw team join`, `aw workspace connect`,
> `aw check`) plus resource packs. See
> [`cli-setup-surface-sot.md`](cli-setup-surface-sot.md) and
> [`resource-pack-template-contract.md`](resource-pack-template-contract.md).

`aw agents bootstrap` is the old project-repo path from "I want a team of
AI agents working around this codebase" to a working aweb team. It
takes a **team template** and produces:

- a registered or joined aweb team,
- a project-local `agents/` directory with one blueprint home per agent,
- optional generated git worktrees for worktree-bound agents,
- role playbooks and shared instructions installed on the coordination
  server,
- local `.aw/` identity and certificate state under each generated
  runtime workspace.

The normative lifecycle contract is
[`agents-layout-lifecycle-contract.md`](agents-layout-lifecycle-contract.md).

## Quick Start

Run from the root of the project git repo where agents will work:

```bash
cd /path/to/project-repo
aw agents bootstrap https://github.com/awebai/aweb-team-coord-worktrees.git \
  --username <username> \
  --identity-prefix <human-slug>
```

`--identity-prefix` is the per-human prefix used when a committed
template allocates global or multi-human-safe local aliases. In a
shared repo, use something human-specific such as `juan`, `maria`, or
`acme-dev`.

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
│  │  ├─ AGENTS.md
│  │  └─ work -> ../../worktrees/developer
│  └─ reviewer/
│     ├─ AGENTS.md
│     └─ work -> ../../worktrees/reviewer
└─ worktrees/
   ├─ developer/
   │  └─ .aw/
   └─ reviewer/
      └─ .aw/
```

The repo root itself is not an aw workspace. Start Codex, Claude Code,
Pi, or another agent runtime from the generated runtime workspace:

```bash
cd agents/home/coordinator
codex

cd agents/worktrees/developer
claude
```

## Mental Model

Bootstrap assembles five separate things:

1. **Template repo**: blueprint files. Current templates use
   `team.yaml`, `roles/`, `docs/`, and `home/<responsibility>/AGENTS.md`.
2. **Project-local agents directory**: generated convention directory.
   Default: `agents/`; override with `--agents-dir`.
3. **Work binding**: repo-root agents use their blueprint home as the
   runtime workspace. Worktree-bound agents keep instructions under
   `agents/home/<responsibility>/`, but their runtime workspace and
   `.aw/` state live in `agents/worktrees/<name>/`.
4. **Team source**: hosted new team, hosted API key, invite token,
   current workspace forwarding, or BYOT.
5. **Generated workspaces**: repo-root workspaces under
   `agents/home/<responsibility>/`; worktree-bound workspaces under
   `agents/worktrees/<name>/`, each with its own ignored `.aw/` state.

The first generated plan is the **anchor**. Bootstrap connects it
first, installs roles and shared instructions through that workspace's
team context, then invites/connects the remaining generated agents.

BYOT means **bring your own team**: your namespace/domain, controller
key, and team authority. There is no separate domain-only bootstrap
mode.

## Shared Repos And Multiple Humans

The committed `agents/` layout is a shared blueprint, not shared
identity state. It should contain `team.yaml`, `docs/`, `roles/`, and
the agent home instructions. It must not contain final aliases, DIDs,
global addresses, certificates, signing keys, or per-human `.aw/`
state.

When a second human clones the same repo, they should not run bootstrap
again over the existing layout. They provision their own ignored
workspace state from the committed blueprint:

```bash
cd /path/to/project-repo
aw agents provision --invite-token <team-invite> --identity-prefix maria
```

The canonical multi-human templates use local aliases such as
`{user}-{classic-name}` so Juan and Maria can both provision the same
responsibilities without alias collisions. Ad-hoc single-human local
adds may still use simpler classic names, but committed shared
templates should prefer per-human aliases.

If a template has global agents, their addresses are also derived from
the identity prefix, for example `example.com/juan-coordinator`.

## Re-Run Safety

`aw agents bootstrap` does not adopt, merge, or overwrite an existing
agents directory in v1. If `agents/` already exists, it fails before
fetching templates, writing files, creating identities, running git
commands, or making network calls.

If your repo already uses `agents/` for something else, choose a
different convention directory:

```bash
aw agents bootstrap https://github.com/awebai/aweb-team-coord-worktrees.git \
  --username <username> \
  --identity-prefix <human-slug> \
  --agents-dir aweb-agents
```

Bootstrap writes scoped `.gitignore` entries:

```gitignore
# Auto-written by aw agents (do not remove)
/agents/home/*/.aw/
/agents/home/*/work
/agents/worktrees/
```

It does not ignore the whole `agents/` directory. The visible blueprint
files are meant to be inspectable and committable. Each agent home's
`work` symlink is generated local state and is ignored so another
human's provision run can regenerate it for their checkout.

If you created an `agents/` layout with an older aw that committed
`agents/home/*/work` symlinks, remove those tracked symlinks from git
after upgrading:

```bash
git rm --cached agents/home/*/work
git add .gitignore agents
git commit -m "agents: ignore generated work symlinks"
```

Do not delete `.aw/` state unless you intentionally abandon that local
identity.

## Template Anatomy

A current template has this shape:

```text
team.yaml
docs/team.md
roles/<role-name>.md
home/<responsibility>/AGENTS.md
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
    identity_scope: global
    home_template: home/coordinator
    work: repo_root
  developer:
    role_name: developer
    identity_scope: local
    home_template: home/developer
    work: git_worktree
  reviewer:
    role_name: reviewer
    identity_scope: local
    home_template: home/reviewer
    work: git_worktree
naming:
  local_alias:
    sequence: classic-name
    pattern: "{user}-{classic-name}"
  global_alias:
    sequence: classic-name
    pattern: "{user}-{classic-name}"
  global_name:
    pattern: "{user}-{responsibility}"
```

`default_name` and `default_alias` are legacy template fields. Current
templates should not use them. The committed template remains
identity-free; final aliases and addresses are planned per human at
bootstrap/provision time.

`home_template` is optional. When omitted, bootstrap looks for
`home/<responsibility>` and then falls back to the legacy
`agents/<responsibility>` source shape.

`work` is optional. When omitted, bootstrap uses `repo_root`.
Supported values in v1:

- `repo_root`: the generated home is the aw runtime workspace; its
  `work` symlink points at the project repo root.
- `git_worktree`: bootstrap creates `agents/worktrees/<worktree-name>`
  and uses that worktree as the aw runtime workspace; the generated
  blueprint home's `work` symlink points there.

## Team Sources

`aw agents bootstrap` provisions workspaces from exactly one team
source. Explicit sources conflict; use only one of:

- `AWEB_API_KEY`
- `--invite-token`
- `--username`
- `--namespace`/`--team`

If no explicit source is set and the caller's current directory is
already an aw workspace, bootstrap forwards that current active team by
creating a one-use invite for the first generated workspace.

If no explicit source is set, the caller is not in an aw workspace, and
the command is running interactively, bootstrap uses hosted onboarding.

If no source can be resolved, bootstrap stops before provisioning;
choose a source explicitly.

### Hosted New Team

```bash
aw agents bootstrap https://github.com/awebai/aweb-team-coord-worktrees.git \
  --username juan \
  --identity-prefix juan
```

### BYOT

```bash
aw agents bootstrap https://github.com/awebai/aweb-team-coord-worktrees.git \
  --namespace mycompany.com \
  --team dev-review \
  --identity-prefix juan \
  --team-display-name "Dev Review"
```

Optional: `--aweb-url` to point the team at a non-default coordination
server, `--registry` to override the AWID registry.

### Existing Hosted Team Via API Key

```bash
AWEB_API_KEY=aw_sk_... \
  aw agents bootstrap https://github.com/awebai/aweb-team-coord-worktrees.git \
  --identity-prefix juan
```

### Existing Team Via Invite Token

```bash
aw agents bootstrap /path/to/template \
  --invite-token <token> \
  --identity-prefix maria
```

### Current Workspace Forwarding

Run from an initialized `.aw` workspace and do not set an explicit team
source. Bootstrap creates a one-use invite from the current active team
and accepts it into the first generated workspace.

## Planning And Provisioning

Use plan before mutating a shared repo or joining a BYOT team:

```bash
aw agents plan --identity-prefix juan
aw agents plan --namespace example.com --team circle --identity-prefix juan
```

For BYOT planning with `--namespace`/`--team`, aw contacts the AWID
registry to fail closed on existing team aliases and namespace
addresses.

After the layout exists in a shared repo, additional humans provision
their own local identities from the committed blueprint:

```bash
aw agents provision --invite-token <token> --identity-prefix maria
```

`aw agents provision` rejects `--username` in v1 because `--username`
creates a new hosted team. Use an invite or API key to join an existing
team.

## Adding And Removing Agents

Add a repo-root local responsibility:

```bash
aw agents add support --role support --identity-scope local
```

Create a local worktree-bound agent without changing the shared layout:

```bash
aw agents add-worktree developer
```

Add a global BYOT responsibility:

```bash
aw agents add support \
  --global \
  --namespace example.com \
  --team circle \
  --identity-prefix juan
```

Remove operations are intentionally explicit because layout changes,
local state cleanup, certificate revocation, and global address deletion
are different actions:

```bash
aw agents remove support --remove-layout
aw agents remove support --deprovision-local
aw agents remove support --delete-global-address
```

`--remove-layout` is a shared blueprint change only. It does not revoke
other humans' certificates or delete their local `.aw/` state.

`--deprovision-local` uses the local team controller key when this is a
self-custodial team. For hosted-managed cert-only agents, it can instead use
the agent's own signing key and active team certificate to ask the hosted
service to deprovision that exact agent. It does not give the hosted service
authority over customer-controlled BYOT team members.

`--delete-global-address` is opt-in. For self-custodial namespaces it requires
the local namespace controller key. For hosted-managed global agents it is
handled by the hosted self-deprovision path only when the address is managed by
that hosted service; BYOT/unmanaged addresses remain controlled by the
customer's namespace controller.

Hosted self-deprovision returns structured errors that map to specific
recovery:

- `hosted_team_controller_required`: this team is not hosted-managed by the
  service. Use/restore the self-custodial team controller key.
- `global_address_not_hosted_managed`: the global address is BYOT/unmanaged.
  Delete it with the customer namespace controller, not the hosted service.
- `delete_global_address_required`: hosted-managed global deprovision must be
  rerun with `--delete-global-address`; the service cannot archive the hosted
  agent while preserving its managed address.
- `local_identity_has_no_global_address`: local identities have no global
  namespace address; rerun without `--delete-global-address`.

## Legacy Mode

The old out-of-repo layout remains supported only for compatibility. It
is selected by either legacy work flag:

- `--work-directory <path>`
- `--work-repo-url <url-or-local-path>`

Do not combine `--agents-dir` with either legacy flag. New customer
setup should use project-local `agents/`.

## Useful Flags

| Flag | What it does |
|---|---|
| `--agents-dir <dir>` | Project-local convention directory for in-repo mode. Default: `agents`. Must not already exist for bootstrap. |
| `--identity-prefix <slug>` | Per-human naming prefix used by shared templates. |
| `--dry-run` | Validate the template and print the plan; do not write generated files, create identities, or call the server. |
| `--fork` | Fork the template via `gh` and clone the fork. |
| `--refresh-template` | Re-clone the template over the existing cached/local clone. |
| `--home-root <dir>` | Legacy mode only: place agent workspaces under `<dir>` instead of `<template>/agents/`. |
| `--work-directory <path>` | Legacy mode: use an existing work directory. Mutually exclusive with `--work-repo-url`. |
| `--work-repo-url <url-or-local-path>` | Legacy mode: clone a work repo into `<template-checkout>/worktrees/<derived-name>/`. Mutually exclusive with `--work-directory`. |
| `--skip-roles` | Do not install role playbooks. |
| `--skip-instructions` | Do not install the shared team-instructions document. |
| `--username <name>` | Use hosted onboarding with this username. Bootstrap only; provision rejects this. |
| `--invite-token <token>` | Accept an existing team invite into the anchor workspace. |
| `--namespace <domain>` | Create/use a BYOT team in `<domain>`. Requires `--team`. |
| `--team <slug>` | Team slug to create/use in the BYOT namespace. |
| `--team-display-name <text>` | Optional display name when creating a new BYOT team. |
| `--aweb-url <url>` | Coordination server base URL each generated workspace connects to. |
| `--registry <url>` | AWID registry URL override. |
| `--template-cache-dir <dir>` | Clone remote templates here instead of using a temporary checkout. |

Run `aw agents bootstrap --help`, `aw agents provision --help`,
`aw agents add --help`, and `aw agents remove --help` for the full
surface.

## After Bootstrap

From inside any generated home:

```bash
aw whoami
aw workspace status
aw work ready
aw mail send --to <alias> --body "..."
aw chat send-and-wait <alias> "..."
```

If you use a wake-up path (Pi extension / Claude Code channel plugin),
start it inside the agent directory after initialization.

## Troubleshooting

If bootstrap fails:

- Capture the first error.
- Do not retry over an existing `agents/` directory.
- Inspect/back up any `.aw/` identity state before deleting generated
  directories.
- Prefer explicit `aw agents provision`, `aw agents add`, or
  `aw agents remove` recovery commands over hand-editing state.

If a second human hits an alias or address conflict, they should rerun
plan/provision with a different `--identity-prefix` or a naming pattern
that allocates an available name. Invite-only flows may discover
collisions only at mutation time; this is expected fail-closed behavior.
