---
title: "Team operating patterns"
kicker: "Product model"
description: "How resource packs describe reusable team souls, roles, skills, and playbooks without creating identities or worktrees."
weight: 23
---

# Team operating patterns

A new-design aweb template is a **team operating pattern** packaged as a
resource pack.

The user should not think "apply a template and hope it mutates the right
things." The user should think:

> Choose a team operating pattern. It gives you souls, roles, skills, and
> playbooks. Then explicitly create instances when you need them.

## Pattern vs instance

A **soul** is the durable body for a kind of agent: its role, operating
instructions, memory policy, and reusable knowledge. A soul lives in the repo as
reviewable files, for example:

```text
souls/developer/
  soul.yaml
  AGENTS.md
  docs/
  decisions/
  memory/
```

An **instance** is a running agent workspace with its own `.aw` identity and,
optionally, its own git worktree/branch. Instances are created explicitly with
normal filesystem/git operations plus aweb team/workspace primitives. A resource
pack may teach how to create an instance; it must not secretly create one.

## No hidden mutation

Applying a team operating pattern may copy or adapt resources, publish shared
instructions, and publish roles. It must not automatically:

- create identities;
- accept invites;
- write `.aw` state;
- create git worktrees or branches;
- delete keys;
- register BYOT/controller state;
- make harness-specific files canonical.

## Novice flow

For a team that already exists:

```bash
# Publish team-wide instructions.
aw instructions set --body-file resource-packs/coord-workflows/resources/instructions.md

# Add roles one at a time from Markdown playbooks.
aw roles add coordinator --title "Coordinator" --playbook-file resource-packs/coord-workflows/resources/roles/coordinator.md
aw roles add developer --title "Developer" --playbook-file resource-packs/coord-workflows/resources/roles/developer.md
aw roles add reviewer --title "Reviewer" --playbook-file resource-packs/coord-workflows/resources/roles/reviewer.md

# Verify what the team sees.
aw instructions show
aw roles list
aw roles show --all-roles
```

Then create agent instances only when needed. A worktree-backed developer
instance is explicit:

```bash
aw team invite
TOKEN=<invite-token>
git worktree add instances/dev-task-123 -b dev-task-123
cd instances/dev-task-123
aw team join "$TOKEN" --alias dev-task-123
aw init --alias dev-task-123
```

Until the human-facing `aw team` verbs are released, dashboard/connect flows may
emit the equivalent released `aw id team invite`, `aw id team accept-invite`, and
`aw init` commands.

## Soul file shape

`soul.yaml` is intentionally small:

```yaml
role: developer
work: worktree      # main | worktree | home
runtime: claude     # claude | codex | pi | other
```

- `role` names the team role this soul usually takes.
- `work: main` means instances point at the main checkout.
- `work: worktree` means instances normally get their own git worktree/branch.
- `work: home` means the agent's home is durable and it creates worktrees only
  through an explicit playbook.
- `runtime` is a default launch hint, not identity state.

## Relationship to resource packs

See [resource-pack-template-contract.md](resource-pack-template-contract.md) for
the file-level contract. A resource pack is the package format; a team operating
pattern is the product concept the package delivers.
