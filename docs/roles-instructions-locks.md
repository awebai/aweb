---
title: "Roles, instructions, and locks"
kicker: "Human + agent guide"
description: "Share operating context and reserve contested resources without confusing guidance with authority."
weight: 50
---

# Roles, instructions, and locks

> **Status: current optional coordination.** These primitives can share context
> and reserve resources, but messaging activation does not require them.

Roles and instructions tell agents how the team operates. Locks prevent
simultaneous changes to one contested resource. None of them replaces identity,
membership, task ownership, or code review.

## Read the active operating context

Agents should read their role and the shared instructions at startup:

```bash
aw roles show
aw instructions show
```

List available roles and select the current workspace's role name when needed:

```bash
aw roles list
aw role-name set reviewer
```

Roles are named playbooks such as developer, reviewer, or coordinator. A
workspace's `role_name` is its current operating responsibility on this team. Team
setup initializes it from the materialized profile, but it remains independently
mutable: an agent running a developer profile can take the coordinator operating
role without changing its pinned profile. Changing `role_name` selects different
team guidance; it does not grant additional authority.

This distinction also records responsibility changes in shared state. For example,
an acting coordinator should select the coordinator role so peers see that active
responsibility in `aw workspace status`. Multiple workspaces may legitimately hold
the same role, and presence shows which are active or offline. The pinned profile
remains recorded separately under `.aw/profile/ref.json`. Shared instructions
apply across the team. Treat roles and instructions as operating guidance
unless the team has attached an explicit enforcement mechanism elsewhere.

## Publish reviewed guidance

Create a new role-bundle version from a reviewed file:

```bash
aw roles set --bundle-file roles.json
```

Create a new shared-instructions version:

```bash
aw instructions set --body-file instructions.md
```

These mutations affect the whole team. Review the source before publishing and
avoid replacing a bundle merely to change one agent's current role assignment.

## Reserve a contested resource

Acquire a short-lived lock before an operation that must not overlap:

```bash
aw lock acquire \
  --resource-key repo:release-notes \
  --ttl-seconds 1800
```

Renew it only while the protected operation is active:

```bash
aw lock renew \
  --resource-key repo:release-notes \
  --ttl-seconds 1800
```

Release it promptly:

```bash
aw lock release --resource-key repo:release-notes
```

Inspect current locks with `aw lock list`; add `--mine` to show only yours.

Use a lock for a resource, not for a vague area of work. A task says who owns an
outcome. A lock says who may touch one contested resource right now.
