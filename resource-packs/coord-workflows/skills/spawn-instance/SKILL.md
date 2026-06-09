---
name: spawn-instance
description: Create or retire a concrete instance of a durable soul using explicit invite/join/init and git/filesystem steps. Use only when a human asks or a documented workflow requires it.
---

# Spawn an instance of a soul

Souls live under `souls/<role>/`. An instance is a runnable workspace with its
own `.aw` identity and optional git worktree/branch.

Do not spawn on your own initiative. Spawn only when a human asks or a documented
workflow requires it.

## Create

From the repo root:

```bash
role=developer
name=dev-task-123
work=$(awk -F': *' '/^work:/{print $2}' "souls/$role/soul.yaml" | awk '{print $1}')

aw team invite
TOKEN=<paste invite token>

if [ "$work" = worktree ]; then
  git worktree add "instances/$name" -b "$name"
else
  mkdir -p "instances/$name"
fi

cd "instances/$name"
aw team join "$TOKEN" --alias "$name"
aw init --alias "$name"
```

If the released CLI does not yet have `aw team`, use the equivalent low-level
commands printed by `aw id team invite` and `aw id team accept-invite`.

Then link or copy the soul body deliberately:

```bash
REPO=$(git -C . rev-parse --show-toplevel 2>/dev/null || pwd)
ln -sfn "$REPO/souls/$role/AGENTS.md" AGENTS.md
```

Create harness-specific links only after choosing the harness.

## Retire

Ask the human/coordinator before retiring an instance. Preserve useful branch or
soul changes first. Then revoke/leave membership where appropriate and remove the
explicit instance directory or worktree.
