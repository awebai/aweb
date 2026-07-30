---
name: retire-instance
description: Remove a teammate — delete an instance's aweb identity and workspace, then its home, worktree, and branch. Use when an instance's job is done (a developer whose branch merged, a reviewer that gave its verdict).
---

# Retire an instance

One-shot instances are retired when their job is done, so teammates don't
pile up on the network. Standing instances (the coordinator) are
long-running and not retired this way.

**Preserve first.** Before removing anything, make sure useful branch work
is merged or pushed, and anything the instance learned that belongs in its
soul is committed (see `self-maintenance`).

Run from outside the instance (e.g. your own home):

```bash
name=<name>
REPO="$(cd "$(git rev-parse --git-common-dir)" && cd .. && pwd)"
inst="$REPO/agents/instances/$name"

( cd "$inst" && aw workspace delete "$name" )            # workspace + identity (run from ITS home)
git -C "$REPO" worktree remove "$inst/work" --force 2>/dev/null   # if it had a worktree
rm -rf "$inst"
git -C "$REPO" branch -D "$name" 2>/dev/null
git -C "$REPO" worktree prune
```

Use `aw workspace delete`, **not** `aw id team leave` — leave refuses an
identity's only team. If it answers 409 "Workspace is still active", the
service hasn't marked it stale yet: wait and retry before removing the
local directory — **never delete the home while the server still considers
the member active**, or it orphans in the roster. If the instance died
before cleanup, remove the stale member via the dashboard.
