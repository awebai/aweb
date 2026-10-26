---
type: Lesson
title: Shared checkout hazards
description: A Go build's read-only module cache inside a worktree blocks worktree removal and seat retirement; a failed retire can leave a .git file that git later points at another seat's worktree; and push.default=matching in a clone shared by seats pushes everyone's branches.
timestamp: 2026-10-24
---

Three hazards met while cleaning up and landing from checkouts that many seats
share.

- **Read-only module cache.** Go builds leave a read-only module cache inside
  the worktree, so `git worktree remove` and instance retirement fail with
  permission errors. The workaround that worked:
  `GOMODCACHE=<tree>/cli/go/.cache/go-mod go clean -modcache` before removing.
  It is a workaround; the underlying issue is tracked (aweb-ackt, open as of
  2026-10-25).
- **Slot aliasing after a failed retire.** A failed retire pruned the worktree
  metadata; git then reused the freed `worktrees/<n>` slot for another seat, and
  the stale `.git` file left behind pointed at that seat's worktree, so
  `git status` there showed the other seat's HEAD. Do not retry the retire.
  Neutralise the dangling `.git` reversibly (rename it) and report it.
- **`push.default=matching`.** In a clone shared by several seats, a bare
  `git push` fast-forwarded two dozen other seats' branches, including unpushed
  commits of their owners. Set `push.default=simple` on shared clones and push
  with explicit refspecs only.

Related: [recover partial lifecycle actions from receipts](recover-partial-lifecycle-actions.md).

## Provenance

Harvested 2026-10-25 from the `naapps` coordinator seat (log entries of
2026-10-19 and 2026-10-22 to 2026-10-24; note `pages-lane-train.md`); aweb-ackt
status confirmed by the seat in db078d42.
