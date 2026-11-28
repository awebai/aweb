---
type: Lesson
title: Read an inventory from the exact base SHA, never a shared clone's local main
description: oats worktree add bases a new tree on origin's main but moves none of the shared member clone's refs, so a bare `main` there can be thousands of commits old; read inventories, diffs and `git show` from the exact SHA the change is based on (the tree's HEAD or a fetched origin/main) and state that SHA in the report.
tags: [lesson, git, inventory, removal, environment, oats]
timestamp: 2026-11-28
---

# The discovery

An inventory for removing AGENTS.md files was built with `git ls-tree main`
and `git show main:<file>` from inside a worktree. The worktree itself was on
origin's main, because `oats worktree add` bases new trees there. But the
member clone's local `main` ref does not move when a worktree is added, and
it had not moved in weeks. It stood 5,858 commits behind origin's main.

The inventory counted 41 agent files instead of 36. It named a production
skill for deletion, and for a hand-off to the hosted team, that had already
been removed on 2026-11-11. Nothing failed and the numbers looked plausible.
The error showed only when the deletion found the file missing.

Inventories feed decisions by Juan and the coordinator, so a stale one leads
to wrong decisions without any error to catch it.

# How to apply

- Read inventories, diffs and `git show` from the exact SHA the change will
  be based on: the tree's `HEAD`, or a freshly fetched `origin/main`.
- Never read from a bare `main` in a shared member clone.
- State the SHA in the report, so a reader can check the inventory against
  the same tree.

The durable fix lies outside aweb, in how OATS sets up shared member clones
and their trees, for example a clone with no local `main` branch to read by
mistake. Until such a fix exists, this lesson is the guard. It complements
[review a change against its existing consumers](/aweb-expert/lessons/review-a-change-against-its-existing-consumers.md):
a removal's search must read the right tree, as well as the right forms.

Checked by the harvester in aweb: the two SHAs are 5,858 commits apart, and
commit f8fc51f6e (2026-11-11) removed the production registry skill.

Evidence: OKF proposal from aweb-expert/aweb-expert-cleanup-oss, 2026-11-28; notes/inventory-against-origin-not-local-main.md.
