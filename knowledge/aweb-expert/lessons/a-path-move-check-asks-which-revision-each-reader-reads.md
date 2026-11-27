---
type: Lesson
title: A path move's in-repo check asks which revision each reader reads
description: Before moving an aweb path, search tests and joined path segments too, ask of every hit which revision it reads (working tree, a pinned SHA, origin/main or a tag), and run the self-test of every checker with a fixed list of root directories.
tags: [lesson, review, paths, history, release, checkers]
timestamp: 2026-11-27
---

A repository search and a green local run can pass for a path move that is
wrong. A tidy of the aweb root on 2026-11-27 hit three blind spots in the
in-repo check. Each one gave a green local run for a move that was broken
then, or would break something later.

- **Tests and joined path segments.** A search that skips test files, or
  matches only `dir/file`, misses
  `filepath.Join(root, "agents", "instructions.md")`. A deletion was returned
  in review because a Go end-to-end test read that file through
  `filepath.Join`, and the author's search had excluded `_test` files.
- **Readers pinned to history.** Some code reads a path from git at a
  revision other than the working tree. After the move, main's code cannot
  read the path at revisions from before the move. Cases found at aweb
  39b3f09114:
  - vm-gate reads `candidate-gate/Dockerfile` with `git show <sha>:...` at
    the SHAs it admits
    ([candidate-gate/ stays at the root](/aweb-expert/decisions/candidate-gate-stays-at-the-repository-root.md)).
  - The product-table ratchet reads its reviewed ceilings from
    `refs/remotes/origin/main` by path, so it is off for the move's own
    landing.
  - `scripts/publish_release.py` checks out the tag's tree but takes each
    package directory from the current script's `NPM_LANES`. A package tag
    cut before a move and published after it fails.
- **Checkers with a fixed list of root directories.**
  `scripts/check-doc-paths.sh` checks only references under its `TOP_LEVEL`
  list. References moved under a directory outside the list stopped being
  checked, and the checker stayed green. Only its freshness self-test caught
  it.

The files above are examples. The lesson is the three questions.

# How to apply

- Search every spelling of the path, tests included: the full string and each
  segment in join form. Then move or delete the path in a scratch tree and
  run the changed packages' tests.
- For each hit, ask which revision it reads: the working tree, a pinned SHA,
  `origin/main` or a release tag. A reader of history needs a decision about
  the move, not just an edit. Either keep the path, or accept a stated, bounded
  gap (for example, a ratchet that is off for one landing).
- Run the self-test of every checker the move changes. A checker that
  narrowed silently stays green.
- For a package move, compare the package's git tags with the registry's
  published versions. Record in the commit message that no tag cut before the
  move is still waiting to be published.

The fixed list in `check-doc-paths.sh` could instead be derived from the
tracked top-level directories. That would remove the third blind spot in code,
which is better than relying on this lesson.

This extends
[review a change against its existing consumers](/aweb-expert/lessons/review-a-change-against-its-existing-consumers.md),
which covers callers in the working tree, to readers of history.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-root-tidy, 2026-11-27;
notes/moving-an-aweb-path-check-outside-consumers.md. The review return of the
deletion, the self-test failure, and the coordinator's landing condition for
package moves are source-reported. The cited code was checked at aweb
39b3f09114 and at main 90519b0d2.
