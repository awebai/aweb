---
type: Lesson
title: Preserve stash objects and dispositions separately
description: Proving that stash changes were incorporated does not preserve the stash object graph, and unreachable does not mean lost.
timestamp: 2026-10-01
---

For an incorporated stash, compare each changed path's blob at the stash
with its proposed incorporating commit. Check the stash parents and index tree,
including whether an untracked-files parent exists. This can prove incorporation
more precisely than applying the patch or judging similar code, while avoiding a
mutation of the active working tree.

Preservation is a separate obligation. Keep the stash commit, parent trees and
required ancestry in a verified bundle or pack, and record whether a pack depends
on base objects elsewhere. A patch is a convenience view, not a lossless object
backup. Test the preserved refs and objects before retiring their original home.

During October 1, 2026 consolidation, exact blob comparison proved one stash
incorporated while its historical objects were archived separately. A later
no-reflogs fsck baseline grew when another stash moved the former tip into the
reflog. Every newly unreachable object was found in the preserved archive's
closure. Compare object sets and explain reference changes; do not infer loss or
safety from counts alone, and do not prune unexplained objects.

## Provenance

Harvested from the coordinator’s September–October 2026 handover notes: `stash-incorporation-and-lossless-preservation.md`, `fsck-no-reflogs-and-stash-ref-movement.md`. The preserved notes and archived sessions retain the detailed incident receipts; this concept records the reusable conclusion, not a current implementation inventory.
