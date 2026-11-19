---
type: Lesson
title: Rebuild on a rewritten dependency head; do not merge it again
description: When a dependency branch your head already merged is rebased, merging its new tip carries both copies of every rewritten commit into the train; rebuild instead on a merge of the new dependency tips, cherry-pick your own commits, prove the result differs only by the dependency's real change, and remap every cited SHA.
tags: [lesson, git, coordination, trains]
timestamp: 2026-11-19
---

Work is often stacked on reviewed dependency branches before they land
([staff by reviewed dependencies](/coordinator/staff-by-reviewed-dependencies.md)),
and a combined head follows the dependency owners' latest heads. If a
dependency owner rebases a branch you already merged, a plain merge of the new
tip brings in both the old and the rewritten copy of each of its commits. The
train's non-merge commits then no longer equal the union of the reviewed
heads ([lane trains share main](/coordinator/lane-trains-share-main.md)).

# How to apply

1. Check whether the dependency moved forward or was rewritten:
   `git merge-base --is-ancestor <old tip> <new tip>`. If the old tip is an
   ancestor, it fast-forwarded, and a plain merge is right.
2. If it was rewritten, list your own commits against the old tips:
   `git rev-list --reverse --no-merges HEAD ^<old dep tip> ^<other dep tip>`.
3. Make a new base by checking out the new dependency tip and merging the
   other dependencies' tips, then cherry-pick the list onto it.
4. Prove the rebuild: `git diff <old head> <new head>` must show only the
   dependency's real change (compare its old and new tips with
   `git diff --stat` first, so you know what that change is).
5. Every SHA of yours has changed. Remap the ones cited in commit messages,
   review requests, notes and task records before anyone acts on them.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-library-auth,
2026-11-18/19; notes/rebuild-on-rewritten-dependency-head.md (task
aweb-acgh.5). A dependency was rebased from 8ddc27a6c6 to 0e5e7e0a96 with
one real fix; 32 commits were rebuilt on c28cb37f67, and the diff against the
old head showed only that fix. The source reports that an independent
reviewer re-verified the composition; later dependency moves were
fast-forwards and were merged plainly.
