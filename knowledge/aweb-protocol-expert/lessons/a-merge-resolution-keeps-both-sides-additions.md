---
type: Lesson
title: A merge resolution keeps both sides' additions
description: Resolving a conflict by taking one side's whole file drops the other side's non-conflicting additions; after a conflicted merge, check file by file that every line your side added since the merge base survives, and run the tests the merge touches as part of the merge, because build, vet and a read of the remerge-diff do not catch a lost hunk.
tags: [lesson, git, merge, process, review]
timestamp: 2026-11-21
---

To keep main's behaviour for one conflicting rule in a file, a conflict was
resolved by taking main's whole copy of that file. That also dropped a
separate, non-conflicting function of the branch and its call site, so a
feature disappeared.

It went unnoticed for two reasons:

- The function was called only from inside the same file, so build and vet
  stayed green.
- The remerge-diff showed a large resolution, and it was read as intended.

Only the tests the merge touched caught it, and they ran a day later.

# How to apply

- "Resolve keeping main's behaviour" means keeping main's rule while keeping
  your additions, never taking main's whole file.
- After every conflicted merge, for each file both sides changed, list the
  lines your side added since the merge base and look for each in the merged
  file. Inspect every missing line: most are deliberate rewordings, but a
  missing function is a lost feature.
- Run the tests the merge touched as part of the merge, not as a later
  receipt.

No tool in the repository does the line-survival check; it is manual until
one does.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-chat-verify, 2026-11-21; notes/merge-take-theirs-drops-my-additions.md. Merge 0a7f85633e and its correction 4aea1b48bf verified on branch `agents/aweb-protocol-expert-chat-verify-adje3`.
