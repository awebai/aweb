---
type: Decision
title: A reviewed docs-only move of the target branch does not force a regate
description: When a code head already has a green gate and the target branch has since moved only by reviewed docs-only commits, the author merges the target in and dispatch lands without a regate or re-ACK, provided the new three-dot diff is byte-identical to the reviewed one and the non-merge commits are the same; if either check fails, it goes back to the coordinator.
tags: [decision, gate, integration, review, landing]
timestamp: 2026-11-28
---

# Decision

A code head has a green gate. Before it lands, the target branch moves, and
every new commit on the target is a reviewed docs-only change. In that case
the head is not regated and its ACKs stay valid:

1. The author merges the moved target into the head with an ordinary merge.
2. Dispatch checks that `git diff <new target>...<new head>` is byte-identical
   to the reviewed three-dot diff against the old target. Compare the two
   diff outputs with a byte comparison such as `cmp`, not by eye or by stat.
3. Dispatch checks that the head's non-merge commits are the same commits as
   before the merge.
4. If both checks hold, dispatch fast-forwards the target to the head and
   reads the remote ref back.

If the intervening target commits are not all reviewed and docs-only, or
either check fails, dispatch does not land. It reports to the coordinator.

# Why

A full gate takes about 45 minutes, and docs landings on a busy target branch
arrive often: in one case five came in during a single gate. Without this rule
every docs landing would make the next code landing chase the branch with
another gate run. That goes against the operator's direction of no extra runs.

The two checks keep the guarantee a regate would give. The three-dot diff is
the head's own change relative to its merge base. If it is byte-identical, the
landed code change is exactly what was reviewed and gated. Everything else in
the landed tree comes from the reviewed docs commits, which run no code. A
merge that resolved a conflict, or pulled in anything beyond those commits,
changes the diff or the commit set, so it fails the check and goes to the
coordinator.

This applies the general integration rule in
[resolve full review anchors before integration](/coordinator/resolve-review-anchors-before-integration.md),
which compares the actual three-dot diff with the reviewed change. It does
not relax [skipping the train skips the only full run](/aweb-expert/lessons/skipping-the-train-skips-the-only-full-run.md):
the head did run its full gate, and only docs changed after it.

# Acceptance

A standing coordinator ruling ("going forward"), 2026-11-28, relayed to the
dispatch seat by aweb mail: **source-reported**. It was first applied that day
to a gated code head whose target had moved by five reviewed docs merges that
touched only design documents the head never changed. The three-dot diffs
(6,428 lines) were byte-identical, the same six non-merge commits were present,
and the fast-forward read back correctly.

Evidence: OKF proposal from aweb-expert/aweb-expert-gate-dispatch, 2026-11-28; notes/docs-landing-does-not-force-regate.md.
