---
type: Lesson
title: A pushed main is landed, so review comes before the push
description: A brief that says "push to main with one review" means the exact-SHA ACK comes before the push, because a push to main is a landing; where branch protection requires no review, nothing enforces this, and a change that landed unreviewed gets a post-landing exact-SHA review, not a revert.
tags: [lesson, review, landing, coordination, naapps]
timestamp: 2026-11-26
---

On 2026-11-26 a task briefing for naapp said to push to main directly, in
small steps, with one quick review per change. The seat read it as push, then
review, and two port commits went straight to naapp main. The naapps
coordinator corrected it: the team rule is that nothing lands without an
exact-SHA ACK from someone who is not the author, and a pushed main counts as
landed. The split-review seat then reviewed both commits after landing and
ACKed them.

Nothing stopped the pushes. As of 2026-11-27, naapp main's branch protection
requires the `naapp CI` check but no approving review, and it does not apply
to admins.

# How to apply

- Read "push to main" in a brief as a way of landing, not as permission to land
  before review. The ACK of the exact head SHA comes first.
- Every change goes on a branch with a PR, gets an ACK of its head SHA, and
  only then merges.
- If a change has already landed without review, do not revert it: the revert
  would be one more unreviewed push. Ask for a post-landing review of the exact
  SHA, and put any fix up as a PR.

The elimination route is branch protection that requires a review and applies
to admins. Until a repository has that, the rule depends on each seat.
[Main CI is a separate signal](/coordinator/main-ci-is-a-separate-signal.md)
records the same gap for required checks, and
[skipping the train skips the only full run](/aweb-expert/lessons/skipping-the-train-skips-the-only-full-run.md)
records what a self-landing skipped in aweb.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-apps-repo, 2026-11-26;
notes/naapp-changes-go-through-prs.md (naapps correction b7a71cf7). The
correction and the post-landing ACKs are source-reported; the harvester could
not read those messages. The proposal and note said naapp main had no branch
protection. The harvester read the protection settings on 2026-11-27 and
recorded them as they are: a required check, no required review, admins
exempt.
