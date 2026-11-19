---
type: Lesson
title: Train-ready names a full-diff review at the exact head
description: Before calling a branch ready for a train, name the independent reviewer and the ACK message that covers its full diff at the exact head; a lead's scoped ACK of a policy shape or a harness, and a passing gate, are separate facts and neither stands in for that review.
tags: [lesson, review, trains, evidence, coordination]
timestamp: 2026-11-13
---

On 2026-11-13 a gate-portability branch was reported ready for a train with a
green gate and the lead's ACKs, each of which covered only part of the change
(the shape of a policy, a harness). No independent reviewer had reviewed the
full diff at that head. The coordinator caught it before the train. The
independent review that followed found a false claim in the documentation the
branch added, which neither the scoped ACKs nor the gate could have caught.

# How to apply

- A readiness report names the independent reviewer and the ACK message id
  that covers the full diff at the exact head SHA. Without both, the branch is
  not ready, whatever else is green.
- Keep three facts apart: a scoped ACK says one part was reviewed, a green
  gate says the tests passed on those bytes, and a full-diff ACK says the
  change was reviewed. Only the last makes a branch reviewable-complete.
- An ACK at an earlier head does not cover a later one; check the head the ACK
  names against the head being sent, as in
  [resolve full review anchors before integration](/coordinator/resolve-review-anchors-before-integration.md).

This is the readiness side of the
[evidence and reproduction standard](/aweb-expert/decisions/evidence-and-reproduction-standard.md):
an ACK states what it verified, so a scoped ACK cannot be read as a full one.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-testing-servers,
2026-11-18; notes/gate-lessons-2026-11-12.md (item 12). The coordinator's catch
and the documentation finding of the later review are the source's report.
