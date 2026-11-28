---
type: Lesson
title: Find the recorded form of a relayed decision before designing on it
description: A human decision relayed through agents arrives compressed, and its full form may already be written into a reviewed sibling design. Before designing on it, search the designs of every lane it touches, design from the recorded text, and surface any disagreement for a recorded decision.
tags: [lesson, design, review, coordination]
timestamp: 2026-11-28
---

A human decision about where a service's keys are held reached a protocol
design through two agents as a one-line summary: the keys are held only in the
worker. The design followed the summary and stored the keys as envelope rows in
the database under the worker's key ring, a reasonable reading of it. The same
decision had already been written into a sibling OSS design that another
reviewer had acknowledged (`hardware-backed-personhood.md` at `61f604c623`,
lines 779-790). That record carried two constraints the summary had dropped: the
keys are a `0600` secret file mounted only into the worker, never in the
database, and the watcher reconciles against an out-of-band approved-change
record held by the operator. Coordination returned the design for the mismatch,
and reconciling it to the recorded form took another review round before it
landed with both acknowledgements.

**Why it happens.** Each relay compresses the decision. Whoever first wrote it
into a design kept its full form, and that design may be the closest
authoritative record of the human's words.

# How to apply

When a human decision reaches you relayed, before designing on it:

- search the landed and in-review designs of every lane the decision touches,
  by its date and its subject;
- if one already records it, design from that text and cite it;
- if the recorded text and the relay disagree, surface the difference for a
  recorded decision; do not pick one silently.

This extends [scope belongs to the operator](../../coordinator/scope-belongs-to-the-operator.md),
which checks a relayed scope change against its source, to the design records a
relayed decision may already live in. It is a sibling of
[accepted guarantees change only by ruling](accepted-guarantees-change-only-by-ruling.md):
in both, the recorded text governs until a ruling changes it.

One occurrence so far.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-pilot-custody, 2026-11-28; notes/a-relayed-decision-may-be-recorded-in-full-elsewhere.md.
