---
type: Lesson
title: A round-trip listing proves only that the mapping was followed
description: When a data move's source-side listing goes through the same mapping code as the import, equal listings prove the import followed the mapping, not that the mapping is right; the PR states that limit, the independent verifier reads the mapping against its numbered rulings, and each ruling gets its own test against a real source.
tags: [lesson, data-migration, review, verification, testing]
timestamp: 2026-11-27
---

A data move is often checked by making one canonical listing of the source
and one of the imported rows, then comparing them byte for byte. A raw export
cannot list the same way as the app's rows unless the export side also goes
through the mapping. So the source listing uses the same mapping code as the
import, and the comparison cannot tell a wrong mapping from a right one.

The comparison is still worth having. It catches writes that differ from the
mapping: editing one staged row made it fail. But a reviewer who treats a
byte-identical listing as proof that the move is right has checked nothing
about the rulings that the mapping encodes.

# How to apply

- The PR says what the comparison proves: that the import followed the
  mapping, not that the mapping is correct.
- The independent verifier reads the mapping against the numbered rulings it
  is meant to implement, rather than relying on the listings.
- Each ruling gets its own test against a real source, not only the
  round-trip.
- Before citing any comparison, ask which wrong outcomes it can tell apart.
  This refines [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md):
  a comparison is evidence only for what it can tell apart.

Limits: a review practice from one data move. The verifier's rulings on that
move confirmed it; no second move has tested it yet.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-tasks-move, 2026-11-27;
notes/round-trip-listing-proves-only-the-mapping-was-followed.md. naapp PR 65
(board move): the author's fit questions stated the limit, and the verifier's
rulings answered that the verifier reads the mapping itself.
