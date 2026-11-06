---
type: Decision
title: Required invariants belong on the fix
description: A reproduction only has to be red on released code with the reported failure; when a plausible wrong fix could turn it green by breaking a security invariant, assertions of that invariant and a refusal control are required on the fix head, not on the reproduction.
timestamp: 2026-10-23
---

Decided by the integrations coordinator on 2026-10-23, correcting its own
instruction of an hour earlier. A fix was to let agents reach humans by alias
over chat. The coordinator first demanded, at reproduction review, assertions
that linking or same-team membership never bypass the recipient's inbound
policy or add contacts. Under the review friction rules the reviewer judged
them unnecessary to prove the reported failure, which was correct. But a fix
that made the reproduction green by bypassing contacts-only policy would have
shipped an egress hole behind a green test.

## Decision

- The reproduction proves the reported user-visible failure on released code,
  nothing more.
- If a plausible wrong fix could make it green by violating a security
  invariant, the invariant's assertions and a refusal control are required on
  the fix head.

## Rejected

Demanding the invariant assertions before accepting the reproduction: it mixes
proving the failure with constraining the fix.

This refines the realistic-failure bar in
[review blocks only on realistic failures](../aweb-expert/decisions/review-blocks-only-on-realistic-failures.md)
and the reproduction rule in
[evidence and reproduction standard](../aweb-expert/decisions/evidence-and-reproduction-standard.md).

## Provenance

Harvested 2026-10-25 from the `integrations` coordinator seat (note
`contacts-only-binds-channels.md`; decision mail 703e0159; session transcript
of 2026-10-23T22:15Z).
