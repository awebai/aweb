---
type: Decision
title: Evidence and reproduction standard
description: Every claim names its evidence or is labelled a hypothesis; a fix starts from a committed, reviewed reproduction of the reported failure on released code; an ACK separates what the reviewer verified from what it took on trust; wrong attempts are cleaned up completely.
tags: [decision, review, evidence, debugging, quality]
timestamp: 2026-10-23
---

Team rules written and broadcast to every seat by the OSS coordinator on
2026-10-23, binding at once, on the operator's direction: "you really need to
step up the quality of the work of the team. this is crucial to get right."
The wording of the rules is the coordinator's; the coordinator confirmed on
2026-10-25 that nothing has superseded them (a later "no more quality rules or
gates" forbids new rules, it does not repeal these). The trigger was a production
fault in mail send. A cause derived from reading source was relayed as fact; a
fix was built for it, reviewed, ACKed and offered for release; production data
then showed the failure happened earlier and elsewhere. The reviewing ACKs had
checked a test of a neighbouring case, not the reported direction.

# Decision

1. **Evidence.** Every claim in mail, a task or a review names its evidence:
   production data (the query and who ran it), a test at an exact SHA (command
   and output), or the word "hypothesis". A hypothesis is never relayed as a
   cause. Times come from the clock. A source reading is "source fact
   (file:line at tag)" or a hypothesis, never the cause.
2. **Reproduction first.** A bug fix starts from a reproduction of the observed
   failure in its production shape: same identity types, direction, inputs and
   released code, red on the release and green only with the fix. Reproduce the
   real client's request sequence, including its fallbacks and the requests it
   omits; a plausible model can pass neighbouring tests and still be wrong.
3. **ACK scope.** An ACK states what the reviewer verified personally and what
   it took on trust. Reviewing a fix includes checking that its test reproduces
   the reported failure, not a neighbouring one. The first review question on
   any fix is "show me the reported failure red on the released code".
4. **No debt.** No code beyond the reproduced failure or the accepted spec. A
   wrong attempt is cleaned up completely (remote branch, queued runs, scratch)
   and the cleanup is reported.

Refinement by the OSS coordinator the same day: the separate review of a
reproduction before any fix is written applies while the cause is not yet
established. When the cause is established from the exact released source, the
reproduction commit and the fix commit go on one branch, red at the test commit
and green at the fix, and are reviewed together.

# Consequences

- An exclusion is a causal claim too. "Not my code path", read from a diff,
  needs the same evidence as naming a cause; a later successful controlled
  invocation does not explain an earlier refusal. The coordinator accepted a
  seat's self-correction on exactly this point as "the standard".
- Reviewer agreement that a design is safe does not establish that it fixes the
  reported failure.
- This makes binding, as team rules, the lessons in
  [reproduce before attributing a regression](/aweb-expert/lessons/reproduce-before-attributing-a-regression.md)
  and [a live result outranks a theory](/aweb-expert/lessons/a-live-result-outranks-a-theory.md).
  How much evidence blocks a landing is set by
  [review blocks only on realistic failures](/aweb-expert/decisions/review-blocks-only-on-realistic-failures.md).

The same relay carried a fifth rule about release ordering against a hosted
consumer; it is hosted release practice and is not recorded in this base.

# Provenance

Harvested 2026-10-25 from seat `aweb-expert-security-review-2` (notes
`team-quality-rules-2026-10-23.md`, `label-hypotheses-and-check-against-data.md`;
coordinator mail f46329f7), corroborated by the same relay in
`aweb-expert-naapps-verify` (6b1ecbcb), `aweb-expert-pages-requests` (d5978071),
`aweb-protocol-expert-awid-service-bypass` (c679b6c4, refinement 0916d9ce, note
`reproduce-client-sequence-before-identity-repair.md`) and
`aweb-protocol-expert-contacts-only` (note
`source-attribution-is-not-a-causal-exclusion.md`, coordinator 22cccca7).
Attribution confirmed by the OSS coordinator in f8d89364 (2026-10-25).
