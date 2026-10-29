---
type: Lesson
title: Frozen vectors need a real consumer
description: Under acmj's frozen-vector policy, ordinary consumer tests carry design acceptance; an unused hypothesis matrix adds a parallel specification without proving runtime behavior.
tags: [lesson, conformance, vectors, testing, simplicity]
timestamp: 2026-10-29
---

The initial aweb-acmj.19 brief requested conformance vectors. A design-only
matrix supplied 92 scenarios in 1,271 lines and a scratch evaluator checked its
decision rows. Independent review required cutting it: no implementation read
it, and evaluating proposed facts could not prove transaction serialization or
binding behavior. Every later prose change would have needed another edit to
keep that second representation consistent.

# How to apply

- Before adding a frozen corpus, establish which real consumer runs it and
  which boundary it proves. Internal consistency is not evidence that the
  runtime enforces the contract.
- Respect the task's admission policy. The acmj ruling allowed new vectors for
  shipped bugs and ordinary implementation tests for the other behavior. That
  scoped freeze does not ban shared known-answer fixtures for every new
  protocol; a later proposal must justify itself under the then-current policy.
- A brief can request unnecessary weight. Get the deliverable explicitly
  corrected rather than retaining unused artifacts or silently dropping it.
- Keep transaction acceptance with the actual consumer: both lock orders,
  rollback without proof consumption and retry after stop need the effect
  transaction. A truth table or provenance check cannot substitute for them.

This adds an admission question to [shared vectors prove only what they pin](/aweb-protocol-expert/lessons/shared-vectors-prove-only-what-they-pin.md):
first establish why a shared fixture should exist; then examine what its bytes
and consumers prove. It does not weaken the existing corpus or its checks.

# Provenance

Manual harvest on 2026-10-29 from `aweb-protocol-expert-acmj-binding`, notes
`frozen-vectors-need-a-real-consumer.md` and `okf-proposal.md`, task aweb-acmj.19.
The reviewer required removal and the coordinator corrected the brief. Final
contract `docs/human-channel-binding.md:271–286`, authored at
`0618263546f09696f8362a443a41eb80a21a3f6a` and landed at
`053ff87bd6f8834fe19df614438a5eaeec71341a`, assigns acceptance to ordinary
consumer tests and lands no new vector or matrix.
