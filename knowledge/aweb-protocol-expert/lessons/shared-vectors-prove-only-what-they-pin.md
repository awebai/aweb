---
type: Lesson
title: Shared vectors prove only what they pin
description: Check each single-fault negative vector by skipping its own check, probe primitive boundaries independently of the corpus in every language, and run every consumer of a vector change with its own prerequisites and policy inputs; a shared corpus does not by itself make accepted input domains equal.
tags: [lesson, conformance, vectors, cross-language, testing]
timestamp: 2026-10-21
---

Shared conformance vectors are how independent implementations agree. Three
ways they were found to prove less than assumed.

- **Two-fault negatives.** A negative case with two faults passes any verifier
  that refuses it for either reason, so it pins the wrong ordering or no rule at
  all. Hand review of the first draft of a new vector set missed two such cases
  (a malformed id that could also never match the caller; an expiry equal to the
  timestamp that is also expired at a later "now").
- **Accepted domains.** A cross-language review found Python and Go disagreeing
  on timestamp year 0000 while ordinary timestamps passed both; Python's
  `strptime` `%Y` also accepts non-ASCII digits that `fromisoformat` refuses. A
  language library's undocumented acceptance range can become part of the
  protocol by accident.
- **Consumer context.** A new manifest vector passed the Go interpreter and the
  Python reader, then failed other consumers' prerequisites (a reserved-id
  conflict, missing tool scopes), and an explicit policy input in the vectors
  did not reach the runtime adapter.

# How to apply

- Before adding a corpus, apply [frozen vectors need a real consumer](/aweb-protocol-expert/lessons/frozen-vectors-need-a-real-consumer.md):
  justify its existence and identify the implementation that runs it.
- Write a reference verifier from the scheme text, not from the generator. Run
  each negative twice: normally (it must refuse with exactly its code), then
  with only that code's check skipped (it must then verify). Exempt codes that
  stop evaluation by definition (oversize, wrong type).
- Pick primitive boundaries independently of the proposed vectors and pair the
  refused input with the nearest valid value and an ordinary valid control, in
  every language. Put non-ASCII digits where each parser reads them.
- Before handing off a vector change, find every consumer and check both its
  fixture prerequisites and the explicit inputs that must cross its adapter. A
  parser pass alone is not adapter conformance.
- Confirm a red run actually selected the test; a filter that matches nothing
  reports deselections, not a pass.

These refine [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)
for conformance corpora.

# Provenance

Harvested 2026-10-25 from seats `aweb-protocol-expert-agent-activity` (notes
`vector-one-fault-check.md`, `shared-vector-consumer-context.md`),
`aweb-protocol-expert-p0-review` (note
`shared-vectors-need-runtime-boundary-probes.md`; ACK cb13ba1c) and
`aweb-protocol-expert-app-team-api` (note `strptime-unicode-digits.md`).
