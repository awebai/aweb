---
type: Decision
title: Compose one working flow before polishing parts
description: The operator's direction of 2026-11-12 for the protected owner-act work is one end-to-end flow working on composed code before any part is polished; reviews block only on correctness or security, and style, naming, lint baselines and non-security corner cases are filed as P3.
tags: [decision, direction, review, integration, owner-acts]
timestamp: 2026-11-12
---

Direction from the operator on 2026-11-12, relayed to the seats by the OSS
coordinator (aweb 27081a50). Acceptance is **source-reported** (relay
27081a50, as reported by the source; the harvester could not read it). The
operator's point: the team had many polished parts that did not work
together. Make everything work first; corner cases, details and style come
after.

The trigger: parts of the protected round trip were reviewed separately and
kept failing when composed. Lane iterations 1 to 11 found only integration
bugs. Polishing each part was not converging on a working system.

# Decision

- **The milestone is one flow on the real composed code**: the owner-acts
  round-trip lane. aw requests a human-role revoke, a person approves it with
  a passkey in a browser, the server signs it, and aw shows the result.
- **Next in priority** is landing and releasing what works.
- **Reviews block only on correctness or security.** Style, naming, doc
  wording, lint baselines and non-security corner cases are filed as P3 and
  never block integration.
- **Each owner makes its part work inside the joined round trip** and fixes
  what the round trip exposes. Parts are not polished on their own.
- The round trip runs on its own dedicated VM and iterates there, without
  waiting for shared placement.

# How to apply

When building or reviewing in this area, ask first whether the change moves
the composed flow forward. A finding that is not about correctness or
security becomes a P3 task, not a NACK.

This narrows the blocking bar further than
[review blocks only on realistic failures](/aweb-expert/decisions/review-blocks-only-on-realistic-failures.md),
for the protected round-trip work. It does not change the evidence a verdict
needs ([evidence and reproduction standard](/aweb-expert/decisions/evidence-and-reproduction-standard.md)).
The direction is tied to this milestone. Revisit it once the round trip is
proven and released.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-12;
notes/composition-first-direction.md.
