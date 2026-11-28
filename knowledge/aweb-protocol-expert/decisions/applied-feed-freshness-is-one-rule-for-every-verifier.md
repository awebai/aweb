---
type: Decision
title: Applied-feed freshness is one rule for every verifier
description: Every standing-proof verifier enforces the same 30-second applied-feed freshness boundary and signed expiry; when freshness is lost, new admissions relying on that issuer stop until the issuer's complete live prefix is applied, while an already admitted effect may finish. Live subscription and on-demand authenticated range reads are two delivery methods under one conformance suite; a lighter consistency profile and a local maximum statement age were rejected. Operator-ruled; not implemented.
tags: [decision, awid, standing, invalidation, freshness, availability, verifier]
timestamp: 2026-11-28
---

Ruled by the operator on 2026-11-28 for the million-agent architecture
(task aweb-aeal). **Acceptance: source-reported**: the operator's decisions
were relayed through OIC in coordination mail 3d16b7d2 (fail closed, preserve
admitted effects, operate for availability) and d3b15b96 (one verifier
profile, no local maximum statement age, live or on-demand delivery with
common conformance). The harvester cannot read either record. They close two
points that the earlier architecture ruling (7127dd02, portable standing with
one public invalidation feed per registry) left open: verifier behaviour when
the feed is lost, and a lighter verifier profile.

**Status:** accepted direction only. Implementation order, real failover
evidence, conformance tests and scale-gate evidence are still pending.

# Decision

- **One freshness rule.** Every verifier that admits on standing proof
  enforces the same rule: the signed expiry of the standing statement, and a
  30-second bound on the last applied, authenticated feed point of the issuer.
- **Loss fails closed at the applied cut.** When the last applied feed point
  of an issuer reaches the 30-second boundary, the verifier stops new
  admissions that rely on that issuer's standing. Decisions that do not rely
  on that issuer are not affected.
- **Admitted effects finish.** An effect admitted before the boundary may
  complete. The freshness gate applies to admission, not to completion of an
  already admitted effect.
- **Only a live applied point restores service.** Admission resumes only once
  the issuer's complete live prefix is applied. A new transport receipt for
  an old authenticated point does not advance authority.
- **Transport is not authority.** A live subscription and an on-demand
  authenticated range read (catch-up) are two methods of acquiring the same
  committed prefix. On-demand is first class, so a low-traffic verifier can
  avoid idle subscription cost under the same rule. One conformance suite
  checks both methods for gaps, snapshots, age and admission.
- **Issuers operate for availability.** The issuer keeps its heartbeat
  signing and public distribution available, so that an outage is rare. The
  verifier rule does not relax to cover one.

# Rejected

- **Admitting on a stale feed until the statement expires.** Portable
  standing can outlive the removal bound. Admitting fresh effects with a stale
  feed would silently make statement expiry the removal deadline during an
  outage.
- **A lighter consistency profile.** It would give different removal promises
  for the same portable statement, depending on which verifier reads it.
- **A local maximum statement age, or an unsigned proxy receipt.** Neither may
  extend authority during a failure. A verifier cannot configure a longer
  local age limit to keep admitting.

# How to apply

When a policy permits several delivery methods, keep the verified decision
state and its deadline common to all of them, and model transport separately
from authority. Scope an unavailable issuer to the decisions that rely on it,
and separate the admission gate from the completion of an already admitted
effect. This is [gate before the point of no return](/aweb-protocol-expert/lessons/gate-before-the-point-of-no-return.md)
applied to feed freshness. Like
[evidence freshness must survive lock waits](/aweb-protocol-expert/lessons/evidence-freshness-survives-lock-waits.md),
a window never restarts on receipt.

The portable-standing decision that this refines is pending review as
`decisions/portable-standing-with-public-invalidation.md`. Its open points on
feed loss and a lighter verifier profile are answered here.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-coordination, 2026-11-28; notes/feed-loss-fails-closed-at-the-applied-cut.md and notes/feed-transport-does-not-change-verifier-authority.md.
