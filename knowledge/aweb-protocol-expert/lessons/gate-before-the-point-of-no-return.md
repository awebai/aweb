---
type: Lesson
title: Gate before the point of no return
description: Availability and authorization gates belong on admission and on the last step before an irreversible effect; once bytes are sent or a credential issued, the record of that consequence commits in the same transaction and fails only on its own write. A "stricter" condition that gates the record afterwards strands the effect.
tags: [lesson, hooks, audit, design, review]
timestamp: 2026-10-23
---

Two corrections in one day while designing the secrets naapp's lifecycle hooks.

- The designer proposed gating a results hook on audit-target availability. The
  coordinator corrected it: gating it on a target or a backlog would mean a
  stale log target strands a request that was already sent.
- A security review added a separately gated governance event for storing an
  already-issued upstream credential. It sounded stricter, but it would have
  split one accepted atomic receipt into two hooks and could have stranded a
  credential already issued upstream when audit availability changed. The
  designer checked it against the contract's one-effect, one-hook and
  atomic-capture clauses; the reviewer withdrew it and the coordinator kept the
  original boundary.

# How to apply

- Find the effect's point of no return: bytes sent, credential issued, money
  moved. Gates for availability, backlog and approval go before it.
- After it, the record of the consequence commits atomically with the effect's
  own transaction and fails closed only on that local write.
- For any proposed refusal, ask what it would leave behind if it fired after
  the point of no return.
- A review ACK that adds a condition does not settle a conflict with the
  accepted contract: put the concrete conflict to the contract's owners instead
  of implementing a contradiction because it is phrased as extra safety.

This is a case of [review every site on both axes](/aweb-expert/lessons/review-every-site-on-both-axes.md)
at the structurally different, already-attempted effect.

# Provenance

Harvested 2026-10-25 from seat `aweb-protocol-expert-secrets-design` (note
`reviewer-safety-conditions-can-change-the-contract.md`; coordinator e93f7f7f
and 0d27d9e6, withdrawal 4190de2e).
