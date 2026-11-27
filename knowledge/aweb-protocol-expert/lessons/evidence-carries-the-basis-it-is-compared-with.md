---
type: Lesson
title: Network evidence carries the basis it is compared with
description: Evidence fetched outside locks must carry the local pins it will be compared with, and the gate re-checks them after the last lock wait; a changed basis refuses without freezing and refetches, or our own promotion committed during the wait turns an unexpired observation into a false takeover.
tags: [lesson, authority, freshness, concurrency, custody]
timestamp: 2026-11-27
---

[Evidence freshness must survive lock waits](/aweb-protocol-expert/lessons/evidence-freshness-survives-lock-waits.md)
says to fetch remote evidence before taking locks and to check its expiry after
the wait. That is necessary but not enough. Freshness is not the only property a
lock wait can break: the local record the evidence will be compared with can
move too.

A signer reads team key A from the registry while our record says A, then
waits on a lock. Meanwhile another transaction confirms our own rotation and
promotes B. The observation "registry says A" is still unexpired, but our record
now says B. A plain "registry differs from record" check then freezes the
organisation on our own legitimate change.

# How to apply

- Read the local pins before the fetch, outside locks: for example the
  controller and epoch, and the key row's id, generation and did:key. The
  evidence object carries them.
- After the last lock wait, compare the locked record with those pins first. A
  changed basis refuses without freezing, and the caller refetches. Only an
  observation taken against an unchanged basis may freeze.
- "Our own rotation landed, so no freeze" is an exemption, and it needs proof:
  that we dispatched the attempt (it reached the dispatching state), the exact
  successor (for a namespace, the rotated epoch derived from the recorded
  sequence), and a live authorising row. A matching staged key with no dispatch
  is an anomaly, and it freezes.
- Re-check that proof after the final wait, for every decision that relies on
  it, not only the first. In the reviewed design the signing gate had it, but
  the exception for DNS being ahead of the registry, and the promotion step, had
  not applied the row-liveness check until a second review.
- A freeze or fence decided after a request was signed must also be checked at
  the transport, before the dispatching state is consumed.
- Persist a freeze in a fresh transaction that takes the row FOR UPDATE, never
  by upgrading a lock already held. Two holders of a shared row lock that each
  try to upgrade deadlock on each other.

The same "recheck after every blocking wait" rule appears in
[lock order in authority and approval transactions](/aweb-expert/lessons/lock-order-in-authority-and-approval-transactions.md).
Naming which two values a freeze compares is
[a freeze rule names both sides of its comparison](/aweb-protocol-expert/lessons/a-freeze-rule-names-both-sides-of-its-comparison.md).

# Status

Design-level only: a hosted custody design gained these rules over three
review rounds and the corrected design was accepted by both reviewers on
2026-11-27. No implementation has run these gates yet.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-pilot-custody, 2026-11-27; notes/an-observation-is-about-the-record-it-was-taken-against.md.
The design is hosted, so it is described generically here; its document,
commits and reviewer messages are not cited.
