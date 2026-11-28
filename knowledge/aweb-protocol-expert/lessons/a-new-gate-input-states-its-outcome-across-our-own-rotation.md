---
type: Lesson
title: A new gate input states its outcome across our own rotation
description: When a gate that freezes on unexpected evidence gains a pinned input, write that input's outcome in steady state, in the DNS-ahead window, after our own rotation lands but before reconciliation, and at promotion, with one test each; the rotation row names the expected successor of every pinned input, not only the key.
tags: [lesson, authority, rotation, design, review, custody]
timestamp: 2026-11-28
---

A custody gate written as "freeze when the evidence differs from the pin" is
right against an outside change and wrong against our own planned rotation.
Our rotation changes the evidence on purpose. If the gate does not say what
that change means, our own cutover either refuses forever or freezes us. A
pin that must verify under the DNS-selected successor also blocks the very
cutover that opens the new epoch.

A hosted custody design made this mistake twice. First the team key froze us
on our own landed rotation, until the gate gained explicit outcomes for it.
Later the design added the organisation head as "verified under the
controller in the open epoch, freeze on difference". Two reviewers returned
it from opposite ends:

- **After our rotation lands**, the head signed in the old epoch no longer
  verifies, so every gate refuses. If the controller republishes the head,
  it differs, and that freezes us.
- **While DNS is ahead of the registry**, requiring the head to verify under
  the DNS-selected successor blocks the cutover itself.

# How to apply

For every new pinned input to a freezing gate (an organisation head, a team
incarnation, a key), write its outcome for four states before writing the
rule:

1. **Steady state.** Evidence that differs from the pin freezes.
2. **DNS ahead of the registry.** Only the exact cutover proceeds, and only
   on predecessor evidence equal to the pin.
3. **Our rotation landed, not yet reconciled.** Evidence equal to the
   successor that the live rotation row names refuses without freezing.
   Anything else still freezes.
4. **Promotion.** The reconciler moves this pin together with the epoch, and
   only with continuity evidence that nothing else about the input changed.
   Moving the pin on the epoch alone would launder an outside change.

The rotation row must name the expected successor of every pinned input, not
only the key; otherwise state 3 has nothing to compare with. Name one test
for each of the four states.

This rule says which outcome each state gets. Re-checking evidence expiry
after a lock wait is
[evidence freshness must survive lock waits](/aweb-protocol-expert/lessons/evidence-freshness-survives-lock-waits.md).

# Status

Design-level only: the corrected hosted design was accepted by both reviewers
on 2026-11-28. No implementation has run these gates yet. This rests on one
design with two occurrences.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-pilot-custody, 2026-11-28; notes/new-gate-evidence-must-cross-our-own-rotation.md.
The design is hosted, so it is described generically here; its document,
commits and reviewer messages are not cited. The continuity condition at
promotion comes from the proposal, which records it as a later review fix;
the backing note does not state it.
