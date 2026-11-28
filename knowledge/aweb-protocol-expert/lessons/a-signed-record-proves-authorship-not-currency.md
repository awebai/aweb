---
type: Lesson
title: A signed record proves its author, not that it is current
description: Evidence for a gate that freezes on a changed record needs a registry-signed, nonce-bound, short-lived observation of the current state, with signed absence kept apart from unavailability and one digest throughout; a consumer that is not the authority needs its own revocable, single-subject read grant, and the read reports a differing value instead of refusing it.
tags: [lesson, authority, freshness, custody, registry, review]
timestamp: 2026-11-28
---

A custody or authority gate that freezes when a record differs from its pin,
and activates when it is equal, must know that the record it sees is the
current one. The author's signature on the record does not show that. It
proves who wrote the record. A cache, a lagging replica or a signer being
withdrawn can still serve revision n after revision n+1 exists, with a valid
signature. The gate could then activate against a replayed record, or freeze
on stale evidence.

# Rejected

According to the source's review, a first draft of the standing organisation
record format, which predates the committed design document, had both flaws:

- **Currency.** The organisation head was read by "public exact lookup" and
  carried only the namespace controller's signature.
- **Read right.** The team incarnation, a private fact, was readable only by
  the controller. A hosted custody gate needed to check that fact, but it is
  not the controller, so it could not check it at all.

# What the gate needs

- **A current read.** The registry signs an observation of its committed state
  under a pinned read key. The observation binds the consumer's nonce and is
  short-lived (at most 30 seconds in the reviewed format). It carries state,
  revision and digest.
- **Signed absence, apart from unavailability.** If the registry cannot
  establish the current state, it returns no observation at all, never a
  signed absence. Otherwise "refuse without freezing" and "verified change,
  freeze" collapse into one answer.
- **One digest throughout.** The observation, the chain's `previous` link and
  the consumer's pin all name the record by the same digest.
- **A read right of its own.** A consumer that is not the authority (here, a
  hosted service reading a private fact about a team it does not control)
  needs a grant that the controller issues. The grant is revocable, scoped to
  one subject, bound to the reader's key, and confers no other access.
- **A differing value, not a refused read.** When the value differs from what
  the reader expects, the response reports it (`different`, or a signed
  `absent`). That differing value is exactly what the gate must see in order
  to freeze, so refusing the read would hide it.
- **Read-key rotation refuses.** Rotating the read key makes older
  observations unverifiable. That refuses and the consumer fetches again; it
  never freezes.

# How to apply

Before accepting any new input to a freezing gate, ask two questions, and
require both answers in the first draft:

1. What proves this evidence current, as opposed to authentic?
2. Who may read it, given that the consumer may not be the authority?

Expiry of evidence across a lock wait is a separate rule, in
[evidence freshness must survive lock waits](/aweb-protocol-expert/lessons/evidence-freshness-survives-lock-waits.md).
That lesson assumes the evidence was current when observed. This one says
what makes it current at all.

# Status

Design-level only. The corrected rules are in section 4 of
`docs/design/standing-organisation-records.md` on the aweb `one-organisation`
branch (commits 1a2ada79b and 1f87cc653, merged there at 53a8abbb7). They are
not on aweb main, and no implementation has run them yet. The hosted custody
design that consumes them is described generically here. Its document and
commits are not cited.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-pilot-custody, 2026-11-28; notes/a-signed-record-proves-authorship-not-currency.md.
The harvester checked the section 4 rules against the `one-organisation`
branch. The proposal names one design as its only evidence.
