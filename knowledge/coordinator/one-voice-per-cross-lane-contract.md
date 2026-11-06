---
type: Lesson
title: One voice per cross-lane contract
description: When two coordinators can both rule on a shared contract, the lane that owns the artifact issues the single instruction, rulings wait until every owner has answered, crossed rulings are settled synchronously with one mail naming every superseded message, and implementers hold rather than choose.
timestamp: 2026-10-21
---

On 2026-10-20 two coordinators and the security reviewer ruled on the same
cross-lane contracts by mail. Installation ordering flipped four times in under
an hour (epoch, generation-only, epoch, generation-only); attestation rulings
crossed four times; a helper's placement flipped three times, each side
deferring to the other's latest mail. One implementer refused to build until a
single mail named both sides' message ids. A coordinator also ruled on a
forwarded proof while other owners were still answering, and had to supersede
itself when the simpler equivalent arrived; on 2026-10-21 it did the same after
asking two owners for a joint answer and acting on their first two.

## How to apply

- The lane that owns the artifact instructs the author. The other coordinator
  sends its view to that lane, not to the author.
- For a contract crossing lane boundaries, wait until every owner (and the
  security reviewer where it applies) has answered, then send one ruling to all
  of them. If you asked owners to settle between them, wait for their joint
  answer.
- Before re-ruling something another coordinator touched, read their latest
  mail on it; if the rulings may be crossing, settle it synchronously first.
- The settling mail names every superseded message id and goes once to every
  implementer. Implementers hold rather than pick between crossed rulings.
- A field in another lane's registry is that lane's to represent: state the
  requirement (for example "ordering is total and survives uninstall"), not the
  representation.
- For reversible, near-equal choices, rule once and say so; when mails cross,
  adopt what the implementer is building and say "no further changes".

This extends [converged decisions stay frozen](../aweb-expert/lessons/converged-decisions-stay-frozen.md)
from one coordinator's reversals to several coordinators ruling at once.

## Provenance

Harvested 2026-10-25 from the `naapps` coordinator seat (notes
`crossed-rulings.md`, `single-instruction-with-secrets.md`) and the `secrets`
coordinator seat (note `settle-before-ruling.md`).
