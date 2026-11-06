---
type: Decision
title: Prove a generic core with two consumers
description: Shared architecture is designed and built against two real consumers at once, so the generic core is validated before review; reusable runtime lives once in the shared library, and existing apps adopt each shared piece as it lands.
timestamp: 2026-10-20
---

The operator's direction, given twice in two lanes. On 2026-10-19, on building
two human-channel platforms together: "my worry is that if we only do one we
may end up with an implementation that will require lots of duplicatikno to
build the second. building two, and making sure that the shared core actually
works for both." On 2026-10-20, pairing a new app lane with an existing one as
co-designers: "the reason i want you and naapps to be working together is that
i want to make sure that the basic architecture that we build works for both.
this will give us a much better chance of building a properly generic
architecture." And: "i do not want repeated code".

## Decision

- A new generic layer is designed with at least two real consumers in the
  room, and built against both before it is called done.
- Reusable app runtime goes into the one shared library; apps do not keep
  copies.
- Existing apps switch to each shared piece as it lands, not after the whole
  library is finished. An app with no owner waits.

The naapp design docs record that a second design consumer exists; this
records why the operator required it.

## Provenance

Harvested 2026-10-25 from the `integrations` coordinator seat (operator turn of
2026-10-19T21:48Z in its session transcript) and the `secrets` coordinator seat
(operator turns of 2026-10-20T03:54Z, 04:08Z and 04:10Z; Claude memory
`naapp-shared-library.md`).
