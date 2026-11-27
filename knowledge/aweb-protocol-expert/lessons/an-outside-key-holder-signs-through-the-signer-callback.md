---
type: Lesson
title: An outside key holder signs online through the signer callback
description: controller_request awaits a checked signature for every role before it sends once, so routing one role's ControllerSigner callback to a separately authorised outside signer keeps that key out of the holder with no SDK change; only a detached or offline ceremony, with a proof collected in advance, needs a new preparation and submission seam.
tags: [lesson, awid, controller-signing, custody, sdk, design]
timestamp: 2026-11-27
---

While designing custody for a hosted service, the designer read that the SDK
chooses the request timestamp and concluded that a new controller key held
outside the service could not sign a `namespace_rotate`. Review refuted it.
That conclusion holds only for a key that must sign in advance. An online
outside signer works with the SDK as it is.

`controller_request` in `awid/src/awid/registry.py` validates every role's
signing context first. It then awaits `checked_controller_signature` for each
role in turn, and sends the request once after all of them. The signer is a
`ControllerSigner` callback (`awid/src/awid/controller_signing.py`). It
receives the typed `ControllerSigningContext`, and its answer is verified
against that role's did:key before use. For `namespace_rotate` the roles are
`controller` and `new_controller`. The adapter can route the `new_controller`
callback to an outside signer that is authorised separately. That signer gets
the typed context and answers within the freshness window. Its private key
never enters the holder.

# How to apply

- "Held elsewhere" means the holder has no local access to the private key.
  It does not exclude that key from a request the holder sends.
- Before calling a custody requirement an SDK gap, ask whether a role's
  callback could be routed to the party that holds the key.
- Only a detached or offline ceremony needs new SDK surface: one where the
  proof is collected before the request is assembled. That needs a
  preparation and submission seam, because the SDK fixes the timestamp
  itself at send time.

A holder that signs this way still has to reconcile writes whose answer was
lost: see [whether a resend is safe and what an earlier attempt did are separate questions](/aweb-protocol-expert/lessons/resend-safety-is-not-settlement.md).

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-pilot-custody, 2026-11-27; notes/sdk-namespace-rotate-needs-in-call-new-key.md.
The design is reviewed against source and not built. The reviewer ran the
DB-free SDK tests from an OSS export. The harvester checked the per-role
signing loop and the callback check at aweb main 39b3f0911.
