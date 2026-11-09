---
type: Lesson
title: A signed vector needs its signer first
description: A vector whose signed cases come from the real signer cannot be re-frozen for new acts until the signer and verifier in Go and Python know them, so a "contract and vector" task for an additive signed act is also a signer/verifier change, scoped and approved as an identity-path change from the start.
tags: [lesson, conformance, vectors, owner-act, scoping, cross-language]
timestamp: 2026-11-09
---

The owner-act delivery vector builds every signed case with the real signer,
`owner_act_signing_bytes`, so that each vector byte is what a signer actually
produces. The signer refuses any act outside its own table with `unknown_act`
(Python in `naapp-lib`, and its Go twin in `cli/go/awid/owneract.go`, which is
the authority for `owner-act-v1.json`). When the human-role owner acts were
added to the owner-act/1 contract, the filed follow-up tasks consumed the new
acts but none defined them in the signer. The "contracts and vector" task
stalled at the vector re-freeze.

# How to apply

- Before filing or starting a task that adds a signed act or artifact to a
  contract with a frozen vector, check how the vector's signed cases are
  produced. If they come from the real signer, the task also changes the
  signer and verifier in both languages, plus the vector.
- Scope all of that into one reviewed change when filing, not mid-way. It is
  an identity-path change, so cite the human's ruling that approves it.
- Raise a scope gap with the coordinator before starting the work.

This adds a scoping step to [shared vectors prove only what they pin](/aweb-protocol-expert/lessons/shared-vectors-prove-only-what-they-pin.md)
and [frozen vectors need a real consumer](/aweb-protocol-expert/lessons/frozen-vectors-need-a-real-consumer.md).
The vocabulary the new acts join is a separate decision:
[acts not yet served get their own vocabulary](/aweb-protocol-expert/decisions/acts-not-yet-served-get-their-own-vocabulary.md).

Verified on aweb main 161f02d1f: the delivery vector generator in
`naapp-lib/tests/hooks/` signs with `owner_act_signing_bytes`, and both signers
refuse unknown acts with `unknown_act`. The coordinator ruled the signer work
into the vector task (aweb-acwd.4.1, 2026-11-09), with the human's
identity-path ruling as its authority; that change is on a review branch, not
on main.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-09; notes/signed-vector-refreeze-needs-signer-vocabulary.md.
