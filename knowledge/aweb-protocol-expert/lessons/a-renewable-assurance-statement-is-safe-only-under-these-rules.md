---
type: Lesson
title: A renewable assurance statement is safe only under these rules
description: An issuer's renewable assurance claim (hardware backing, a grade, personhood) must rest on the exact credential that completed the issuer's own confirmation, take eligibility and expiry from one evaluation, compute any public deadline only from inputs every subject shares, prove a superseded signer independently, and, for delegated signers, use immutable epoch-bound grants whose force comes from registry commit times and never count retrospectively.
tags: [lesson, review, design, assurance, personhood, delegation, privacy]
timestamp: 2026-11-28
---

Each rule below was forced by a review finding on the hardware-backed
personhood design. Together they are the checklist for designing or reviewing
any renewable issuer statement.

# The basis

- **The basis is the credential that itself proved.** It is the exact
  credential that completed the issuer-built confirmation in the existing
  pending ceremony: prepare, confirm against the pending binding, commit,
  then publish. Being listed in a signed (even pending) binding is not enough.
  Otherwise a mixed roster lets a passkey's confirmation carry a hardware
  claim. This applies
  [vary independent assurance dimensions](/aweb-protocol-expert/lessons/vary-independent-assurance-dimensions.md):
  the authorising fact is that credential's own proof.

# Eligibility and expiry

- **One evaluation, one `issued_at`.** Eligibility and expiry come from the
  same evaluation, with a deadline check at publication time. A digest
  compare alone misses a cutoff crossed while both digests stay unchanged.
- **Cap at known withdrawals.** A renewal never extends past a withdrawal
  date the issuer already holds. Signing compares against the snapshot
  installation it was evaluated under.
- **A public deadline uses only shared inputs.** When a model- or
  batch-specific withdrawal date would set the deadline, suppress the
  statement rather than publish the date. Together with the public snapshot
  digest, that date identifies the model.
- **"Superseded issuer" needs proof.** That verdict requires independently
  verified predecessor evidence. Otherwise a bad signature and a rotated
  issuer are indistinguishable, and the reading must be `signature_invalid`.

# Delegated signers

- **A grant is immutable and bound to its creating epoch**, and is never
  re-granted to the same key.
- **A grant's in-force interval comes from authenticated registry commit
  times carried in the read**, never from signed clock fields.
- **The designation that bounds what a delegate may back must itself require
  current eligibility**, or the delegate inherits a stale basis.
- **Order observations by request sequence**: send a nonce read after the
  other response arrives. Never order by timestamps of equal precision.
- **Preserved-at-T is not validated-at-T.** Historical policy evidence for T
  does not show the claim existed at T. Keep the two readings separate, and
  never count delegated signatures retrospectively.

Where these rules are applied:
[hardware backing is a renewable issuer statement](/aweb-protocol-expert/decisions/hardware-backing-is-a-renewable-issuer-statement.md)
and [the issuer personhood condition](/aweb-protocol-expert/decisions/issuer-personhood-condition-is-a-namespace-record.md).

# Status

All rules are design-level: no implementation or test vector has run them.
They are in `docs/design/hardware-backed-personhood.md` on the two
`agents/aweb-protocol-expert-adyx13-hw-personhood` branches, not on main. The
review rounds that forced them are source-reported.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-adyx13-hw-personhood, 2026-11-28; notes/basis-must-be-the-credential-that-proved.md.
