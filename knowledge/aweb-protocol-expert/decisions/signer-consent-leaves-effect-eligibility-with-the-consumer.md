---
type: Decision
title: Human approval leaves effect eligibility with the enforcer
description: Human consent to an exact act does not establish target or effect eligibility; each enforcer verifies its own receipt binding and approver rule and checks the current facts it owns, without copying application policy into the approval service.
tags: [decision, consent, authority, approvals, enforcement]
timestamp: 2026-11-15
---

**Acceptance:** the original consent-versus-eligibility distinction came from
coordinator rulings for aweb-adbm. The source seat reports that Juan approved
the replacement adcl architecture on 2026-11-15, relayed by the coordinator in
0e337824-8070-48e0-809e-c8f58cf0f12a. The coordinator's cleanup ruling, relayed
in f0ef1eeb-7ff2-4bda-9fb1-f91fb9016320, directs this amendment. These are
**source-reported relays**, not independently verified human-authored records.

**Status:** this amended proposal follows the agreed adcl architecture and
approval protocol. It does not claim an implementation, qualification or
release. The earlier proposal's combined-signer delivery mechanism is
superseded; its authority distinction remains.

# Decision

- **Approval is consent, not resource authority.** A person's approval of an
  exact act does not establish that its target or effect is currently eligible.
- **Each enforcer verifies its own approval requirement.** It checks the
  receipt for its exact act, enforcer, nonce and deadline under its own rule
  about who may approve. A fixed current-owner rule is not implied for every
  application or operation.
- **The consumer keeps the facts it owns.** Target human kind, current
  membership, role holding and other application-local eligibility remain
  checks of the real consuming application at its effect boundary. The key
  holder is an enforcer for its own controller operations, not a replacement
  source of another application's eligibility policy.
- **The approval service does not duplicate application policy.** It does
  not establish application-local target or effect eligibility by taking a
  second snapshot of the consumer's state.

# Rejected

Moving a consumer's eligibility checks into the approval service as a second
observation port. That snapshot is weaker than the consumer's own current
check, duplicates policy that can drift, and leaves the consumer needing to
check its facts again when applying the effect. An authentic approval must
not become an early return around those checks.

# Why

This preserves the independent-authority distinction in
[owner binding needs independent authorities](/aweb-protocol-expert/decisions/owner-binding-needs-independent-authorities.md):
consent and resource authority are different facts, checked by their proper
owners. It does not supersede that decision. Related:
[admission is not the effect transaction](/aweb-protocol-expert/lessons/admission-is-not-the-effect-transaction.md)
and [vary independent assurance dimensions](/aweb-protocol-expert/lessons/vary-independent-assurance-dimensions.md).

# How to apply

- Keep application eligibility checks with the application, even after an
  approval receipt verifies.
- Use the agreed approval protocol for receipt and auxiliary-material binding;
  this decision adds no delivery-digest format, schema-freeze promise or
  condition on whether vectors may change.
- Follow the current approval protocol and application's user flow for refusal
  feedback. The old requirement that every consumer result appears on the
  combined signer's approval page is not carried forward by this decision.

Evidence: the source seat's original OKF proposal and backing note
notes/signer-consent-and-consumer-eligibility.md; its adcl cleanup disposition
9f5abbb7-50bf-4913-a616-00bb7845fc50 and the coordinator-directed source amendment.
