---
type: Decision
title: Signer consent leaves effect eligibility with the consumer
description: An owner-act signer attests the current owner's user-verified approval of the exact act and a digest-bound immutable delivery; target and effect eligibility stay with the real consuming app under its own final fences, a duplicate app-state observation in the signer was rejected, and the approving owner sees the consumer's refusal and next action on the approval page. Accepted design, not implemented.
tags: [decision, owner-acts, signer, consent, authority, approvals, transactions]
timestamp: 2026-11-14
---

**Acceptance:** coordinator rulings for task aweb-adbm. The harvester cannot
read them, so they are **source-reported**. No human acceptance is claimed.

**Status:** accepted design for the next extension of owner-act signing
(auxiliary material such as a membership certificate). It is not
implemented, qualified or landed.

# Decision

- **What the signer attests.** The current owner approved this exact act with
  user verification, and the delivery the consumer receives is immutable and
  bound by digest to that approval. That is consent, not resource authority.
- **What the consumer keeps.** Target eligibility (for example the target's
  human kind, current membership and existing role holding) and effect
  eligibility are checked by the real consuming app against its own current
  facts, under the fences of its effect transaction.
- **Auxiliary material is bound, not re-modelled.** The existing credential
  and contact commitments stay checked against the signed artifact. Other
  auxiliary material, including a membership certificate the app verifies at
  effect time, is bound by its exact bytes through the covered request and
  delivery digests. No new owner-act subject member and no refrozen vectors
  follow from adding it.
- **A consumer refusal is a normal outcome.** The approving owner sees the
  consumer's refusal reason and next action on the same approval page. An
  agent-readable receipt alone does not close the owner's workflow.

# Rejected

A second observation port in the signer that reads the consuming app's state
before signing. It would be a weaker snapshot than the app's own check under
its final fences, and a second implementation of app-local policy that can
drift from the first, while the app must still check its current facts
anyway. Approval and resource authority stay separate.

# Why

This applies
[owner binding needs independent authorities](/aweb-protocol-expert/decisions/owner-binding-needs-independent-authorities.md)
to signer-issued acts. That decision requires independent authority facts to
agree in the effect transaction. This one says which side holds which fact,
so the effect side's facts are not copied into the signing service. It does
not supersede that decision. Related:
[admission is not the effect transaction](/aweb-protocol-expert/lessons/admission-is-not-the-effect-transaction.md)
and [vary independent assurance dimensions](/aweb-protocol-expert/lessons/vary-independent-assurance-dimensions.md).

# How to apply

- When extending what a signer covers, bind new material by digest. Do not
  add an eligibility check that duplicates the consumer's.
- Do not read a signer attestation as proof that the target or effect is
  eligible. The consumer decides that at commit.
- When a consumer refuses a signed act, show its reason and next action to
  the owner where they approved.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-signer-membership, 2026-11-14;
notes/signer-consent-and-consumer-eligibility.md.
