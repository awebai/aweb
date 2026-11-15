---
type: Decision
title: Public identity evidence approves its own public act
description: An identity evidence sidecar proving creation, adoption or key transition carries approval of its own complete public identity act; it never reuses, redacts or publishes a receipt for a private application act. Accepted design boundary (source-reported); wire format pending, no implementation.
tags: [decision, identity, approval, privacy, evidence, contracts]
timestamp: 2026-11-15
---

**Acceptance: source-reported.** The source reports that the OSS coordinator
relayed design acceptance of the verifier plan on 2026-11-15, explicitly
confirming this disposition. The harvester could not read that record.

**Status:** an accepted claim boundary, not a frozen wire schema. The exact
commitments and result types await the protocol revision; implementation is
held. No code or run backs it.

# Decision

- Identity evidence that proves an identity's creation, adoption or key
  transition carries an approval of **its own complete public identity act**:
  a separately committed act whose exact bytes are the ones approved and
  published.
- It never **reuses** a receipt approved for a private application act.
- It never **redacts** such a receipt to make it publishable.
- Public sidecars carry no private application resources or rights.

# Why

An approval is checked against exact bytes. Redacting an approved request
changes those bytes, so the redacted form no longer carries a checkable
approval. Publishing the original private act instead keeps the bytes but
exposes resources and rights that are outside the identity claim. A
separately approved public act keeps both guarantees: exact-act verification
and the privacy boundary.

# Rejected

- Treating a signed receipt as safely redactable.
- Publishing a private application's exact act to obtain publicly checkable
  identity evidence.

# Generality

Any portable statement that carries proof of a private operation must
preserve the approved bytes. When the private operation cannot be disclosed,
a separately approved public claim is required.

# Relation to other knowledge

This specializes
[vary independent assurance dimensions](/aweb-protocol-expert/lessons/vary-independent-assurance-dimensions.md)
to the exact-byte approval and privacy boundary; it does not supersede that
lesson or the broader separation of approval, application enforcement and key
custody. Weakening exact-act verification or privacy to fit an implementation
needs the ruling that
[accepted guarantees change only by ruling](/aweb-protocol-expert/lessons/accepted-guarantees-change-only-by-ruling.md)
requires.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-offline-verify, 2026-11-15; notes/public-identity-acts-have-their-own-approvals.md.
The source cites draft 1 of the adcl.5 design (SHA-256
e7dc682e0aae70fe522d640aff4fb9712600d883cc12904f3106f41713c057d6, lines
328-335) as defining the public identity act and its independently checkable
raw assertion. Message identifiers and reviewer names are omitted.
