---
type: Decision
title: Approval provenance is an additive signer statement
description: A human-approved artifact needs a public, DNS-rooted signer statement naming the exact artifact, the approver identifier, the operation and the time, verifiable without any coordination server; it states credential user verification only as the signer's attestation, and its absence never invalidates existing identities. Accepted requirement; mechanism not yet designed.
tags: [decision, approvals, provenance, passkeys, attestation, identity, contracts]
timestamp: 2026-11-14
---

**Acceptance:** the operator required this on 2026-11-14; the requirement was
relayed to the source seat by the coordinator, with an independent reviewer
response. The harvester cannot read those records, so the acceptance is
**source-reported**.

**Status:** an accepted requirement awaiting one reviewed design. No
mechanism, implementation, native test or rollout exists or is claimed.
Registry-first shipment does not wait for this design.

# Decision

- **Approval provenance beside the artifact.** A human-approved artifact gets a
  public statement, signed by the signer service, over the exact artifact
  digest, naming the approving human's identifier, the operation and the time.
  The signer's authority is anchored in the namespace's independently
  discovered DNS authority, so a validator outside any coordination server can
  verify it.
- **Honest about what it attests.** The statement reports registered-credential
  user verification as the signer operator's account. It does not establish
  physical human presence, hardware properties or a credential signature over
  the act.
- **Additive.** Existing identities without a statement remain valid and
  display the absence honestly. Existing callers' registry answers are
  unchanged.
- **Scope of the first step.** The initial act families are human issuance,
  root endorsement and human-approved team operations. Messages and unattended
  acts are excluded.
- **Exclusions.** The record carries identifiers, never names or contact
  details. It is fetched by exact artifact and operation reference, with no
  listing API, and needs a specified revocation and erasure tombstone
  lifecycle. Fetch and verification are on demand and add no warm-request
  registry or SQL work.

# Why

Issuer authority and approval provenance are different assurances. A v1 ID or
team certificate signature establishes issuer authority under its existing
rules, not whether a signer or a passkey was involved
(`docs/human-assurance-contract.md`, "What a remote verifier can establish").
The protected-effect receipts the registry keeps today are read only by exact
retained header possession and are not a public, independently verifiable
statement (`awid/src/awid/protected_receipts.py`, `read_receipt`;
`docs/protected-team-boundary.md`, the `aweb.protected-effect` payload).

# How to apply

- Do not infer passkey use from an issuer signature.
- Do not claim physical-human or hardware proof from a signer attestation.
- Do not replace current authorization or effect-application evidence with
  approval history. Human approval evidence, mutable current authorization and
  confirmed application are separate facts. Whether immutable admission
  evidence could replace current membership lookups, coordinated cutover,
  generations or effect-confirmation receipts is an open question, not an
  accepted removal; neither is the proposed scope freeze.
- The stronger credential-signed form remains possible but is not the present
  target. This statement does not substitute for the independent
  credential-signature guarantee kept in
  [accepted guarantees change only by ruling](/aweb-protocol-expert/lessons/accepted-guarantees-change-only-by-ruling.md),
  and does not relax other applications' independent-proof promises; it names
  its weaker trust boundary instead.

This applies [vary independent assurance dimensions](/aweb-protocol-expert/lessons/vary-independent-assurance-dimensions.md):
who approved, who issued and what is currently authorized are separate inputs.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-security-fixes, 2026-11-14; notes/portable-approval-provenance.md.
The prior public model was checked at aweb 16e6862afa (on main):
`docs/human-assurance-contract.md:51-62`,
`awid/src/awid/protected_receipts.py:62-108` and
`docs/protected-team-boundary.md:112-121`.
