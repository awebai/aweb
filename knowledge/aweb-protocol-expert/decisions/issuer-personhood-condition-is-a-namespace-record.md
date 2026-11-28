---
type: Decision
title: The issuer personhood condition is a controller-signed namespace record
description: Whether an issuer requires hardware backing for kind=human is published as awid.issuer-personhood/1, a namespace-controller-signed record in the standing-organisation-record pattern (chain, publication under the namespace write lock, tombstones, signed nonce-bound currentness read, separate history read); absent means never published, it covers the exact namespace only, and hosting never selects the issuer. Juan chose this option (B); reviewed design, not implemented.
tags: [decision, identity, personhood, registry, federation, assurance]
timestamp: 2026-11-28
---

An issuer's condition on what its `kind=human` certificate means (for
example, "vouched only with hardware backing") is published as a
controller-signed namespace record, `awid.issuer-personhood/1`. It reuses the
standing-organisation-record pattern: the chain, publication under the
namespace write lock, tombstones, and the signed, nonce-bound currentness
read.

- `absent` means no revision was ever published. The gap after a controller
  rotation reads unavailable, never `absent`, and an `absent` after a pinned
  revision is a conflict that reads unavailable.
- History is a separate read bound to `at`.
- A revision is in force from its registry commit time, not from signed clock
  fields.
- The record applies to the exact namespace only. A hosting provider's origin
  or domain never selects the issuer.
- For a covered issuer, a missing or unavailable condition never yields the
  stronger reading.

This settles the approval-service rule "no new registry record" as scoped to
approval, custody and requester state. The reviewer accepted that scope
ruling.

# Why

A closed certificate body has no field for the condition, and a condition
carried in holder-presented evidence fails open (see
[an issuer condition needs a carrier the holder cannot suppress](/aweb-protocol-expert/lessons/an-issuer-condition-needs-a-carrier-the-holder-cannot-suppress.md)).
The record gives verifiers an authenticated answer the holder cannot omit,
with currentness and history semantics already designed and reviewed.

# Rejected carriers

- **A new key in the `_awid` TXT record.** Released aw refuses unknown keys
  (see [the `_awid` TXT record is closed](/aweb-protocol-expert/lessons/the-awid-txt-record-is-closed-for-released-clients.md)).
- **A separate DNS name.** A forged NXDOMAIN reads as "no condition", and DNS
  keeps no history.
- **A well-known file.** No signed currentness or history.
- **Holder-presented evidence.** The holder can leave it out.
- **Per-issuer rules in verifiers.** One operator would govern the contract.
- **A separate sign-in namespace.** A second identity surface for one issuer.

# Status

Juan chose option B over A (issue `kind=human` only after hardware). The
choice is source-reported, relayed by the approval-service seat. Reviewed
design, not implemented, and not on main. The design is on branch
`agents/aweb-protocol-expert-adyx13-hw-personhood-option-b`, ACKed by the
reviewer at 0fa69da3a083 after three NACK rounds. The harvester confirmed
that tip, that it builds on `one-organisation` at 1521e103904e (not on main),
and the record name, `absent` meaning and hosting rule in its text. The
custody of a hosted delegated grant key is still open with Juan. Relates to
[hardware backing is a renewable issuer statement](/aweb-protocol-expert/decisions/hardware-backing-is-a-renewable-issuer-statement.md).

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-adyx13-hw-personhood, 2026-11-28; notes/issuer-conditions-need-a-carrier.md. The note predates Juan's ruling and recommends option A; the choice of B and the rejected carriers come from the proposal.
