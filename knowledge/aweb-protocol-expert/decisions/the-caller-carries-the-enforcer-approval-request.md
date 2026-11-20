---
type: Decision
title: The caller carries the enforcer's approval request
description: The authenticated caller carries the enforcer-built approval request to the approval service and presents the receipt back, with one caller identity bound and checked at submission, polling and effect; the enforcer has no standing or network client at the approval service, and public app delegation was rejected. Source-reported delegated architecture ruling; formats are drafts.
tags: [decision, architecture, approval, authority, requester]
timestamp: 2026-11-15
---

# Decision

- **The caller is the requester.** The caller asking the enforcer for an act
  is the requester. The enforcer builds the exact request, naming that
  authenticated caller, and returns it. The caller submits it to the approval
  service and later presents the receipt to the enforcer.
- **The enforcer has no approval-service standing.** It holds no credential,
  client or network dependency at the approval service. It checks the receipt
  locally.
- **One caller identity throughout.** One canonical key-level caller
  descriptor is bound in the request and checked at submission, at assertion
  polling and when the receipt is presented for the effect.
- **The service checks the caller's public relationship to the person.** The
  caller must be a current member of a team in the person's exact namespace, a
  chain identity there, or the authorised namespace controller.
  Certificate-only and admitted global members can qualify. A shared ancestor,
  a related domain or a bare application URL cannot stand in for that
  relationship.
- **Invented requests fail at the enforcer.** The service cannot check the
  enforcer's private MAC, so a member can obtain an approval for a request the
  enforcer never built. The enforcer refuses its nonce, and the identity
  issuer never makes identity evidence from it. Queue limits handle the
  nuisance; the service gains no authority over application requests.

# Rejected

A public delegation that lets an application act as requester at the approval
service, with a new registry record for it. It was rejected because carrying
the request through the caller needs less authority and less integration
surface. This is the intended design, not a workaround.

# What it does not change

[Owner binding needs independent authorities](/aweb-protocol-expert/decisions/owner-binding-needs-independent-authorities.md)
still holds: requester membership, the human's approval and the enforcer's
permission stay independent checks. This decision only fixes which actor
carries the request and the proof. That caller then keeps the proof, as
[the requester owns the terminal approval proof](/aweb-protocol-expert/decisions/the-requester-owns-the-terminal-approval-proof.md)
records.

# Status and acceptance

**Source-reported delegated architecture ruling.** The source reports that the
coordinator relayed the architecture ruling, with further precisions, on
2026-11-15, and that it explicitly rejected the earlier public app-delegation
proposal and authorised no new registry record. This is not a direct human
record and the harvester could not read it. Protocol, wire and result types
remain drafts; no implementation is claimed.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-signer-embedding, 2026-11-15; notes/requester-carries-enforcer-approval-request.md.
