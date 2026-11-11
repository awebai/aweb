---
type: Decision
title: Customer servers use ordinary team membership
description: A customer-operated server joins its team with an ordinary member certificate issued by the team controller; a separate server identity kind and an agent-authentication restriction were withdrawn because no named requirement needs authority narrower than membership.
tags: [decision, teams, certificates, membership, authorization]
timestamp: 2026-11-10
---

Accepted on 2026-11-10. The operator gave a simplicity direction, and the
protocol ruling was simplified in response and authorised for implementation.
Both were relayed to this soul by the coordinator; the acceptance is
**source-reported** (relayed mail, not a record a reviewer can read).

# Decision

A server operated by the customer for its own team is an ordinary team member.
The team controller issues it an ordinary member certificate, under the same
controller-only issuance as every other certificate
([team certificates are controller-only](/aweb-protocol-expert/decisions/team-certificates-are-controller-only.md)).
Its authority is ordinary membership, including acting as that member on aweb.
No new issuer and no new credential type is authorised.

# Why

In the supported customer journey the operator already holds the team
controller key, can issue ordinary members at will, and operates the server
that carries the team's traffic. A narrower credential would bound nothing the
operator could not already do. A separate kind would add verification work and
compatibility obligations toward released consumers that do not know the kind
([released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md)),
without meeting a required authority boundary.

# Rejected

- **A server identity kind.** Proposed and withdrawn: extra verification and
  old-consumer compatibility work with no boundary it is needed for.
- **An agent-authentication restriction on the server's membership.** Withdrawn
  for the same reason.

# Limits

- This is not a universal rule that every server gets full membership. It
  covers the operator-controlled customer server only.
- Do not describe such a member as read-only because its current use is
  registry reads. Its authority is ordinary membership, whatever it uses today.

# Reopen condition

A named, supported actor that needs authority narrower than ordinary
membership. Do not reintroduce a server kind or an authentication restriction
as a standalone improvement.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-gate-vm, 2026-11-10; notes/ordinary-server-membership.md.
