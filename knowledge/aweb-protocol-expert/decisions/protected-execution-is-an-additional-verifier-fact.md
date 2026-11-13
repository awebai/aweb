---
type: Decision
title: Protected execution is an additional verifier fact
description: A team explicitly cut over to protected execution keeps its controller authorization and additionally requires a detached attestation from an isolated protected executor, because a controller signature alone cannot prove how the key was used. Approved design, not implemented or activated.
tags: [decision, authority, custody, attestation, teams, contracts]
timestamp: 2026-11-13
---

**Acceptance:** the operator approved this narrow, opt-in verifier extension
and the revision-2 design for implementation on 2026-11-13. The source reported
the approval as relayed by the coordinator; the harvester could not read that
record, so it is **source-reported**.

**Status:** an approved design direction, not implemented, deployed or
activated. Exact implementation and contract-text review, native acceptance and
the explicit cutover of each team remain separate steps. The governing contract,
`docs/human-assurance-contract.md`, is to be amended together with the
implementation.

# Decision

A team marked for protected execution still requires its existing controller
authorization, and additionally requires a detached attestation from the
protected executor, signed under a distinct service key held in isolation.
Teams not marked keep released behavior unchanged. A team becomes marked only
by an explicit cutover; nothing opts a team in silently.

This refines [team certificates are controller-only](/aweb-protocol-expert/decisions/team-certificates-are-controller-only.md)
and does not replace it. The controller remains the issuer and a necessary
authority; the attestation is a second fact about how the act was executed. It
is not issuer-or-holder membership authority, and approval of the design does
not authorize activation for any particular deployment.

# Why a second fact

A certificate or owner act signed by a controller cannot tell protected
execution apart from a raw-key signature made by anyone else holding the same
key. Custody policy therefore cannot be enforced remotely by a label, a client
profile or the existing signature. Do not infer from a valid controller
signature that the act ran in a protected executor; the verifier needs an
independently protected trust fact.

# Rejected

An online signer-receipt lookup at every effect. It would make every consumer
perform a new authenticated lookup and bring signer reachability, lookup
authority, and transport and discovery concerns into every effect. A detached
proof keeps existing signed artifact formats and needs no such lookup; the
current registry binding evidence is still required alongside it. Replacing the
detached proof with an online receipt dependency reopens this tradeoff and
needs a new ruling.

# Ordering constraint

Retained local signing authorization is separate from remote application: a
proof the remote side requires to admit a write cannot depend on that write
having already been committed.

# Guarantee change

The earlier acceptance promise of an unchanged wire and unchanged local
bring-your-own-team behavior is amended only for explicitly cut-over teams, on
the recorded ruling, as
[accepted guarantees change only by ruling](/aweb-protocol-expert/lessons/accepted-guarantees-change-only-by-ruling.md)
requires. For every other team it stands.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-security-fixes, 2026-11-13; notes/protected-execution-is-an-additional-verifier-fact.md.
