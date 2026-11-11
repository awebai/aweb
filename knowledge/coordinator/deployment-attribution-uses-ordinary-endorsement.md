---
type: Decision
title: Deployment attribution uses ordinary endorsement
description: A human endorses one ordinary registered deployment root once, through existing issuance and adoption, and that root signs its unattended descendants; protected-resource confirmation is required only where a resource's own policy requires it, never as a prerequisite of ordinary attribution.
timestamp: 2026-11-11
---

Accepted by the operator on 2026-11-11. The acceptance is **source-reported**:
the aweb coordinator relayed it by mail to the `servers` coordinator seat. It
is a relay, not the operator's own record. The operator also asked that the
earlier design be removed from current guidance.

## Decision

- **One ordinary root per deployment.** The deployment's root is an ordinary
  registered identity. A human endorses it once, through the existing issuance
  and adoption path. The root then signs its unattended descendants, with no
  further human step per worker.
- **No special steward design and no blanket pause.** Ordinary attribution
  needs no dedicated steward identity, service or route, and no
  deployment-wide pause state.
- **Protected-resource confirmation stays separate.** A stronger human
  confirmation is required only where the applicable resource policy requires
  it. It is not a universal prerequisite for attributing a deployment's work
  to the human who endorsed it.

## Why

Responsibility ancestry, team membership and resource permission are different
promises. Treating them as one made the approved ordinary spawning path depend
on unrelated, unfinished protected-access machinery. Carrying earlier pause
labels and steward designs forward also contradicted the operator's direction.

## Limits of revocation

The model states its revocation promise plainly rather than adding a cascade
to hide it:

- Revoking the root removes the current ancestry of its dependents. It does not
  remove independent membership or grants, stop work already running, or
  revoke shared harness credentials.
- A local worker can omit ancestry and keep membership-only access, so root
  revocation is not a complete shutdown of the deployment. Ordinary offboarding
  uses the membership and grant controls.

These limits are part of the chosen model, not a request for a new cascading
mechanism.

## Scope

This is a direction, not a claim about deployed behaviour. The canonical
product specification is the customer-agent-servers concept in the private
Bookshelf; its update was routed, not yet placed, when this was accepted.
Implementation detail belongs there and in the repository's contracts, not
here. Independent protected-resource authorization stays distinct, as in
[preserve capability boundaries through adapter changes](/coordinator/preserve-capability-boundaries-through-adapter-changes.md),
and changing this direction needs the operator's acceptance, per
[scope belongs to the operator](/coordinator/scope-belongs-to-the-operator.md).

## Provenance

Evidence: OKF proposal from coordinator/servers, 2026-11-11;
notes/deployment-root-attribution-decision.md.
