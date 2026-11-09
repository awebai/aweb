---
type: Decision
title: Permission containment follows execution boundaries
description: Operational deployments and soul roles organize work but are not security boundaries; before promising that one worker cannot act with another's authority, the coordinator identifies the actual execution, credential/signing and privileged-invocation separation, and a role check alone does not prove it.
timestamp: 2026-11-09
---

Accepted by the operator on 2026-11-09 ("agree"), in the `servers`
coordinator session, after the seat's explanation of the difference between an
operational deployment and its actual trust boundaries. Acceptance is
**source-reported** (session), not an independently published record. It
replaces the seat's own looser framing of a deployment as a permission
ceiling; that framing was never recorded in this base.

## Decision

- **Deployments and souls are not security boundaries.** A deployment name or
  a soul definition organizes work and prevents mistakes. Neither establishes
  that its workers are contained, and one deployment may contain several
  enforced boundaries.
- **Containment follows actual separation.** Where agents can reach one
  another's signing keys or invoke one another's privileged execution, a
  principal or role distinction between them is not containment against a
  compromised worker.
- **Identify and qualify the boundaries first.** Before allocating sensitive
  permissions or claiming per-worker containment, the coordinator establishes
  which execution, credential/signing and privileged-invocation boundaries
  actually separate the workers, and scopes the claim to them. Existing
  controls are reused first.
- **A role check is not a containment proof.** A client-selected identity
  path, an approved source revision, or a request correctly rejected when
  signed with A's own key shows that role enforcement works. It does not show
  that A cannot obtain B's identity or execution authority.

## Why

Authorization policy protects only as far as a caller cannot select a
stronger authenticated identity or freely invoke its authority. Presenting
organizational roles as isolation would misstate the supported security
model to whoever relies on it.

## Limits

This is a boundary on what the coordinator may claim and how it scopes
delivery. It introduces no permission object, weakens no role enforcement,
approves no particular isolation mechanism or customer test, and authorizes
no customer access. It applies the separation in
[preserve capability boundaries through adapter changes](preserve-capability-boundaries-through-adapter-changes.md)
(identity, runtime and resource authority are distinct responsibilities, not
labels) and the evidence standard in
[acceptance must exercise the claimed operation](acceptance-must-exercise-the-claimed-operation.md).
Changing it needs the operator's acceptance, per
[scope belongs to the operator](scope-belongs-to-the-operator.md).

## Provenance

Evidence: OKF proposal from coordinator/servers, 2026-11-09;
notes/permission-containment-follows-execution-boundaries.md.
