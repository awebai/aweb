---
type: Decision
title: Swarm permissions are explicit grants
description: Responsibility ancestry (endorsement) and explicit resource-owner grants to a defined swarm compose at admission, so spawned descendants can work autonomously without per-worker grants and without inheriting authority from ancestry; ordinary identities are reused, Cloud is optional, and there is no mandatory steward identity primitive.
timestamp: 2026-11-09
---

Accepted by the operator on 2026-11-09, in the `servers` coordinator session,
after the recommendation of explicit resource grants to defined swarms
(keeping individual and app-role grants): "this is correct. let's go ahead.
start by discussing it with aweb coordinator". The operator also accepted
recursive endorsement where the person understands that it covers spawned
descendants. Acceptance is **source-reported** (session; recorded on task
`aweb-acwd` and relayed by mail to the aweb coordinator), not an independently
published record.

## Decision

- **Responsibility uses existing identities.** Ordinary identities and
  certificates carry responsibility ancestry. Endorsing a spawned subtree says
  who answers for it; it is not itself permission on any resource.
- **Permission comes from the resource owner.** An explicit grant selects the
  authorized swarm or subtree and the operations, including future
  descendants when the owner deliberately grants that. Individual and app-role
  grants remain.
- **Admission composes both.** A request is admitted only with the required
  current endorsement and a matching grant. Withdrawal of either disables the
  dependent access.
- **Independent withdrawal reuses a registered deployment identity.** No new
  steward identity type or service is mandatory. "Steward" is at most a
  deployment role; resident custody services and grant seats are operating
  arrangements, not a second protocol primitive.
- **Cloud is optional.** It may host or hold custody, but the
  customer-operated path must stand on OSS functionality.

## Why

- Repeating grants for every transient worker makes useful autonomous
  spawning impractical.
- Inferring permissions from ancestry alone would hand descendants authority
  that resource owners never approved.
- Explicit swarm targeting allows automation while keeping scope and
  withdrawal with the resource owner.
- A shared nickname for a host convenience must not become a protocol concept.

## Rejected

- Per-worker manual grants as the only workflow.
- Permissions inherited from endorsement or spawn ancestry.
- A mandatory steward identity type or service.

## Limits

This is an architecture direction only. It approves no encoding, schema or
implementation, asserts no release readiness and authorizes no customer
access. Local-to-registered identity conversion, exact endorsement
confirmation and authoritative policy enforcement still need bounded
implementation contracts, and existing independent and security review
applies; protocol encodings go to protocol review. Changing this direction
needs the operator's acceptance, per
[scope belongs to the operator](scope-belongs-to-the-operator.md). It applies
the separation in
[preserve capability boundaries through adapter changes](preserve-capability-boundaries-through-adapter-changes.md):
authority to act is never inferred from a neighbouring capability.

## Provenance

Evidence: OKF proposal from coordinator/servers, 2026-11-09;
notes/swarm-endorsement-and-permissions-direction.md.
