---
type: Decision
title: A new member on the signer's answers breaks every released aw
description: aw decodes the protected signer's prepare and pending-receipt answers with exact member sets, so a server-side addition needs version negotiation or a proven named-client floor before it is emitted; until then a new fact, such as a suppressed approval notice, is reported through the owner page and the audit, worded "not mailed" or "suppressed", never "deferred".
tags: [decision, compatibility, clients, signer, owner-acts, wire]
timestamp: 2026-11-14
---

Decided on 2026-11-14 while designing the owner approval-notice budget, when
reporting a suppressed notice as a new member of the prepare answer (for
example `notice: deferred`) was considered.

# Why an addition is not additive here

aw's governance client accepts a prepare answer only when its members are
exactly `operation_id`, `handoff_id`, `digest`, `payload` and `expires_at`, and
a pending receipt only when they are exactly `state`, `reason` and
`expires_at`. The security reviewer confirmed these checks in the published
aw-v1.36.59-rc.2 (ruling fbb5129b); they are on main in
`cli/go/internal/handoff/governance.go`.

One extra member therefore turns a successful prepare into a client failure
for every deployed aw. The operation already exists on the signer, and the
resume receives the same answer again, so the client fails in a loop.
[Released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md)
makes additions the safe default for what the server accepts; toward a client
that decodes exact members, an addition the server emits is a narrowing.

# Decision

- No wire change for the notice budget. The signer records the suppression
  (an audit event and a reservation row), and the owner page shows the notice
  as not mailed because it was over the budget. The contract says plainly that
  an agent requester cannot necessarily see this (coordinator decision
  b4ecb2f3).
- A wire addition to these answers needs either explicit version or metadata
  negotiation that keeps the old answer for old clients, or a separately
  authorized named-client floor, with real installs, pins and restarts proven
  before the server emits the new member.
- An earlier floor (`intent_v1`, `upgrade_aw_required`) is not blanket
  permission for another narrowing.
- Notification metadata stays out of the frozen act and its digest.
- A notice that will not be sent is described as "not mailed" or "suppressed",
  never "deferred", unless a later send is actually scheduled.

# Rejected

Adding an optional notice member to the prepare or pending-receipt answer
now: every released aw would refuse the answer.

The elimination route is in the client: aw accepting an optional member is a
separate follow-up, and until a floor that includes it is proven in real
installs the rule above holds.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-14;
notes/aw-governance-wire-is-exact-members.md (task aweb-adbb, D2a). The exact
member checks were re-read on aweb main 03f434b7c. As of the proposal the
notice-budget implementation and its contract wording were on a branch, not
on main.
