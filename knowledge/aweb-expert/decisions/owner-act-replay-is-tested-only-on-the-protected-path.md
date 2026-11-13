---
type: Decision
title: An owner act's exact replay is tested only on the protected path
description: End-to-end tests prove an exact replay of an owner act only through the protected path, where aw keeps the signed request and resends identical bytes that the receiver answers with 409 applied_earlier; a consumer without that path proves one effect from the receiver's own records, and a test-only injector that re-POSTs captured bytes was rejected.
tags: [decision, testing, e2e, owner-acts, protected-operations, idempotency]
timestamp: 2026-11-13
---

Decided by the OSS coordinator on 2026-11-13 for the Secrets end-to-end
lanes. A request to prove an owner-act replay "in every consumer" cannot be
met as written, because only one aw path can replay.

# Decision

- **The protected path carries the replay test.** Through a protected
  service, aw keeps the saved request after a lost answer. A Resume resends
  the identical signed bytes, and the receiver answers
  409 `applied_earlier` with no new effect.
- **The direct path has nothing to replay.** When the owner signs locally
  with the team key in hand (for example, a human-role designate), aw signs
  the act, delivers it once and returns. It keeps no request.
- **A consumer without the protected path proves the effect from the
  receiver's records.** It asserts that the act took exactly one effect, and
  that a refused fresh duplicate leaves those records unchanged. Which
  records prove that is in
  [prove one owner-act effect from the receiver's durable anchors](/aweb-expert/lessons/prove-one-owner-act-effect-from-receiver-anchors.md).

# Rejected

- **A test-only injector** that captures the delivered body at the front and
  re-POSTs it. That path is outside every supported aw command, so passing it
  proves nothing a user can reach.

# Status

Source fact at aweb main f268e6596: in `cli/go/cmd/aw/app_role_cmd.go`,
`runHumanRoleAct` without a protected profile signs with the team key and
calls `deliverOwnerAct` once. Only `runProtectedResume` in
`app_role_protected.go` resends a saved request. The source reports that the
split is implemented in commit 650e0f3bc (`assert_designated`,
`assert_unchanged`, `revoke_once`). That commit is on the deploy-team
branch, not on main at f268e6596.

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-13;
notes/receiver-anchors-for-one-effect.md. The coordinator's decision is the
source's report.
