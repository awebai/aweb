---
type: Decision
title: A recorded event kind follows the act
description: An audit event's kind is fixed by the act that caused it, never by the state the writer finds, so a human-role replace is always APPROVER_REDESIGNATED even when containment or backfill left no current approver; a writer that chose the kind by state is fixed in the writer, and widening the recorder to accept the wrong pairing was rejected. Specified on a review branch, not yet on main.
tags: [decision, audit, receipts, human-role-holders, owner-acts]
timestamp: 2026-11-10
---

**Status (verified 2026-11-10):** specified in
`docs/design/human-role-holders.md`, "What the credential audit retains", at
de9434ce1 on a review branch, not on aweb main. The source reports two
reviewer ACKs; that is agent review, not a human acceptance.

# Decision

- Each owner act pairs with exactly one event kind: `human-role.designate`
  with `APPROVER_DESIGNATED`, `human-credential.replace` with
  `APPROVER_REDESIGNATED`, and `human-role.revoke` with `APPROVER_RETIRED`.
  The recorder refuses any other pairing.
- A replace is always `APPROVER_REDESIGNATED`, whatever the holding's
  approver history. Its previous subject is the holding's latest approver,
  even one containment already retired. It is absent only when the holding
  never had an approver, as after a backfill.

# Rejected

- **Choosing the kind by state.** A writer picked `DESIGNATED` or
  `REDESIGNATED` by whether a current approver existed. When containment or
  a backfill had removed the approver, a replace was recorded as a
  designation, so the audit trail claimed an act that never happened.
- **Widening the recorder to accept replace with `DESIGNATED`.** It makes the
  wrong writer pass and makes the pairing check meaningless. The fix belongs
  in the writer.

# How to apply

When a writer's event kind depends on a lookup, check whether the kind
describes the act or the state. An audit event records what was done; state
it finds goes in the event's fields (here, the previous subject or its
absence), never in its kind. When a recorder check fails, fix the caller
before relaxing the check.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-10; notes/human-role-audit-identifiers.md.
The pairing and replace rules were checked in the design text at de9434ce1.
The rejected writer and recorder change come from the source note.
