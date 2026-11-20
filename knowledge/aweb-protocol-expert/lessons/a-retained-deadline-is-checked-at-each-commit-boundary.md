---
type: Lesson
title: A retained deadline is checked at each commit boundary and anchored to a shared clock
description: When an authorized effect spans more than one commit, a deadline check after the last wait runs at each commit boundary, and each boundary has its own refusal outcome; a retained deadline taken from a process-local monotonic clock is never persisted, but anchored to the database clock at admission and compared with that clock.
tags: [lesson, authority, freshness, transactions, secrets]
timestamp: 2026-11-10
---

While specifying the membership-deadline fence for secrets (aweb-acwd.13 and
.16), the first converged rule said one final fence transaction covers
approval consumption, credential release and dispatch. Three reviewers
agreed. It was still wrong, and the error showed only when the rule was
checked against the accepted secrets state machine (`docs/design/secrets.md`
§10.5 and §11.1). That is two commits, not one:

- **Admission** consumes the approval and commits the intent (`admitted`).
  An expired deadline here rolls back with nothing consumed, and an exact
  re-submission recovers.
- **The dispatch or runner-claim fence** opens and releases the credential
  later. An expired deadline here rolls back the effect transaction, but the
  approval was already consumed by the committed admission. The intent closes
  `refused`, and recovery needs a fresh request and, where policy requires
  it, a fresh approval.

Vectors asserting "no approval consumed" for a queued runner claim would have
contradicted §11.1. Moving approval consumption to the claim was rejected,
because it reopens the accepted §10.5 and §11.1.

The same work found a second trap. The shared verifier holds its proof
deadline on a process-local monotonic clock. A queued effect crosses workers,
so that value means nothing in another process, and persisting it silently
extends authority. The deadline is anchored at admission:

1. sample the database `clock_timestamp()` first;
2. compute the smallest remaining original budget, rounded down to the
   persisted precision; a non-positive budget refuses;
3. add it to that earlier timestamp and persist the absolute deadline;
4. compare it against the same database clock at each later checkpoint.

Adding an earlier budget to a later timestamp extends authority and is
forbidden. Queueing may consume the budget; it never extends it.

# How to apply

- Before stating where a deadline check runs, list the effect's actual commit
  boundaries and what each one consumes. Give each boundary its own refusal
  outcome and recovery, and check vectors against the accepted state machine.
- Never persist or share monotonic time. Anchor a retained deadline to the
  database clock at admission and compare it only with that clock.
- The same holds for any retained proof expiry that crosses a commit or a
  worker, for example a launch claim's `exp` or attestation freshness.

This extends [evidence freshness must survive lock waits](/aweb-protocol-expert/lessons/evidence-freshness-survives-lock-waits.md)
from one transaction to effects that span commits and workers, and applies
[gate before the point of no return](/aweb-protocol-expert/lessons/gate-before-the-point-of-no-return.md)
once per boundary.

# Status

Proposed, not accepted. The rule is in `docs/design/selective-membership-inheritance.md`
on the acwd.16 proposal branch (aweb 1c6083660, merging the acwd.13
correction cc5bab679), ACKed by its reviewers but not on main as of this
harvest. The implementation is not commissioned, and the secrets fence does
not yet check membership deadlines.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-10; notes/deadline-checks-follow-commit-boundaries.md.
Checked by the harvester against aweb 1c6083660.
