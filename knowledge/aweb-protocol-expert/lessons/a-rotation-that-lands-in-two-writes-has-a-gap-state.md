---
type: Lesson
title: A rotation that lands in two registry writes has a gap state the gate must name
description: When our own rotation opens the new controller epoch in one registry write and republishes a pinned record in another, a freezing gate needs a named state between the two, bounded by the live rotation row, in which only a fresh signed absent for the exact successor epoch refuses without freezing and promotion waits for the expected successor record; outside it absence still freezes, and a predecessor-epoch observation is a crossed read that refuses and is refetched unless it is itself authenticated evidence of a change we did not make.
tags: [lesson, authority, rotation, design, review, custody, registry]
timestamp: 2026-11-28
---

A gate that freezes on unexpected evidence usually gets outcomes for our own
planned rotation. Those outcomes are easy to write as if the rotation lands in
one event. It may not. In the standing organisation records design (pilot D2),
the namespace rotation opens the successor controller epoch, and the successor
then republishes the organisation head at the next revision by its own route.
Those are two registry writes. The registry's current read is scoped to the
open epoch, so between the two writes it answers a signed `absent` for the
head in the successor epoch. A committed open namespace with no current record
is exactly what `absent` means.

A hosted custody design treated the landing as one event, so a signed `absent`
froze, and our own planned rotation would have frozen us. The first fix then
went too far the other way. It let the predecessor head count as a current
answer in the successor epoch. Two review rounds caught these, and a third
reviewer added the precedence rule for a crossed record below.

# The gap state

Name the state between the two writes explicitly, as its own state with its
own outcomes. It holds only while all of these hold:

- the live rotation row in exact scope, and for a signed row, one that has
  been dispatched;
- exact DNS on the successor;
- the epoch observed `rotated` to the expected key.

The row's expiry bounds the gap. Without a bound the gap becomes a standing
exemption from the freeze.

**Inside the gap**, only a fresh signed `absent` refuses without freezing. It
must be for that exact successor epoch, under the current trusted read key,
and for the request's nonce. Promotion waits for the expected successor
record.

**Outside the gap**, absence still freezes: in the stable epoch, with no row
or an expired row, or under a successor we did not expect.

# A crossed read is not a second registry answer

Because an observation is scoped to its epoch, the registry cannot answer
"predecessor head, present" for the successor epoch. An observation taken in
the predecessor epoch and compared with the successor epoch is a mismatch
between our observations. It refuses and is refetched. Do not model the gap as
the registry giving two valid answers.

The freeze takes precedence over the refetch, though. If the crossed
observation is itself authenticated evidence of a change we did not make, the
gate freezes.

# Rejected

Proving that the registry publishes the epoch and the head atomically was
rejected. D2 specifies two routes, and atomic publication would be a new
registry promise.

# How to apply

- For each pinned input to a freezing gate, count the registry writes our own
  rotation makes, and name every intermediate state before writing the
  outcomes.
- Bound each intermediate state by something live and expiring, such as the
  rotation row.
- Bind each exemption inside a state to the exact epoch, read key and nonce,
  so that an observation from another state cannot use it.
- Test with a real paused sequence between the writes, and with a crossed-read
  control.

Expiry of evidence across a lock wait is a separate rule, in
[evidence freshness must survive lock waits](/aweb-protocol-expert/lessons/evidence-freshness-survives-lock-waits.md).

# Status

Design-level only. The epoch-scoped current read and the republished head are
in sections 3 and 4 of `docs/design/standing-organisation-records.md` on the
aweb `one-organisation` branch at 53a8abbb7, which is not on aweb main. Both
reviewers accepted the corrected hosted custody design on 2026-11-28. No
implementation has run these gates yet. The lesson rests on one design.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-pilot-custody, 2026-11-28; notes/a-rotation-that-lands-in-two-writes-has-a-gap-state.md.
The harvester checked the epoch scoping, signed absence and head republication
against the design document at 53a8abbb7. The hosted design is described
generically, and its document, commits and reviewer messages are not cited.
The dispatch and exact-DNS conditions and the precedence of the freeze over
the refetch come from the proposal, which records the precedence as a later
review fix. The backing note does not state them.
