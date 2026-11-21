---
type: Lesson
title: Recovery across commands preserves the original field omission
description: When one CLI command recovers a request another command submitted, it replays the values and omissions recorded at the first submission, not its own fresh-creation defaults, while still checking explicit choices against the original context; test the documented recovery entry point in a fresh process so flag state from earlier calls cannot alter the replay.
tags: [lesson, recovery, idempotency, cli, testing]
timestamp: 2026-11-21
---

A recovery that keeps the signing key and request ID can still change the
request. A roster setup request submitted with no agent type. After a
simulated loss of the response, the documented recovery path ran native
`aw init`, which defaults the agent type for fresh creation. The replayed
request now carried a field the original omitted. The exact-context guard
correctly refused it, and the admission was stranded.

The recovery contract already requires the original selection: a retained
partial refuses any other agent type, among other fields, and recovery
retains the original key, request ID and registration arguments
(`docs/hosted-global-bootstrap.md` on main at d8d0bfa1e).

# How to apply

- **Replay what was recorded, including what was absent.** A recovery command
  takes the retained request's values and omissions. Its own fresh-creation
  defaults apply only to fresh creation.
- **Keep checking explicit choices.** An operator-supplied value at recovery
  still goes through the exact original-context check; only an absent value
  falls back to the retained one.
- **Test across entry points.** A replay test is most informative when the
  first submission and the documented recovery use different commands. Same
  key and request ID are not enough to assert; assert the replayed request
  matches the original.
- **Run the recovery command in its own process.** An in-process test that
  runs several commands can leak flag values from an earlier call (here, a
  role flag) into the recovery. Run the documented recovery as a fresh
  process and assert the same DID and the exact certificate.

This applies
[tests exercise the real authority](/aweb-protocol-expert/decisions/tests-exercise-the-real-authority.md)
to the choice of entry points: the recovery test runs the command an
operator would run, as that operator would run it.

**Status (verified 2026-11-21):** on a review branch, not on main at
d8d0bfa1e. Commit 7c9c5a77e keeps the saved agent type during API-key init
recovery when the operator supplies none; 42a461e46 runs the roster recovery
in a fresh CLI process.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-signer-membership, 2026-11-21; notes/recovery-preserves-original-field-omission.md.
