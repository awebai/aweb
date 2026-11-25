---
type: Lesson
title: Script break-proofs, and classify a mutation that stays green
description: Prove kept guards with a scripted pass (exact-once match, restore the original bytes, check the tree is clean) rather than by hand; before calling a green mutation a dead guard, try a joint mutation for overlapping guards and look for a missing fixture; a guard the host cannot run is reported as proven only in the gate.
tags: [lesson, testing, mutation, verification]
timestamp: 2026-11-24
---

From the break-proof pass of the aweb test sweep on 2026-11-24, which proved 49
kept guards red.

# Run the pass as a script

Each mutation is a file, an exact old string, a replacement and a test
command. The script expects red, then restores the bytes and checks the tree:

- The old string must match exactly once. Any other count is a setup error,
  not a red.
- The script restores the original bytes itself, then checks that the tree is
  clean. A restore by hand failed once in the sweep: an interactive `cp` alias
  prompted and hung, and a mutation stayed in place.
- Run the narrowest test that exercises the guard. If other tests in the same
  module already fail on this host, a module-level red proves nothing, so run
  the single test or class.
- A guard the local host cannot run (for example one that needs the real
  runner or real Docker) is reported as "proven only in the gate", never as
  proven.

The byte-level traps behind the first two rules are in
[a test result belongs to the bytes that ran](/aweb-expert/lessons/a-test-result-belongs-to-the-bytes-that-ran.md).

# A green mutation is a question

[A harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)
says to classify every non-red. The sweep found two causes of a green mutation
that are not a vacuous guard:

- **Overlapping guards mask a single mutation.** In
  `scripts/check-server-version-bump.sh`, an equality refusal and a
  strictly-greater comparison each catch an unbumped version. Removing either
  one left the test green, and removing both turned it red. Before concluding
  that a guard is untested, or writing a new test for it, mutate the
  overlapping guards together.
- **A green mutation can expose a missing fixture.** Both pi.skills refusals in
  `scripts/npm-exact-publish.sh` could be removed with the lane self-test still
  green, because no fixture reached them. The fix was a fixture flag and one
  refusal case each. After that, each mutation went red (b15c9183b).

Evidence: OKF proposal from aweb-expert/aweb-expert-cleanup-oss, 2026-11-24;
notes/mutation-harness-for-break-proofs.md. Checked by the harvester: the two
overlapping refusals in `require_greater` on aweb main 1378733f0, and commit
b15c9183b on the sweep branch. The count of 49 guards and the hung restore are
source-reported.
