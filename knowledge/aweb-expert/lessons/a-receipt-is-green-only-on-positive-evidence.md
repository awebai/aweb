---
type: Lesson
title: A receipt is green only on positive evidence, judged in the right order
description: When a gate runs someone else's procedure and writes a receipt, list every route by which the run could read green without its evidence and make each one a red test before the first run; eight such routes cost six review rounds on the servers rehearsal path.
tags: [lesson, verification, gate, receipts, testing, vm-gate]
timestamp: 2026-11-27
---

When the VM gate runs a procedure it does not own (a servers install
rehearsal, a CI job's steps) and writes a receipt, the receipt is only as good
as the ways it can be green without the evidence. On `vm-gate run --project
servers` those ways were found one review round at a time, over six rounds.
Each of these is a route to a false green:

1. **A red control judged by its exit alone.** "Nonzero means the intended
   failure" also passes a pull failure, a timeout or a failed cleanup. The
   control names its marker lines, and its raw exit is kept apart from the
   verdict.
2. **A failed teardown under a green exit.** The servers journey prints
   `DOWN FAILED` without changing its exit, so the step must forbid that line
   explicitly.
3. **Evidence that may be absent, or that escapes its base.** Artifacts are
   required unless the spec marks them optional. A kept file must be a regular
   file inside its base after links are resolved, or the receipt can carry a
   file, even a secret, from outside it.
4. **Loose JSON checks.** A wildcard that drops missing leaves passes a record
   with no value, and `0 == False` lets a number pass for `false`. A missing
   value is a failure, and comparisons check types.
5. **Infrastructure judged after the generic nonzero.** A runner or collector
   fault writes the same nonzero exit as a failed rehearsal. Judge
   infrastructure first, or the fault is reported as a red rehearsal.
6. **A digest of a derived document.** A digest of something built from the
   reviewed spec does not bind the reviewed bytes. Ship the reviewed bytes
   verbatim and have the guest check their digest before it runs anything.
7. **A filesystem change before the containment check.**
   `mkdir(parents=True)` ahead of the path check can create directories
   outside the base even when the step is then refused.
8. **Matchers written from the request's prose.** A matcher written from what
   the request says the source prints can reject a real success. On the
   servers journey the `APPS` line carries a suffix, and the `AGENTS` line is
   unreachable on the no-apps path. Write matchers from the strings the pinned
   source actually prints.

# How to apply

- Before the first run of a new receipt path (aweb-cloud is next, then the
  root steps), go through the eight routes above for that path and write a red
  test for each one that applies.
- Prove each fix with a mutation: break it once and see its test go red. Twice
  on the servers path the first test passed for the wrong reason. An
  after-copy check caught an outside write only after the write had happened,
  and an absent-artifact check passed because the file was never created at
  all. Only the mutation showed it.

This is the receipt-path form of
[a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md):
a receipt check that cannot go red when its evidence is missing proves nothing.

**Limit.** No rehearsal has yet run under the launcher. The routes rest on
reviewed fixtures and on reading the pinned servers journey, not on a receipt
from a real run.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-gate-dispatch, 2026-11-27;
notes/rehearsal-receipt-green-only-on-positive-evidence.md. Gate-vms reviews
4f5dc08b, dd5c1619, ea131da7, 3e6a17b3, fc67d01e and 08a18905
(2026-11-26/27). The fixes landed on aweb main at 271b2bd44a (gate vm-0fe0a75a
green), in the `vm-gate` servers commits 0a3c67b3f, e000836dd, 108bcf626 and
271b2bd44. One path so far.
