---
type: Lesson
title: Attribute test egress per test and bisect by tree
description: An egress receipt names no tests; record the client process and its parents on each denial (pid, executable, working directory, never arguments), let a Go test's t.TempDir in the working directory name the test, then find the introducing commit by exporting each tree with git archive, running that test under the guard with services unset and docker refused, and bisecting the first-parent line by denial count.
tags: [lesson, testing, egress, bisect, attribution]
timestamp: 2026-11-20
---

An egress denial arrives as one receipt for a whole package run, with no test
names. This method turned 111 anonymous denials into named tests and one
introducing commit.

# Find which test

- On each denial, record the client process and its parents: pid, executable
  and working directory. Never record arguments.
- A Go test's `t.TempDir()` in the client's working directory names the test.
  This attributes egress from a child `aw` process to the test that started
  it.

# Find which change

- Export each commit's tree with `git archive`. Don't check it out.
- Run the named test under the guard with services unset and `docker` refused
  on the `PATH`, and count denials.
- Bisect the composition's first-parent line by denial count.

This found the source on a composed branch rather than on main. A
checkout-based bisect in a shared worktree would have been slower and riskier.

# Example

On 2026-11-20 (local development runs, not gate evidence), the R7 composition
gave 111 denials, all to `api.awid.ai:443`, all attributed. One test gave 0
denials at main c42ad775a and 42 on R2. The first-parent bisect landed on
ee45af6ed9, which added a registry read to creation. The test-side resolution
is [cmd/aw tests name a refusing registry](../decisions/cmd-aw-tests-name-a-refusing-registry.md).

# Limits and elimination route

- The guard sees HTTP(S) proxy traffic, not DNS. A lookup leaves no denial.
- Per-process attribution belongs in the guard itself. It is commit
  40fbd86b84 to `scripts/test-egress/native.py` on a review branch, awaiting
  the operator's acknowledgement and not on main at c42ad775a. Once it lands,
  the guard records the processes, and this lesson keeps the reading of a
  test's temporary directory and the tree-export bisect.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-aw-tests-1,
2026-11-20; notes/creation-key-read-falls-back-to-the-production-registry.md.
The harvester verified that 40fbd86b84 exists on a review branch and is not on
main.
