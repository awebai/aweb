---
type: Lesson
title: Environment tests clear the gate lane's exports
description: The aweb gate runners export their own variables (GATE_CPUS, GATE_MEMORY_MIB and more) to everything they start, so a test that spawns a child with the inherited environment and asserts something is absent from it passes on a laptop and fails in the gate; clear the lane's variables in the test's patched environment and reproduce by setting them.
tags: [lesson, gate, testing, environment, subprocess]
timestamp: 2026-11-26
---

The aweb gate's runners export variables of their own, such as `GATE_CPUS`
and `GATE_MEMORY_MIB`, to every process they start. A test that spawns a
child with the inherited environment and then asserts that a variable is
absent from the child's environment passes on a developer machine and fails
in the gate.

This happened to a release test that checks the Cloud gate runs on the host.
The Cloud script set no budget, but the stub `make` the test started saw the
lane's `GATE_CPUS`, and a stacked gate run went red.

# How to apply

- In a test that asserts on a child's environment, clear the gate lane's
  variables inside the test's own patched environment, rather than relying on
  the developer machine not having them.
- Reproduce the gate's condition locally by setting those variables before
  running the test, and see it red before trusting the fix.

The fix in the evidence was made in the test itself. It applies to every test
that asserts on a subprocess's environment, under any CI or gate runner.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-gate-dispatch, 2026-11-26;
notes/tests-must-clear-lane-exports.md. Stacked gate vm-64317eb1
(2026-11-26), test_release; fixed in aweb c788a508db, landed as c3d378917a,
seen red with GATE_CPUS set. One occurrence.
