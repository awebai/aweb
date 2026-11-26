---
type: Lesson
title: A full gate of an unlanded head takes it as the guest's main
description: The full candidate gate refuses a head that is not on the guest's origin/main, so a gate that runs before its commit lands prepares the source in branch scope (the head as the guest's main) and checks on the controller that real main is in the head's history; launcher tests that fake the machine never meet that refusal.
tags: [lesson, gate, release, vm-gate, testing]
timestamp: 2026-11-25
---

`scripts/candidate-docker-gate.sh` refuses a full gate (no stage list) unless
the source head S is an ancestor of the guest's `origin/main`. What that
`origin/main` is depends on how vm-gate prepares the source:

- **Train scope** freezes the guest's main at real main. A head that is not
  yet on main is refused before any stage runs.
- **Branch scope** freezes the guest's main at S itself. This is how the joint
  release job's aweb suite has always run.

A release gate whose commit lands only after the gate therefore prepares S in
branch scope. That alone would let a head that is not a fast-forward of main
pass the gate. So the controller checks, before the guest boots, that real
main is in S's history. S can then land unchanged, and the gate's evidence
still belongs to the commit that lands.

The first real run of aweb's new release path used train scope. It ran for
about 40 minutes and was then refused with "source SHA is not on the
synchronized origin/main history". The launcher's own tests had faked the
machine, so they never reached the real gate script's admission checks.

# How to apply

- Choose the source scope deliberately for any gate of a head that lands
  afterwards. Use branch scope, plus the controller-side ancestry check.
  Record the scope in the receipt, as the release gate does.
- Tests that fake the machine prove the launcher's logic, not what the
  guest's real scripts accept. Before the first real run of a new launcher
  path, read the gate script's own refusals and check the path against each
  of them.

The elimination route for the release path is in code: vm-gate's release
project prepares S in branch scope, and its tests assert the scope. A new
launcher path gets no such guard until it is written.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-gate-dispatch, 2026-11-25;
notes/guest-main-must-be-the-unlanded-head.md. Refused run vm-ee6fd0a0; fixed
in aweb 2adb76c46e. The next run reached every stage, and the release run
vm-e6ea6ce5 was green before aweb 1.27.55 was published. One occurrence.
