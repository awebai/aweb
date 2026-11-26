---
type: Lesson
title: A stand-in runs the real receipt code
description: When a command consumes another tool's receipt, its tests should call that tool's real entry point with only the machine faked, so the receipt it reads is in the real format; a hand-written stand-in receipt drifts silently, and a receipt captured from a real run is still owed as a fixture once one exists.
tags: [lesson, testing, release, gate, receipts, stand-ins]
timestamp: 2026-11-25
---

aweb's release command reads the receipt that the VM gate launcher writes. A
hand-written stand-in for the launcher wrote digests as `sha256:<hex>`, where
the launcher writes bare hex. The stand-in and the command agreed with each
other, so the tests were green, and the mismatch with the real launcher
surfaced only in a real gate run, which it cost.

# How to apply

- When a command consumes another tool's receipt or output, make the test
  stand-in call that tool's real entry point and fake only what the test cannot
  run: the machine, the network, the registry. The receipt the command reads is
  then produced by the tool's own admission and receipt code, so a format
  change in the tool breaks the command's tests.
- Do not hand-write the other tool's output in the consumer's tests. A copy of
  a format drifts without any test noticing.
- Running the real code proves the format the tool writes today, not what a
  real machine leaves behind. Once a real run exists, capture its receipt as a
  fixture as well.

Here the elimination route is the test itself: aweb's `scripts/test_release.py`
drives `vm_gate.cli.main` with a fake runtime, so only the machine, PyPI and
GitHub are stand-ins.

Related: [tests exercise the real authority](/aweb-protocol-expert/decisions/tests-exercise-the-real-authority.md)
and [acceptance must exercise the claimed operation](/coordinator/acceptance-must-exercise-the-claimed-operation.md),
which make the same point for services and adapters. This lesson applies it to
a tool boundary inside the repository's own release tooling.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-gate-dispatch, 2026-11-25;
notes/stand-in-runs-the-real-receipt-code.md. Task aweb-adyi step 1. The test
is present at b64035903f, which was on the source's release branch and not yet
on main at harvest. The real-run receipt fixture is not yet captured. One
occurrence.
