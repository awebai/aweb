---
type: Lesson
title: A flake fix must keep the design contract
description: A green flaky ordering test proves only the ordering it asserts; before moving where a side effect happens to fix it, read the component's design contract in docs/design and pin that contract in a real test, because the cheapest ordering point can satisfy the test and break the contract.
tags: [lesson, testing, flaky-tests, contracts, review]
timestamp: 2026-11-27
---

A flaky test of the CLI's handoff loopback asserted that the callback listener
is closed once `Wait` returns. The first fix moved the close into `Wait`, the
cheapest point whose return is ordered after it, and the test went green
deterministically. The tests and tooling reviewer returned that fix twice. The
handoff wire design says the listener closes after the first accepted callback.
Between the callback and `Wait`, the CLI publishes the page and opens the
browser, so the moved close left the listener open through a window the
contract closes.

The fix that held puts everything in order in the callback handler: flush the
page, close the listener, then hand over the code. `Wait`'s return is still
ordered after the close, and the contract holds whether or not `Wait` has
started. Contract tests against a real listener were committed first and were
red on the earlier code 3 of 3, then green with the fix.

The same review found a second gap the flaky test could not show. In Go,
`net/http`'s `Server.Close` closes only the listeners that `Serve` has
registered. A listener the type opened but `Serve` has not yet taken stays
open, so a type that owns a listener must close that socket itself.

# How to apply

- When a fix changes where a side effect happens (a close, a flush, a publish, a
  release), grep `docs/design` for the component and read its stated contract
  before choosing the new point.
- Treat a passing flaky test as proof of the one ordering it asserts, nothing
  more. Choose the point that satisfies the test and the documented contract
  together.
- Write the contract as its own test against the real resource, shown red
  before the fix and green after, instead of learning it from a review return.
- When a type owns a listener or another resource that a library may never have
  registered, close it in the type's own close path.

This is the reproduction rule of the
[evidence and reproduction standard](/aweb-expert/decisions/evidence-and-reproduction-standard.md)
applied to the fix's other side: the documented contract is an existing
consumer of the behaviour, as in
[review a change against its existing consumers](/aweb-expert/lessons/review-a-change-against-its-existing-consumers.md).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-release-flakes, 2026-11-27;
notes/read-the-design-contract-before-moving-an-ordering-point.md. Server
release flake aweb-aear: the first fix 5393ff902e was returned at it and again
at 4ee2a88852; contract tests 0bf1c86192, fix cf9d1fc878, ACKed at 54b7d7d821.
The harvester checked the contract sentence in `docs/design/handoff-wire.md` at
main fbfa65f22.
