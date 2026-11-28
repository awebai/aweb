---
type: Lesson
title: An expected value comes from the declaration, not the code under test
description: When a test drops a pinned literal for a set or structural comparison, build the expected value from an independent source (the declared inventory, a frozen vector or the producer's real output); deriving it from the function under test makes the assertion compare that function with itself.
tags: [lesson, testing, review, verification]
timestamp: 2026-11-27
---

Turning pinned literals into behaviour tests is a gain only if the new
expected value has a source of its own. A test that asks the code under test
what the answer should be, and then checks the code under test against it,
stays green whatever that code does.

Two cases from one review, 2026-11-27:

- **Qualification cases.** Pinned counts (66 required, 62 passed) were
  replaced by set equalities. The expected set was read from the
  qualification function's own `required_agent_cases`, the same output the
  test then checked. Dropping a required case from qualification kept both
  tests green. The fix builds the expected set from the declared pairs (by
  kind and mode) and the declared controls only.
- **Toolchain audit.** A Go image audit took "every version mentioned in the
  file" as the image's pin. A stale `ARG` agreed with `go.mod` while the build
  stage used another compiler. The value compared must be the effective
  declaration: what the build actually resolves to, not anything the file
  happens to mention.

Both passed a green run and a first review. Neither looks wrong on the page:
the tautology is visible only by asking where the expected value came from.

# How to apply

- When you remove a literal from an assertion, name the independent source
  the expected value now comes from: the declared inventory, a frozen vector,
  or the real output of the producer (not of the consumer under test).
- If the only available source is the code under test, the assertion has
  become tautological. Keep the literal, or find the declaration; do not call
  the rewrite a behaviour test.
- In review, trace each expected value in a rewritten test back to its origin
  before accepting it. Then show the test red by removing one declared item
  from the code under test
  ([a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)).

The same principle, seen from acceptance against an external service, is
[acceptance must exercise the claimed operation](/coordinator/acceptance-must-exercise-the-claimed-operation.md):
a fixture that copies an implementation constant proves only internal
consistency.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-contracts, 2026-11-27;
notes/expected-values-come-from-the-declaration.md. Review return 1863b3e7;
fixes fe0ffb4322 (qualification set built from the declared pairs and
controls) and f87228394c (Go audit pin), on the contracts task branch at
harvest time.
