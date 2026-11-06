---
type: Decision
title: Tests exercise the real authority
description: Mocks are acceptable only rarely and almost never in end-to-end tests; a test must run the component that decides the result, the suite should stay under an hour, and code or tests left unused by a change are deleted in that change.
tags: [decision, testing, mocks, e2e, cleanup]
timestamp: 2026-10-20
---

Direction from the operator for the testing epic, relayed by the OSS
coordinator. On 2026-10-19: "mocks are only acceptable in rare cases, almost
never for e2e tests. brittle tests are a problem. there is no reason why our
test suite should take more than an hour to run." On 2026-10-20: "i only want
the code and tests that we need, not more. if the previous attempts are not
being used and can be removed we need to do so."

# Decision

- A test exercises the authority that decides its result. A fabricated
  registry response cannot show that the real services agree; a replaced callee
  cannot show that the real one accepts what its caller passes.
- When a mock is replaced with the real service, the fake, helper or fixture it
  leaves unused is deleted in the same change. A test that only tests a mock or
  the harness is deleted, not rewritten.
- Before deleting, confirm nothing calls it: Makefile, CI, compose files, docs,
  test collection.
- Suite time is a design constraint. The inventory found the main costs in
  repeated binary builds and per-fixture database setup, not in the number of
  tests.

# Example

Contact-tool registration tests swapped in a permissive implementation; they
observed arguments but could not see that the real implementation rejected
three keywords the registration passed, a TypeError on every production call.
Only a request through the actually mounted app reproduced it. The scope of
that green stays narrow: one origin and no federation transport, so it is not
evidence of cross-origin delivery.

Related: [acceptance must exercise the claimed operation](/coordinator/acceptance-must-exercise-the-claimed-operation.md).

# Provenance

Harvested 2026-10-25 from seats `aweb-protocol-expert-awid-service-bypass`
(coordinator 9a28511f and d37e4c6e; inventory report) and
`aweb-protocol-expert-contacts-only` (note
`exercise-the-real-registration-boundary.md`).
