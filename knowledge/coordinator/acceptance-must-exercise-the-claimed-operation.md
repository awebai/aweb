---
type: Lesson
title: Acceptance must exercise the claimed operation
description: Use realistic boundary values and inject the claimed fault on the real operation path; mocked agreement is not compatibility proof.
timestamp: 2026-10-01
---

A fixture that copies an implementation constant can confirm internal
consistency while missing disagreement with the external service. A permissive
callback can likewise hide a production resolver's input restrictions. Choose
independent expected values from the real contract and exercise the concrete
adapter against a disposable service.

For lost-response recovery, inject failure after the server commits but before
the client receives the response, then retry the normal command and inspect both
sides. Ordinary reuse is not that fault. For authorization failure, fail the actual
authority call whose result is being claimed. Distinct identity domains need
distinct realistic fixture values; do not collapse internal IDs, certificate team
names and signing identities into one convenient string.

September 2026 acceptance exposed a custody resolver rejecting a bare global ID,
a canonical-team/internal-ID mismatch, and an external home that accepted a
certificate but could not yet operate or release itself. October provider-target
checks caught a service-name mismatch that tests sharing the same constant missed.
These cases extend [the harness sensitivity rule](../aweb-expert/lessons/a-harness-must-be-shown-to-fail.md). Preserve production authorization while correcting incomplete test doubles.

## Provenance

Harvested from the coordinator’s September–October 2026 handover notes: `acceptance-faults-must-exercise-operation.md`, `deployment-target-tests-need-independent-service-name.md`, `custody-resolver-contract.md`, `auth-dependency-test-fixtures.md`, `external-home-acceptance-needs-operating-lifecycle.md`, `paired-fixtures-must-preserve-identity-domains.md`. The preserved notes and archived sessions retain the detailed incident receipts; this concept records the reusable conclusion, not a current implementation inventory.
