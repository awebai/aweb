---
type: Lesson
title: Missing equals missing passes
description: A check written as expected.get(k) == actual.get(k) is green when the observed record is absent, because None equals None; an evidence check must first require that the observed record exists and names an expected item, and only then compare values.
tags: [lesson, verification, gate, release, receipts, testing]
timestamp: 2026-11-25
---

The first version of the release launcher's gate check counted a green suite
with no wheel record as green. The check compared the expected wheel digest
with the observed one by looking both up, and when the observed record was
absent both lookups returned nothing and compared equal. The proof that the
built wheel was installed had not run at all, and the gate still read green.

# How to apply

- In any gate, receipt or evidence check, first require that the observed
  record exists and that it names an item the check expects. Only then compare
  its values with the expected ones. An absent record is red, with failure text
  that says it is absent.
- Treat any comparison of two lookups with a default (`.get()`, an optional
  field, a missing key read as empty) as suspect when it is the whole check.
  Both sides being missing is the case it silently accepts.
- The elimination route is a test per check: give it a green run whose
  observed record is missing and require red. That test caught this instance
  before commit.

This is one concrete form of the vacuous guard in
[a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md):
an exit-code or read-back check that cannot go red when its evidence is
missing proves nothing.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-gate-dispatch, 2026-11-25;
notes/missing-equals-missing-passes.md. Task aweb-adyi step 1. The test
`test_aweb_green_suite_without_the_wheel_record_is_red` in
`scripts/vm-gate/tests/test_project.py` is present at b64035903f, which was on
the source's release branch and not yet on main at harvest. One occurrence.
