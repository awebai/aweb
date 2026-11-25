---
type: Lesson
title: Copied test code carries its import-time side effects
description: A conftest's module-level settings are harmless where one conftest governs a whole suite, but copied into another repository they leak into every test collected in the same process; record them as data, apply them with a scoped fixture that restores them, and prove the fix by running both suites together in both orders.
tags: [lesson, pytest, testing, isolation, repository-split]
timestamp: 2026-11-25
---

When the apps repository took its server-compatibility suite from aweb, the
helpers were copied verbatim from `server/tests` at server-v1.27.53, including
the conftest's module-level `os.environ.setdefault(...)` lines for the awid
service token. In aweb that conftest governs the whole server suite. In the
apps repository it was collected next to the naapp-lib tests, so the
environment it set applied to them too: naapp-lib's `test_current_member`
passed alone and failed (403, then KeyError) when a single compatibility file
was collected with it.

Collection order is no isolation. pytest imports every collected conftest
before any test runs, so a module-level side effect also reaches tests that
were collected earlier.

# How to apply

- When moving or copying test helpers between repositories or suites, list
  their module-level statements: environment settings, monkeypatches, global
  registries.
- Record each as data and apply it with a fixture scoped to the suite that
  needs it, restoring the previous value afterwards. The apps repository fixed
  it with a package-scoped fixture (naapp d28971d44).
- Prove the fix by running the affected test in the same process as the
  copied suite, in both orders: red on the old head, green on the new.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-apps-repo, 2026-11-25;
notes/copied-test-code-carries-import-side-effects.md. The failure was found
by another seat; the fix commit is the source's report.
