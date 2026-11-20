---
type: Lesson
title: A run's durable verdict is written after every downgrade
description: A run that leaves a durable verdict (verdict.json, a result file, a journal's final line) writes it only after every doubt has downgraded the result, with the final result, the reasons and the exit code; its controls read that file and assert it agrees with the printed verdict, because tests that check only stdout let a stale receipt ship.
tags: [lesson, testing, runners, evidence, receipts]
timestamp: 2026-11-20
---

Learned on 2026-11-20 from a lifecycle diagnostic's continuation run. It
collected its doubts (cleanup not observed gone, an unbound driver, an
unverified seat), wrote `verdict.json`, and only then downgraded the result.
The run printed INCOMPLETE and exited 3 while the file on the host said FAILED
or PASS. Every doubt control passed, because each checked only the printed
line. This is a failure read as success: the retained evidence a later reader
trusts disagreed with the exit code.

# How to apply

- Compute the final result first, including every downgrade that depends on a
  later observation. Then write the durable record, carrying the result, the
  reasons and the exit code.
- A failure to write the record can only be reported where the run's output
  goes, so keep it as a printed doubt.
- In every downgrade and doubt control, read the durable file and assert it
  equals what was printed, and show the old ordering going red, per
  [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md).
- The same holds for any receipt a run leaves behind that a reader may consult
  without its stdout: journals, `result.json`, final log lines.

# Elimination route

The parity assertion in the run's own tests is the fix; this lesson is for
writing and reviewing runners that do not have it yet.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-20;
notes/durable-verdict-after-every-downgrade.md. The run, its outputs and the
red result of the earlier revision against six parity controls are the
source's report.
