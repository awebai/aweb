---
type: Lesson
title: A pass line must carry the command's own exit status
description: Piping a check through tail reports tail's exit status, so a failing check reads as passing and a chained commit lands on top of it; evidence runs use pipefail, or log to a file and test the command's own status, and keep the full log.
tags: [lesson, verification, evidence, shell]
timestamp: 2026-11-13
---

A pass line is evidence only when the exit status it reports belongs to the
check. In a pipeline the shell reports the last command's status, so
`check | tail` reports tail's, which is nearly always zero. This refines
[a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md):
an exit-code check is one of the harnesses that is not a test, and this is
one way it can never go red.

In one task (acxy.16, 2026-11-13) the same pattern gave two false
passes:

- A backgrounded `make <targets> | tail` exited 0 while one of its targets,
  the test-vector provenance check, failed. Only reading the output showed
  make's error. The failure is visible at 865e64975 and fixed at 2e9ae16ae.
- `ruff check ... | tail -1 && git add ... && git commit` committed an
  import-order error, because the `&&` chain saw tail's status. The lint
  error landed at 45dd32efe and was fixed at ecea212f6.

The repository cannot show this: the code was fine to read, and the failure
lived in the shell that reported on it.

# How to apply

- For any pass line pasted into a landing request or a review verdict, run
  the check under `set -o pipefail`, or redirect it to a log file and test the
  command's own `$?`. Keep the full log, not a tail of it.
- Never chain a commit, push or handover on a piped check.
- Elimination route: a commit-time lint hook removes the commit half where
  one runs. The evidence half stays a matter of how the command is run.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-signer-ux, 2026-11-13;
notes/a-pass-line-must-carry-its-own-exit-status.md. The four commits were
confirmed to exist in the aweb repository; the account of what each run
printed is the source's report.
