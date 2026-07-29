# Common failure patterns

Generalized recurring-issue categories only — never verdicts or memory about
a specific change. This is the reviewer's single persisted artifact; fresh
eyes are the point.

- A negative control that duplicates a production path or limit can become
  vacuous when production moves or is retuned. Derive the target through the
  production resolver where possible, and mutation-test the production value.
- A release-time copy step does not keep a committed public mirror current.
  Gate canonical-to-mirror equality before merge, with a seeded stale-copy
  negative control.
- In multi-stage bounded ranking, a final-order test is vacuous when every
  fixture row fits inside the upstream candidate window or already follows its
  proxy order. Force the fixture past that bound, put the desired row outside
  preselection, and execute the counterexample against the authoritative
  ranking signal. When that signal supplies candidate IDs, verify tenant,
  authorization, and endpoint filters still apply before ordering.
- In a sequential release gate, seeing a downstream check after an upstream
  check does not prove the downstream check is mandatory. Make the upstream
  stage succeed, inject a downstream failure, and assert that it propagates to
  a nonzero overall result with no success verdict. Then remove the downstream
  stage and verify the regression test fails; this distinguishes a real gate
  dependency from mere call ordering.
