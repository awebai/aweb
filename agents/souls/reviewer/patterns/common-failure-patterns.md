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
- A red CI result proves capability, not merge obligation. Verify repository
  protection requires the exact observed check context and app (including for
  administrators), then attempt an exact-head merge while that check is red and
  require the provider to reject it. Revert the defect and require the same
  protected context to make the head mergeable.
- A deliberate defect caught by an earlier sibling check does not exercise a
  downstream gate. To prove an end-to-end journey has teeth, inject a semantic
  source defect that is lint-clean, type-clean, and unit-green; require the
  intended journey to fail for its exact assertion rather than infrastructure;
  then revert it and require the same journey to pass.
