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
- A green reproducible gate cannot prove compatibility with a live legacy or
  rollback artifact that the stack does not contain. When a response contract
  adds identity fields, inventory actual deployed shapes and drive exact
  fixtures through preflight, candidate, rollback, and recovery commands.
  Compatibility exceptions must be layer-specific, artifact-and-commit pinned
  per invocation, forbidden on the candidate path, and carry an explicit
  artifact-based expiry condition.
- When a guarantee depends on parallel surfaces or multiple pass-throughs,
  mutating all links at once can be caught by a half-blind test. Break each link
  independently, restore it before mutating the next, and require the regression
  to fail at that exact surface for the intended reason rather than merely
  returning nonzero. For fail-closed contracts, test the symmetric direction too:
  enable each forbidden permissive path independently and require its dedicated
  negative control to fail.
- A validator that checks only for missing required fields is an open schema
  wearing a typed label: it rejects incompleteness while accepting wrong types
  and arbitrary authoritative-looking keys. Require exact key sets (including
  explicit variant-specific keys), independently feed every declared field a
  wrong type, and add unknown claim-like fields such as `passed`. Malformed
  nested containers must return the validator's stable code and location rather
  than leaking a language-level exception.
- An internally consistent evidence record does not prove its provenance. An
  untrusted producer can copy or recompute source SHAs, digests, path IDs, and
  terminal claims while forging the whole record. Without an independently
  established trust anchor, such as an envelope signed by a trusted runner or
  an independently controlled append-only ledger, label the output a capability
  transcript rather than a receipt. Independently verify the actual
  driver, observed subject path, and allowed substitutions; never infer them
  from caller-supplied fields.
