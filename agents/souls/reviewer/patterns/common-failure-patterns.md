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
