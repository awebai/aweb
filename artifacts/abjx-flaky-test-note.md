# abjx flaky-test note

Observed during `aweb-abjx` validation at commit `16afe42ddb897198dbc92f7120e9ffb1e6e5f857`:

- Command: `TMPDIR=/private/tmp go test ./cmd/aw -count=1 -timeout=10m`
- Result: broad suite failed once in unrelated `TestConcurrentRotationsClaimOnlyOneState` with `neither rotation reached the registry` after about 294 seconds.
- Follow-up: targeted rerun `go test ./cmd/aw -run 'TestConcurrentRotationsClaimOnlyOneState' -count=1` passed locally in 4.152s.
- Independent reviewer context: Athena reported the full `go test ./cmd/aw` passed at the same candidate in about 232s and `TestConcurrentRotationsClaimOnlyOneState` passed 5/5 in isolation.

This note tracks the observation as a timing flake under broad-suite load. The test is not weakened or changed by `abjx`; abjx evidence cites both the retained failed broad log and the targeted passing rerun.
