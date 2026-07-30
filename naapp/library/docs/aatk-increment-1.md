# AATK increment 1 acceptance map

This increment is an intentionally partial, falsifiable instrument. It can establish only
`spec-valid`. Both preplan and release-close remain machine-blocked by every deferred
requirement in `ops/aatk-manifest.json`.

| Enforced claim | Positive evidence | Independent rejection / mutation evidence |
|---|---|---|
| Static specification is separate from runtime receipts | `test_canonical_partial_manifest_is_spec_valid_and_matches_executor_universe` | `test_static_manifest_cannot_embed_a_runtime_receipt` |
| Executor predicate IDs exactly equal manifest rows | `make aatk-predicate-inventory`; canonical schema test | deleted, renamed, orphaned, and duplicate predicate tests; source mutation removing the missing-row comparison makes the dedicated deletion test red |
| Rows and fixture receipts are closed, typed, and source-bound | canonical schema and lifecycle fixture tests | independent service/row owner/proof extra/registry owner/expiry/candidate-absence type reproductions; blank/sentinel, unchecked command, wrong SHA/digest/app/context, mixed run, expiry, terminal, unrelated failure, duplicate/unknown/missing receipt, and malformed nested-object tests |
| Every row structurally pairs a positive and faithful negative on one declared path | canonical schema test | missing-negative and unit-only-path substitution tests; source mutation removing the path comparison makes its dedicated test red |
| Candidate-only absence is a source allowlist, not a convenience escape | canonical build/runtime/managed/harness rows | transport escape, shared-transport waiver, and missing exact-source-positive tests; disabling the allowlist rejection makes its dedicated test red |
| Deferred semantics cannot be cleared by editing the manifest | both lifecycle tests enumerate every source-owned deferred ID | `test_editing_deferred_status_cannot_clear_source_enforcement_blocker` |
| External ledger paths cross Make without shell interpolation | quoted exported environment path reaches Python | static recipe regression plus a quote/semicolon shell-injection execution test that proves no marker is created |
| Preplan and release-close cannot be authorized by this increment | schema validation passes | independent structurally valid fixture-ledger tests reach `unenforced-obligation` with the full deferred-ID set; malformed ledgers may fail earlier but no lifecycle path can return success |

The runtime meanings of declared path IDs, actual same-path invocation, receipt freshness and
immutability, separate incumbent/rollback identity semantics, lifecycle transitions, safe
boundary execution, paid-provider obligations, and orchestrator mutation controls remain
explicit deferred blockers. Tests and prose in this increment are not receipts and cannot
satisfy those blockers. The next deliberately non-authorizing capability layer is documented
in `docs/aatk-increment-2a.md`.
