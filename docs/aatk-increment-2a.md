# AATK increment 2A: child capability transcripts

Increment 2A proves a narrow capability only. It does **not** produce trusted receipts or
advance a release lifecycle.

## Enforced slice

The checked-in driver is exactly `render_ops.command_verify`. Contract fixtures keep its
Python command orchestration and health checkers real while replacing only these declared
external boundaries:

- Render API;
- origin HTTP;
- public HTTP.

Four predicate cells are registered as `instrumented-capability`:

- `health.origin.http-200`;
- `health.origin.payload-contract`;
- `health.public.http-200`;
- `health.public.payload-contract`.

Every other predicate cell remains `deferred`. The source-owned coverage registry and static
manifest must contain the exact 50 candidate postdeploy predicates, owners, mappings, and
per-obligation states. A subset therefore cannot imply global enforcement.

The driver records entered components and terminal assertions inside checked-in code. Callers
cannot supply an observed path or outcome. Public negatives first pass origin, then fail at the
exact public child. Failed transcripts use closed variants: four exact dedicated-negative
recipes, nonclaiming incomplete/path/subject failures, and one deferred null-build control.
Arbitrary exception classes cannot accompany a dedicated mutation. Output is bounded, outside
the repository, operator-private, atomic no-replace, and bound to the clean source and captured
config/body bytes.

## Explicit nonclaims

A capability transcript is unsigned fixture output. Its parent ID is correlation only. It does
not prove producer authenticity, top-level completeness, current-production execution,
postdeploy execution, rollback execution, ledger immutability, lifecycle state, Make/CLI
wiring, or production safety selection. Lifecycle validation rejects `capability-fixture`
proofs. All nine global deferred obligation IDs still block both preplan and release.

The generic current-incumbent domain accepts only deferred candidate mappings in 2A.
`candidate_mapping=identical` is rejected until a later increment adds source-owned semantic
descriptors on both domains and an exact runtime/surface/assertion comparator.

`health.surfaces.payload-equal` is deliberately not marked instrumented. Under
`render_ops.command_verify`, both real checkers require the same exact response shape,
status/service values, and candidate build SHA before equality is reached. No unequal pair can
reach that comparison without weakening or bypassing a checker, so increment 2A cannot provide
a faithful negative for it. The cell stays deferred for a later rollback-driver review: with
legacy missing-build compatibility, intact checkers can accept a two-key legacy shape on one
surface and a strict three-key shape on the other, making equality independently reachable.

## Acceptance map

| Claim | Positive | Dedicated negative / mutation |
|---|---|---|
| Source coverage is complete | canonical 50-row source/manifest equality | omitted, duplicate, renamed, manifest-only state, and source-only omission tests |
| Enforcement history is immutable | six implemented IDs map to `increment-1` | rewritten history and unearned deferred history tests |
| Real parallel health path emits children | command verify fixture emits four passing child transcripts | origin/public HTTP and payload failures independently emit exact sibling rejection |
| Public is mandatory after origin | public negatives contain both passing origin children | bypassed health orchestration fails `capability-incomplete`; reordered components fail `capability-path-mismatch` |
| Failed transcript variants are closed | each dedicated negative has exact prerequisites, one terminal negative, and a stable top code | empty-child `TypeError` with a dedicated public mutation is rejected |
| Cross-domain identity is not inferred | deferred current mappings remain representable | typed but unrelated `identical` runtime/surface/assertion mapping is rejected until a comparator exists |
| Fixture evidence is bounded/private/no-replace | exact mode and captured-byte digest assertions | dirty source prevents output; second output creation is refused |
| Fixture output cannot authorize lifecycle | transcript schema validates as capability only | lifecycle receipt validation rejects `capability-fixture` |
