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
manifest contain the exact 50 candidate postdeploy predicates plus the 22 current-incumbent
predicates added by the AATD follow-on, with exact owners, mappings, and per-obligation states.
A subset therefore cannot imply global enforcement.

The driver records entered components and terminal assertions inside checked-in code. Callers
cannot supply an observed path or outcome. Public negatives first pass origin, then fail at the
exact public child. Failed transcripts use closed variants: four exact dedicated-negative
recipes, nonclaiming incomplete/path/subject failures, and one deferred null-build control.
Arbitrary exception classes cannot accompany a dedicated mutation. Capability setup and
finalization are inside the command's guarded evidence path: setup/no-replace/metadata failures
and secondary capability-finalization failures still attempt exactly one terminal primary
health outcome. Output is bounded, outside the repository, operator-private, atomic no-replace,
and bound to the clean source and captured config/body bytes.

## Explicit nonclaims

A capability transcript is unsigned fixture output. Its parent ID is correlation only. It does
not prove producer authenticity, top-level completeness, current-production execution,
postdeploy execution, rollback execution, ledger immutability, lifecycle state, Make/CLI
wiring, or production safety selection. Lifecycle validation rejects both `capability-fixture`
and `current-incumbent-debug` proof classes. All nine global deferred obligation IDs still
block both preplan and release.

Increment 2A initially accepted only deferred current-incumbent candidate mappings. The AATD
follow-on adds source-owned semantic descriptors for both domains and makes validation execute
an exact runtime/surface/assertion comparator. Only public HTTP-200 and profile-pin for each
runtime compare identical. The remaining 18 mappings stay deferred; the four legacy response
contract cells additionally block on `candidate-only.runtime-proof`. Mapping targets must be
unique, and omitted, unknown, renamed, duplicate, or semantically unequal registrations fail
closed.

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
| Cross-domain identity is not inferred | four source-descriptor pairs compare exactly | runtime, surface, assertion, target, and duplicate flattened-target mutations are rejected independently |
| Fixture evidence is bounded/private/no-replace | exact mode and captured-byte digest assertions | dirty source prevents output; second output creation is refused |
| Primary evidence is terminal across capability failures | normal command emits one final primary outcome | pre-existing output, invalid metadata, and capability finish failure each still produce exactly one failed primary terminal |
| Diagnostic output cannot authorize lifecycle | transcript schema validates as capability only | lifecycle receipt validation rejects `capability-fixture` and `current-incumbent-debug` |
