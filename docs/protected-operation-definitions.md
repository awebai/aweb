# Protected operation definitions

`OperationDefinition` in the shared protected signer catalog is the code-owned
entry for each served operation and variant. Its codec supplies the subject
parser, released intent decoder, artifact builder, signing bytes and authority
field. Its effect supplies the adapter and exact delivery builder. Prepared
members, signing port, original request window, execution-refusal and receipt
rules, frozen display metadata and actual catalog binding paths are part of the
same row. Neither a requester nor a host configuration can install another row.

`bound_values` resolves every catalog binding against the frozen request before
approval state is minted. A missing field is an operation mismatch. Null values
remain null, including local membership and an empty certificate head; they are
not treated as absent. The existing subject and artifact codecs remain the
semantic and byte authority.

The public generated description is `docs/protected-operations-v1.json`.
`scripts/generate_protected_operations.py` emits it and the Go client's pinned
selection table from the runtime definitions. Run it using the shared package's
locked environment. `--check` refuses stale generated output. The client checks
the exact prepared member set, projects the generated bindings and invokes the
existing canonical consumer verifier selected by that generated table. An
undefined operation/variant cannot borrow another operation's shape. A response
cannot supply a replacement description.

The page receives subject schemas, presentation constraints and display fields
from that same catalog. It validates the original B2 digest and applies the
definition's constraints. Display has `title`, ordered `consequences`, frozen
`names` and `technical` field sources, and operation-specific `refusals`.
Templates and sources refer only to the frozen request, using JSON pointers.
The root responsibility statement is authored once in its definition and feeds
the server's frozen request, page check and generated client constant.

This refactor adds no resolved name fields to existing prepared requests.
Current deployment labels, member aliases, role names and team identifiers are
already frozen. New authoritative alias/address/display-name snapshots need a
separately negotiated description version that the client verifies. The page,
mail and CLI must not resolve a live name after preparation or treat a requester
label as identity-kind or authority evidence.

The custody retention port and safe public delivery result are documented in
`protected-operation-retention.md`. Existing unmarked consumers retain their
released behavior; actual protected-verifier acceptance is qualified separately
with the protected custody adapter.

Implementation direction was approved by the coordinator in `653fda3e` for
`aweb-acxy.13`, following `ec1a081a`. The explicitly cut-over protected-effect
extension records Juan 2026-11-13, via coordinator (`7e87b394`); that extension's
codec, custody and verifier source has its independent security review.
