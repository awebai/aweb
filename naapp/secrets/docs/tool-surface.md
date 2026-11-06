# Agent tool surface

The served v2 manifest defines the same tools for generic `aw` and a hosted
MCP gateway. Tool exposure grants no permission: B1 checks the signed caller,
installation, scope and context; secrets checks current principal/role grants.
The gateway's existing transport authenticates its two agents independently.
A direct team-auth test does not prove that hosted transport works.

Agent contexts expose `list`, `describe`, `request`, `run`, `status`, `cancel`
and `contain`. `propose-change` and `activity` are surface-only. There is no
value read, write or export tool in any context.

`list` returns only granted refs, kinds, sensitivity, approval requirement and
destination summaries. Owners may inspect all their installation's metadata.
`describe` adds allowed CURRENT operation/job IDs, digests and parameter schemas.
A stale pin never selects a historical definition. Job metadata includes runner
IDs, not executables, environment contents, credential values or backend locators.
Discovery neither admits a use nor charges rates; execution rechecks authority.

## Structured outcomes

Each handler response has `state` and `request_id`. List/describe use explicit
`request_id: null`; mutations preserve the caller's original nonempty ID.
B1 authentication/authorization failures retain the shared HTTP error contract.

| State | Fields |
| --- | --- |
| `completed` | `result`; an existing use may also carry `request_ref` |
| `awaiting_approval` | `request_ref`, `approval_ref` |
| `refused` | `code` |
| `outcome_unknown` | `request_ref` |
| `result_withheld` | `request_ref`, `code` |

`request_ref` is the stored intent locator. It is never an admission capability,
a dispatch UUID or a credential. Result producers apply projection/redaction
before calling the envelope helper. HTTP status remains the handler's choice;
a throttled use returns HTTP 429 and `Retry-After` from admission's retry delay.

An approval status is read-only. An agent supplies its request ID explicitly,
checks `status` using the returned locator, then re-submits the complete original
request only after approval. It reuses the exact same ID and body. An outcome
with unknown upstream effect is not permission to start another request.

## Generic aw flags

The generic dispatcher uses manifest field names as flags. These examples use
explicit flags, including the underscore in `--request_id`:

```sh
aw secrets list
aw secrets describe --secret payments
aw secrets request --secret payments --request_id refund-1 --operation refund --params '{"charge":"ch_123","amount_minor_units":500,"currency":"EUR"}'
aw secrets request --secret payments --request_id check-1 --method GET --url https://api.payments.example/v1/status
aw secrets run --job backup --runner runner-1 --request_id backup-1 --params '{"database":"orders"}'
aw secrets status --ref int_returned-locator
```

The caller keeps the original body for approval resubmission, including any
`reason`. The manifest's `--body-file` path can carry that JSON unchanged.
The released dispatcher prints response bytes and exits 0 for HTTP below 400,
1 otherwise. Read the structured state even on exit 0: approval waiting,
unknown outcomes and withheld results are not completed work. There is no
automatic request ID, polling or resubmission. Full S16's distinct outcome exits
require the separately owned generic manifest/CLI extension and CLI release
(decision 86); this application adds no secrets-specific CLI branch.

## Composition

M3 owns `create_app` and its guarded tool-router factories. Supply
`metadata_router(MetadataServices(catalog=...), authorized=authorized)` using the
exact runtime B1 dependency. The catalog factory resolves `runtime.db()` only
when a request arrives, after startup, and uses the service's installation
fence. Apply the runner-owned job migrations before serving metadata; there is
one CURRENT job registry. Unmounted tools keep explicit unavailable handlers;
metadata is not a replacement for reviewed request/run/status dispatch routes.
