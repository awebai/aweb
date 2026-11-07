# Agent tool surface

The served v2 manifest defines the tools for generic `aw`. The same manifest
tools are served to MCP clients through a gateway outside this repository.
Tool exposure grants no permission: B1 checks the signed caller, installation,
scope and context; secrets checks current principal/role grants. A direct
team-auth test in this repository does not prove the gateway's transport.

Agent contexts expose `list`, `describe`, `request`, `run`, `status`, `cancel`
and `contain`. `propose-change` and `activity` are surface-only. There is no
value read, write or export tool in any context. **Open (aweb-acgh.18.18):**
`cancel`, `propose-change` and `activity` are declared in the manifest but
answer 501 `not_implemented`; see Composition.

`list` returns only granted refs, kinds, sensitivity, approval requirement and
destination summaries. Owners may inspect all their installation's metadata.
`describe` adds allowed CURRENT operation/job IDs, digests and parameter schemas.
A stale pin never selects a historical definition. Job metadata includes runner
IDs, not executables, environment contents, credential values or backend locators.
Discovery neither admits a use nor charges rates; execution rechecks authority.

## Structured outcomes

Each `list`, `describe`, `request`, `run` and `status` response has `state`
and `request_id`. List/describe use explicit `request_id: null`; `request` and
`run` echo the caller's nonempty ID once the body is parsed. A refusal before
that (for example `grant_missing`) and a `404 not_found` status lookup carry
`request_id: null`. `contain` returns its containment receipt
(`receipt_id`, `action`, `target`, `affected_secret_ids`) and refuses with an
HTTP error whose detail is the refusal code. B1 authentication/authorization
failures retain the shared HTTP error contract.

| State | Fields besides `state`, `request_id` |
| --- | --- |
| `completed` | `result`; a use also carries `request_ref` |
| `awaiting_approval` | `request_ref`, `approval_ref`; a run also has `approval_refs` |
| `approved` | `request_ref`, `next: "resubmit"`; status only |
| `received`, `admitted`, `dispatching` | `request_ref`; persisted progress, not completed work. An admitted run waits for a runner. |
| `not_sent` | `request_ref`, `next: "resubmit"`; HTTP 503 on POST |
| `refused` | `code`; a live attributable refusal adds `use_ref`, a stored refusal adds `request_ref` |
| `outcome_unknown` | `request_ref`, `reconcile_ref` (the same locator) |
| `result_withheld` | `request_ref`, `code`, `result` (safe metadata, no body) |
| `cancelled` | `request_ref`; HTTP 200, no `next` |
| `reconciled_completed`, `reconciled_failed`, `reconciled_unknown` | `request_ref`; `result` if one exists |

A status lookup by an approval locator also returns S12's `denied`, `expired`,
`revoked` and consumed `admitted` states. A persisted cancellation (requester
withdrawal or containment) is never presented as `approval_revoked`; a revoked
approval on a request still awaiting approval is `refused` with
`approval_revoked`. **Open (aweb-acgh.18.52):** run status presents a persisted
`cancelled` as `refused` with `approval_revoked`, and a run POST receipt
returns a stored `refused` as 503. The correction is planned test-first.

`request_ref` is the stored intent locator. It is never an admission capability,
a dispatch UUID or a credential. `use_ref` correlates a refusal with its signed
audit event and grants no lookup or retry. A status read that cannot rebuild
its release context returns HTTP 503, `state: "refused"`, `code:
"release_context_unavailable"`. Result producers apply projection/redaction
before calling the envelope helper. HTTP status remains the handler's choice;
a throttled use returns HTTP 429 and `Retry-After` from admission's retry delay.

An approval status is read-only. An agent supplies its request ID explicitly,
checks `status` using the returned locator, then re-submits the complete original
request only after approval or after `not_sent`. It reuses the exact same ID
and body. An outcome with unknown upstream effect is not permission to start
another request; secrets §11.4 governs reconciliation.

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
progress, unknown outcomes and withheld results are not completed work. There
is no automatic request ID, polling or resubmission. MCP clients read the
structured state. Distinct outcome exits come from a generic manifest
outcome-to-exit mapping in `aw`, with no secrets-specific CLI code
(decision 86). **Open (aweb-acgh.18.18):** that mapping is not on main.

## Composition

`create_service` in `composition.py` passes three guarded tool-router
factories to `create_app` (`app.py`), each under the exact runtime B1
dependency: `metadata_router` (`list`, `describe`), `use_router` (`request`,
`run`, `status`) and `containment_api_router` (`contain`). Their services are
built after startup and resolved when a request arrives; the catalog uses the
service's installation fence. Root applies the runner-owned job migrations
before serving; there is one CURRENT job registry. Every declared tool without
a composed route gets the explicit 501 `not_implemented` handler.
**Open (aweb-acgh.18.18):** `cancel`, `propose-change` and `activity` have no
composed route.
