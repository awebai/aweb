---
name: use-secret
description: Use an allowed Secrets broker operation or pinned runner job without handling credential values.
---

Read `/llms.txt` and `/reference` at the installed app origin for the current
manifest, tool parameters and invocation contexts. Install the app from its
origin with `aw plugin install https://secrets.aweb.ai`. Self-hosted deployments
use their configured origin and manifest app id as the command namespace.

1. Use `aw secrets list` to find permitted references, then
   `aw secrets describe --secret EXAMPLE_REF` to read allowed operations, job
   definitions and parameter schemas. Substitute an actual granted reference.
2. Choose an operation within the task's authority. For a broker call, use
   `aw secrets request --secret EXAMPLE_REF --request_id YOUR_REQUEST_ID --operation OPERATION_ID --params '{}'`.
   Supply parameters from describe. If the grant permits open requests, use
   `aw secrets request --secret EXAMPLE_REF --request_id YOUR_REQUEST_ID --method GET --url https://upstream.example/status`.
   Open requests use method/url and optional headers/data; named requests use
   operation/params. Named headers must be allowed by the operation. Do not mix
   the two forms. For a pinned runner job, use
   `aw secrets run --job JOB_ID --request_id YOUR_REQUEST_ID --runner RUNNER_ID --params '{}'`.
   An optional `--secret CHILD_REF` selects an ordinary child for the job's
   unique durable slot; omit it to keep the job's fixed selectors.
   Never invent arbitrary shell commands or pass credential values.
3. Read the response's `state`, even when the command succeeds. The released
   generic CLI exits 0 for HTTP success and 1 for HTTP errors; a zero exit does
   not mean the broker call or job completed. `received`, `admitted` and
   `dispatching` report progress. An admitted job may still await its runner.
4. If the result is `awaiting_approval`, keep the request id and request unchanged.
   The enrolled approver decides with a passkey on Secrets' own console. An agent
   tool, a link or a team signature cannot approve. Inspect state with
   `aw secrets status --ref REQUEST_REF`, using the returned `request_ref`.
   A job may need several approvals: one approved slot is not approval of the
   whole run. Wait for the aggregate state `approved` with `next: "resubmit"`,
   then explicitly invoke the original command with the same request id and
   unchanged body. This makes a fresh authenticated submission; status itself
   never sends. Do not change parameters, runner, headers, data or child selector.
   Approval states `denied`, `expired` and `revoked` are final for that request id.
5. `not_sent` permits an explicit same-request resubmission when its response
   says `next: "resubmit"`; current policy and expiry still apply. Do not
   automatically retry. A `refused` response carries a code; an HTTP error
   before the handler may instead use the shared runtime error shape.
6. Treat `outcome_unknown` as uncertain: reconcile before retrying the effect.
   Do not label it success. `result_withheld` reports safe metadata without the
   output; it does not establish that no upstream action occurred. Cancellation
   and reconciliation receipts never authorize a new execution. A `completed`
   broker result includes the upstream status, which can itself be an HTTP error.

MCP tools follow the same grant/policy checks. Manifest exposure grants no
authority. Surface-only tools are unavailable to agents. Never request, export,
log, or insert a credential value into a model conversation. Credentials reach
the broker or a pinned job process, not the tool interface. The service and
runner host are trusted with plaintext; redaction is not a confidentiality proof.
