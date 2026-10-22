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
   Supply parameters from describe. For a pinned runner job, use
   `aw secrets run --job JOB_ID --request_id YOUR_REQUEST_ID --runner RUNNER_ID --params '{}'`.
   Never invent arbitrary shell commands or pass credential values.
3. If the result is `awaiting_approval`, keep the request id and request unchanged.
   The enrolled approver decides with a passkey on Secrets' own console. An agent
   tool, a link or a team signature cannot approve. Inspect state with
   `aw secrets status --ref REQUEST_OR_APPROVAL_REF`; when approved, resubmit the
   same request id and exact request, rather than creating a second request.
4. Treat `outcome_unknown` as uncertain: reconcile before retrying the effect.
   Do not label it success. Results are bounded and filtered; withheld output
   does not establish that no upstream action occurred.

MCP tools follow the same grant/policy checks. Manifest exposure grants no
authority. Surface-only tools are unavailable to agents. Never request, export,
log, or insert a credential value into a model conversation. Credentials reach
the broker or a pinned job process, not the tool interface. The service and
runner host are trusted with plaintext; redaction is not a confidentiality proof.
