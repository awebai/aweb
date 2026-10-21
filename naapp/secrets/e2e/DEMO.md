# 1Password demo acceptance

M9 implements Juan's six-step demo from 2026-10-21 as real-path tests on S19
(`aweb-acgh.18.21`). It is the demo subset of S20 (`aweb-acgh.18.22`).
The runner is part of acceptance. Derived credentials, STS issuance, usage
reporting and logs delivery are outside this demo.

## Required environment

Use a dedicated test team, a dedicated 1Password demo vault, test upstream,
real KMS test key and a registered runner. Hestia owns this environment (HO6,
`aweb-acgh.15`). The service account has read-only access to the demo vault;
tests never write to 1Password. The vault contains an HTTP API credential and
a CLI password known independently to their test targets.

The S19 harness owns service startup, identity/bootstrap, TLS, email capture,
browser WebAuthn with a virtual authenticator, and runner lifecycle. Use the
checkout's services and runner binary. The hosted MCP path uses two distinct
agents in the same role and retains the actual agent identity through signing
and admission. A direct team-auth request alone does not cover that path.

The runner and its job must run as a separate OS user from the secrets service
and test driver. Record the actual process identities, binary and job digests,
and terminal state without credential values. A second process under the
same user does not meet this requirement.

Read operator credentials through the environment's agreed `*_FILE` inputs.
Keep values, email link tokens, passkey assertions and runner credential
payloads out of pytest diagnostics, screenshots, traces and retained evidence.
Do not add hard-coded credentials or dump HTTP bodies on failure. Report the
failed step, status/code and non-secret correlation IDs instead.

## One complete scenario

Each row continues from the preceding row. Give every attempted use a unique
request ID and retain its principal, secret, operation/job and outcome for the
activity assertions. Domain records are created through the console, rather
than inserted into the database by the test.

| Step | Real action | Required observations |
| --- | --- | --- |
| 1. Configure | Owner signs into the console with a browser passkey; creates two secrets referring to the demo-vault item/fields; sets HTTP destinations and operations, a pinned CLI job with durable delivery, and grants both to the agents' role. | Unconfirmed changes remain inert. Passkey confirmation makes the definitions/grants usable. Console metadata contains references and policy, without credential values. |
| 2. Use from two agents | Each hosted MCP agent calls `secrets.list`, then `secrets.request` for the allowed API operation. | Both reach the authenticated test upstream and receive precisely the declared projection. Each use is attributed to its own agent; neither response contains the value. A member without the role cannot use the same listed tool. |
| 3. Approve a use | Mark the API secret `approve_only` through a confirmed console change; an agent requests a use; the human opens the delivered email link and approves with a browser passkey. | The pending use has not reached the upstream. The agent receives an approval reference without an email link. Status reads do not dispatch. After approval, the agent resubmits through MCP and exactly one use reaches the upstream. A replay cannot consume the approval again. |
| 4. Run a job | Agent submits a job to the registered runner; a human approves its required credential use; the real runner claims and executes the pinned job as its separate OS user. | The job authenticates to its test target using the 1Password password. Durable release is bound to this approved job, and the job reaches its expected terminal result. Model-visible submission/status/result data contains no password. An unapproved job obtains no credential and makes no authenticated target call. |
| 5. Revoke | Owner removes one agent from the role through the supported control, then that agent and the surviving role member each attempt a fresh API use. | The removed agent is refused before upstream dispatch; the other agent still succeeds. Use this individual-role-removal option to preserve the surviving-agent control: revoking a grant shared by both agents would refuse both. |
| 6. Inspect activity | Owner opens the console activity view. | It correlates the recorded request/job IDs to the correct agent, secret and operation, time and outcome, including approval wait, successful broker/runner uses and refused post-revocation use. No secret value appears. Hook events queue in the outbox; logs delivery is not required for this demo. |

## Execution and evidence

Implement the scenario against the agreed S19 fixtures when the M1/M2 console,
M3 dispatch, M4 hosted tools, M6/M7 runner and M8 approval interfaces are ready.
Missing environment or an absent route is an unmet prerequisite, not a passing
demo. Explicit demo execution must fail clearly if required configuration is
missing; it must not silently skip steps or replace services with mocks.

Run named scenario files directly with at most two workers. Only coordinator
covering suites and gates take the suite lock. Keep one sanitized record of the
exact tested tree and each step's outcome. State which target faults were
shown to fail the assertions, and which sensitivity checks remain owed.

M9 requires independent and Athena review on the exact test head, followed by
secrets' covering train. This document is the acceptance map; executable tests
and a successful complete real-environment run are still required.
