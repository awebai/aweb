# First-release acceptance

M9 implements Juan's six-step first-release journey from 2026-10-21 as real-path tests on S19
(`aweb-acgh.18.21`). It is the release subset of S20 (`aweb-acgh.18.22`).
The runner and real audit ingestion into logs are part of acceptance. Derived
credentials, STS issuance and usage reporting remain parked. Juan corrected
the earlier demo brief: this is a customer release with the production quality
bar, first shown to 1Password employees.

## Required environment

Use a dedicated test team, a dedicated 1Password test vault, test upstream,
real KMS test key and a registered runner. Hestia owns this environment (HO6,
`aweb-acgh.15`). The application service account has read-only access to the test vault; a
separate fixture-writer account can update the dedicated test item for the
item-version-change refusal test. The vault contains an HTTP API credential and
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

Read test credentials through the environment's agreed `*_FILE` inputs.
The test enters the team-owned 1Password service-account token through the
normal console value-ingress path and confirms it with a passkey, so native
custody seals it for that team. The app has no test-only or operator-wide
1Password file-token loader; it opens the team's sealed token per use.
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
| 1. Configure | Owner signs into the console with a browser passkey; creates two secrets referring to the test-vault item/fields; sets HTTP destinations and operations, a pinned CLI job with durable delivery, and grants both to the agents' role. | Unconfirmed changes remain inert. Passkey confirmation makes the definitions/grants usable. Console metadata contains references and policy, without credential values. |
| 2. Use from two agents | Each hosted MCP agent calls `secrets.list`, then `secrets.request` for the allowed API operation. | Both reach the authenticated test upstream and receive precisely the declared projection. Each use is attributed to its own agent; neither response contains the value. A member without the role cannot use the same listed tool. |
| 3. Approve a use | Mark the API secret `approve_only` through a confirmed console change; an agent requests a use; the human opens the delivered email link and approves with a browser passkey. | The pending use has not reached the upstream. The agent receives an approval reference without an email link. Status reads do not dispatch. After approval, the agent resubmits through MCP and exactly one use reaches the upstream. A replay cannot consume the approval again. |
| 4. Run a job | Agent submits a job to the registered runner; a human approves its required credential use; the real runner claims and executes the pinned job as its separate OS user. | The job authenticates to its test target using the 1Password password. Durable release is bound to this approved job, and the job reaches its expected terminal result. Model-visible submission/status/result data contains no password. An unapproved job obtains no credential and makes no authenticated target call. |
| 5. Revoke | Owner removes one agent from the role through the supported control, then that agent and the surviving role member each attempt a fresh API use. | The removed agent is refused before upstream dispatch; the other agent still succeeds. Use this individual-role-removal option to preserve the surviving-agent control: revoking a grant shared by both agents would refuse both. |
| 6. Inspect activity | Owner opens the console activity view. | It correlates the recorded request/job IDs to the correct agent, secret and operation, time and outcome, including approval wait, successful broker/runner uses and refused post-revocation use. No secret value appears. Trace the resulting real signed events through hook delivery and logs ingest, and verify attribution/outcome through logs' real read path. Outbox enqueue alone does not complete audit acceptance. |

## Execution and evidence

Implement the scenario against the agreed S19 fixtures when the M1/M2 console,
M3 dispatch, M4 hosted tools, M6/M7 runner and M8 approval interfaces are ready.
Missing environment or an absent route is an unmet prerequisite, not a passing
release. Explicit release execution must fail clearly if required configuration is
missing; it must not silently skip steps or replace services with mocks.

Run named scenario files directly with at most two workers. Only coordinator
covering suites and gates take the suite lock. Keep one sanitized record of the
exact tested tree and each step's outcome. State which target faults were
shown to fail the assertions, and which sensitivity checks remain owed.

M9 requires independent and Athena review on the exact test head, followed by
secrets' covering train. This document is the acceptance map; executable tests
and a successful complete real-environment run with logs ingest are still required.

## Configuration agreement

Decision 45 fixes `AWEB_SECRETS_E2E_KMS_KEY_ARN`,
`AWEB_SECRETS_E2E_AWS_REGION` and `AWEB_SECRETS_E2E_KMS_CREDENTIALS_FILE`
(AWS shared-credentials format, `[default]` profile). No second profile/name
contract is introduced. Other exact test-vault, hosted MCP and runner input
names are being agreed directly with their owners before HO6 provisioning.
The hosted transport authentication/session format must come from its owner;
MCP token-file names do not prescribe an authorization scheme.
