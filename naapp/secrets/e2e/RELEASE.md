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

## Step 1 scenario: connect the team's vault and create a referenced secret

This scenario runs through the actual service's human-origin root, with its
shared owner console, custody and official 1Password SDK. A manually composed
test router, an SDK `Item` projection, a driver-side SDK call or domain SQL does
not establish this journey. S19 supplies the real service, signed owner-act
bootstrap, personal enrolment/approval delivery and browser lifecycle.

1. Open the genuine owner setup link in a fresh Chromium context with a CTAP2
   resident-key authenticator and user verification enabled. Enrol through
   `/enrolment/options` and `/enrolment`, then use the production passkey sign-in
   button. Check that sign-in reaches the console root with an S4 session and
   the tab CSRF token. A locator alone must not admit the owner actions.
2. Open `/backend-credentials/onepassword/new`. Read the operator-provided
   `AWEB_SECRETS_E2E_ONEPASSWORD_TOKEN_FILE` privately and enter it in the
   password field. Click **Save a draft**. Observe the normal token-ingress
   POST followed by the backend-credential draft; both must return `201`.
   Retain only the inert credential version and draft/approval IDs. The field
   must be cleared, and neither browser storage nor returned page/JSON may
   contain the token. Never use
   `AWEB_SECRETS_E2E_ONEPASSWORD_WRITER_TOKEN_FILE` for ingress.
3. Obtain the personal approval link from S19's real delivery path. Review the
   frozen token change, then explicitly confirm with a fresh APPROVE passkey
   ceremony. LOGIN alone must not apply it. Confirm through the existing
   ChangeSets/B2/B3 flow; retain its revision receipt. Do not seed or activate
   the credential through a fixture helper or database write.
4. In that same owner tab, submit the agreed reference POST below using
   `window.awebSecretsConsole.post`, which supplies the real S4 cookie and tab
   `X-CSRF-Token`. The complete secret record has backend `onepassword`, kind
   `bearer`, and a newly minted ID/ref for this journey. Use exactly
   `AWEB_SECRETS_E2E_ONEPASSWORD_VAULT_ID`,
   `AWEB_SECRETS_E2E_ONEPASSWORD_ITEM_ID`, and
   `AWEB_SECRETS_E2E_ONEPASSWORD_API_FIELD_ID` (the latter mapped to logical
   field `value`).
   The credential version is the version entered and confirmed above.

   ```text
   POST /installations/{installation_id}/onepassword/references
   {
     "secret": <complete SecretRecord v1 after>,
     "reference": {"vault_id": <vault ID>, "item_id": <item ID>,
                   "fields": {"value": <API field ID>}},
     "credential_version": <entered credential version>
   }
   ```

   Require `201` and exactly these response keys: `v`, `secret_id`, `version`,
   `credential_version`, `vault_id`, `item_id`, `fields`, `item_version`.
   Require v1, the submitted secret ID/selectors/credential version, and
   positive integer binding and item versions. Extra keys fail the scenario;
   never print an unexpected response body. This is the staging-read witness:
   the agreed route awaits the official SDK read against the HO6 vault before
   persisting and returning metadata. The driver must not retrieve the item
   value independently. The returned binding is still inert.
5. Through the same console change-set endpoint, draft `secret/create` followed
   by `onepassword_binding/create`, bringing the returned binding's exact
   secret ID and version in `sealed`. Require a pending draft; it must not
   make the secret usable. Review the frozen change via the personal delivery
   link and perform a distinct fresh APPROVE passkey ceremony, then confirm
   through the sole ChangeSets writer. Check the committed receipt and
   persisted applied projection before continuing to step 2's real agent use.
   A successful reference POST alone must never count as secret creation or
   successful broker use.

Record separate outcomes for token confirmation, external SDK reference
staging, and secret/binding confirmation. Retained evidence contains only
stage/status, revision and non-secret correlation IDs; no tokens, assertions,
email links, SDK items, browser traces or screenshots of value entry. Missing
root mounting, bootstrap/delivery, HO6, reference ingress or supported
secret/binding confirmation is a failed prerequisite, never a skip or a pass.

Train-naapp 16 landed the custody create-only confirmation writer and console
page/router factories on main `dc25f6532` (custody `8ea36caae`, console
`3d72b8e49`). The HTTP guard now permits the audited creation kinds, including
secret and 1Password binding creation; other change operations remain outside
this slice. These components are unmounted. Configuration/reference forms,
the shared B3 fence (`aweb-acgh.18.45`) and root preparation, mounting and the
actual S19 startup/browser fixture remain prerequisites. Run this scenario once those
interfaces and the provisioned HO6 environment are available; component proof
does not establish the real draft-confirm/vault journey.

## Execution and evidence

Implement the scenario against the agreed S19 fixtures when the M1/M2 console,
M3 dispatch, M4 hosted tools, M6/M7 runner and M8 approval interfaces are ready.
Missing environment or an absent route is an unmet prerequisite, not a passing
release. Explicit release execution must fail clearly if required configuration is
missing; it must not silently skip steps or replace services with mocks.

Run named scenario files through the suite lock with `SUITE_LOCK_FOCUSED=1`,
at most two workers and load below 8. Coordinators own covering suites and
gates. Keep one sanitized record of the
exact tested tree and each step's outcome. State which target faults were
shown to fail the assertions, and which sensitivity checks remain owed.

M9 requires independent and Athena review on the exact test head, followed by
secrets' covering train. This document is the acceptance map; executable tests
and a successful complete real-environment run with logs ingest are still required.

## Configuration agreement

Decision 45 fixes `AWEB_SECRETS_E2E_KMS_KEY_ARN`,
`AWEB_SECRETS_E2E_AWS_REGION` and `AWEB_SECRETS_E2E_KMS_CREDENTIALS_FILE`
(AWS shared-credentials format, `[default]` profile). No second profile/name
contract is introduced. The agreed test-vault, hosted MCP and runner input
names are listed in ENVIRONMENT.md for HO6 provisioning.
The hosted transport authentication/session format must come from its owner;
MCP token-file names do not prescribe an authorization scheme.
