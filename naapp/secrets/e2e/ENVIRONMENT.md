# First-release E2E inputs

These names are agreed by custody (decision 45 and b683f05d), app (f17d7b7f),
roles (e218463c), and runner (7165fe6d). HO6 provisions the dedicated test
resources. Supply values privately to the E2E runner; never put them in this
repository, messages or retained evidence.

| Variable, under `AWEB_SECRETS_E2E_` | Input |
| --- | --- |
| `KMS_KEY_ARN` | Dedicated test KMS key ARN. |
| `AWS_REGION` | Test KMS region. |
| `KMS_CREDENTIALS_FILE` | Private AWS shared-credentials file, `[default]` profile (decision 45). |
| `ONEPASSWORD_TOKEN_FILE` | Private UTF-8 token file for the test vault's read-only service account. |
| `ONEPASSWORD_WRITER_TOKEN_FILE` | Separate private test-vault fixture-writer token file for setup/item-version updates. Never supplied to the application. |
| `ONEPASSWORD_VAULT_ID` | Stable dedicated test vault ID. |
| `ONEPASSWORD_ITEM_ID` | Stable dedicated test item ID. |
| `ONEPASSWORD_API_FIELD_ID` | API credential field ID. |
| `ONEPASSWORD_CLI_FIELD_ID` | CLI password field ID. |
| `API_ORIGIN` | Absolute HTTPS agent API origin. |
| `CONSOLE_ORIGIN` | Absolute HTTPS human console origin, separate from the agent API. |
| `LOGS_ORIGIN` | Absolute HTTPS logs manifest, ingest and agent origin; maps to `LogsSettings.public_origin` / `LOGS_PUBLIC_ORIGIN`. |
| `LOGS_CONSOLE_ORIGIN` | Required absolute HTTPS logs reader-console origin, with a hostname distinct from `LOGS_ORIGIN` even when ports differ; maps to `LogsSettings.console_origin` / `LOGS_CONSOLE_ORIGIN`. The passkey RP ID is this hostname. |
| `PRIVATE_DNS_NAME` | Bare DNS hostname whose HO6-controlled answer is private, for the network-refusal case. No scheme, port, URL path or IP literal; no TLS is required. |
| `MCP_URL` | Shared absolute HTTPS root MCP endpoint URL, with no credential/query/fragment. |
| `TEAM_ID` | Expected public team ID for both MCP clients. |
| `AGENT_A_ID` | Expected public ID of hosted agent A. |
| `AGENT_B_ID` | Expected public ID of hosted agent B, different from A. |
| `AGENT_A_MCP_TOKEN_FILE` | Private raw OAuth access-token file for A's normal authorized connection. |
| `AGENT_B_MCP_TOKEN_FILE` | Separate private raw OAuth access-token file for B's connection. |
| `RUNNER_BINARY` | Absolute path to the checkout-built runner executable. |
| `RUNNER_CONFIG_FILE` | Absolute path to M7's job/configuration file. |
| `RUNNER_USER` | Pre-provisioned dedicated runner OS username. |
| `RUNNER_STATE_DIR` | Absolute private state directory owned by the runner UID. |

`AGENT_A_IDENTITY_HOME` and `AGENT_B_IDENTITY_HOME` are optional only for an
independently selected `aw` control, if a test needs one. They are not required
for the hosted journey and do not authenticate hosted HTTP MCP.

`AWEB_SECRETS_E2E_LOGS_CONSOLE_ORIGIN` has no fallback to logs' ingest origin
or secrets' console. S19 supplies it in its local combined runtime publication;
the hosted provisioning controller's six outputs stay unchanged. S19 starts
logs with both explicit origins and activates its governance production and
registration before obtaining the pending reader slot from logs. The owner
signs designation for that issued slot; S19 follows logs' actual enrolment
delivery and enrols/logs in on the logs-console origin. It never derives a
reader scope from contact data. M9 reads through that reader session.

The hosted transport owner's contract is Streamable HTTP with normal OAuth
access tokens, one separate client per agent. Use the supplied SDK recipe and
verify each client's `whoami` public team/agent IDs before mutations. Follow
tool pagination and check protocol/tool errors and structured application
results. A successful HTTP status alone is insufficient. Identity homes are
not an alternative HTTP signing/authentication path.

`AWEB_SECRETS_E2E_PRIVATE_DNS_NAME` is distinct from the public API origin and
the positive test receiver. Preflight checks hostname syntax only, without
resolving it or connecting. The real network scenario must observe the
HO6-provisioned private answer and verify that dispatch is refused. The
hostname alone does not prove the DNS record exists or has the intended answer.

There is no required `AWEB_SECRETS_E2E_UPSTREAM_ORIGIN`. S19 owns starting the
checkout's test receiver, choosing its listening address/port and configuring
TLS trust. It passes the resulting origin internally to M9 and the pinned CLI
job configuration; an externally hosted receiver is not an alternate input.

E2E reads the test 1Password token file and enters that token through the
customer console's normal passkey-confirmed value ingress. Native custody
seals it per team; the backend opens it per use. The product has no file-token
loader or operator-wide 1Password service-account credential. The fixture
writer is used only for dedicated test-vault setup/update and must never be
substituted for the app's read-only account.

Run `uv run python e2e/release_environment.py` from `naapp/secrets` to check
required configuration references. It exits 2 with variable names if inputs
are absent or invalid, without printing supplied values or opening credential
files. Credential inputs must be owner-readable private regular files. The
check verifies configuration, not service connectivity or release acceptance.

## Provision the dedicated hosted team

`AWEB_SECRETS_E2E_CLOUD_OWNER_LOGIN_FILE` is a provisioning-only input. It is
not required by `load_environment` or supplied to the app, MCP clients or runner.
HO6 supplies the dedicated verified human account. Its `cloud-owner-login.txt`
file must be a regular file owned by the controller's OS user with mode `0600`.
The controller reads it without following a symlink and never overwrites it.
Use exactly two nonempty UTF-8 lines without BOM, with LF line endings: email
on line 1, password on line 2, no leading/trailing whitespace. A single final
LF is optional. Never put the values in command arguments or this repository.

From `naapp/secrets`, run the checkout controller with the operator-supplied
HTTPS Cloud origin and an absolute, dedicated private state directory:

```text
uv run --no-sync python e2e/provision_hosted.py --cloud-origin <HTTPS Cloud origin> --state-dir <absolute private directory>
```

The controller first creates a dedicated organization with slug
`awtest-secrets-<random label>` so its hosted namespace starts with `awtest-`.
It creates the test team with that organization's explicit `owner_org_id` and
the same name/slug. A team slug alone does not select its namespace: omitting
`owner_org_id` would select the owner's personal organization. Completed reruns
keep the persisted organization and team; this does not rename older teams.
The controller activates one test role,
creates two global custodial agents in that role, and authorizes one normal
OAuth/PKCE connection for each. Owner login uses a separate in-memory cookie
session. Owner cookies, the login password and returned identity API keys are
not MCP authority or runtime outputs. The controller uses two independent
official MCP clients at the root endpoint and checks canonical team ID and each
agent ID before publishing outputs. Management UUIDs are not canonical team IDs.

After success the private state directory contains `runtime.json`, whose six
string keys all carry the `AWEB_SECRETS_E2E_` prefix: `TEAM_ID`, `AGENT_A_ID`, `AGENT_B_ID`, `MCP_URL`,
`AGENT_A_MCP_TOKEN_FILE` and `AGENT_B_MCP_TOKEN_FILE`. The two files contain only
their raw OAuth access token, have absolute distinct paths and mode `0600`.
Refresh pairs and client bindings remain in `controller-state.json` (`0600`),
inside the `0700` directory. Neither credentials nor codes appear in console
output. Protect this directory as credentials; never retain it as test evidence.

Writing `runtime.json` does not configure S19 automatically. S19 explicitly
loads that JSON mapping and merges it with its remaining HO6 inputs before
validation, without shell evaluation or a dotenv loader:

```python
runtime_inputs = json.loads((controller_state_dir / "runtime.json").read_text())
environment = load_environment({**os.environ, **runtime_inputs})
```

A completed rerun refreshes the stored current grants without another consent,
persists each rotated pair before publishing access-only files, and checks both
identities again. The owner login file is not read for that refresh. Concurrent
controllers refuse. An intent journal is written before remote side effects;
a partial run or lost exchange/refresh response refuses on rerun, since the
remote operation may have committed. It never repeats creates, adopts a
duplicate-name object or retries a consumed code/refresh token. Inspect the
recorded stage with the hosted owner to recover explicitly; do not delete the
journal or use a fresh directory to bypass the refusal. Expired/revoked grants
require the normal owner authorization path, never an API key or CLI-token
substitute. No automatic remote cleanup runs on failure.

## Runner and release acceptance

S19 launches the real runner under its pre-provisioned OS user. M7's `doctor`
checks config/job/executable ownership, write authority and UID separation;
its state directory is 0700 and keys/journal are 0600. Preflight does not try
to traverse another user's private state or create users. Full scenario tests
must still establish real broker effects, passkey approvals, durable job
execution, revocation and audit ingestion into logs as described in RELEASE.md.

## BYOT native/KMS lab profile

The LF rehearsal uses a separate, explicit profile. It neither calls the hosted
provisioner nor changes the 24 required release inputs or their acceptance.
`lab_environment.load_lab_environment(mapping, private_dns=...)` selects exactly
these 18 names, under the same `AWEB_SECRETS_E2E_` prefix:

| Group | Suffixes |
| --- | --- |
| Team and services | `TEAM_ID`, `API_ORIGIN`, `CONSOLE_ORIGIN`, `LOGS_ORIGIN`, `LOGS_CONSOLE_ORIGIN` |
| Native custody | `KMS_KEY_ARN`, `AWS_REGION`, `KMS_CREDENTIALS_FILE` |
| Separate-user runner | `RUNNER_BINARY`, `RUNNER_CONFIG_FILE`, `RUNNER_USER`, `RUNNER_STATE_DIR` |
| CLI selection | `AW_BINARY`, `HUMAN_IDENTITY_HOME`, `AGENT_A_IDENTITY_HOME`, `AGENT_B_IDENTITY_HOME` |
| Customer authority | `AWID_REGISTRY_URL`, `COORDINATION_ORIGIN` |

Binary and identity-home paths are absolute. Agent homes are the actual credential
directories used by `aw --identity-home`, usually the selected workspace's `.aw`.
The human home is the public `HumanRecordDir` under the driver's
`~/.awid/humans/<normalized-domain>/<stable-id-suffix>`, as created by the
protected human initializer. Its public `identity.yaml` must resolve back to that
canonical directory and name a registered human.
There is no fallback to the driver identity. All three homes and their certified
principals are distinct. `AWID_REGISTRY_URL` and `COORDINATION_ORIGIN` are HTTPS
origins without credentials, query strings or fragments. Service-origin separation
has the same rules as the release profile. The KMS key ARN must name the selected
region; the AWS credential reference is a private regular file, never opened by
the reference checker. KMS is required: this profile offers no local-key fallback.

`RUNNER_USER` must resolve to a real non-root OS account different from the driver.
The checker does not traverse its protected config/state. S19 must still use
the single `RunnerHarness` and approved supervisor/launcher, verify the actual
worker PID/UID and protected job pins, and preserve its journal across restart.
An account lookup alone is not separate-user execution proof.

Choose DNS coverage explicitly with `private_dns="included"` or `"excluded"`.
Included coverage additionally requires the bare hostname `PRIVATE_DNS_NAME`;
S19 must exercise the real private-answer/refusal scenario. Excluded means that
scenario is outside lab coverage, never that it passed. The reference check
does not resolve DNS. External tunnel reachability is an independent requirement.

The command below performs reference checks only and exits 2 for missing or
invalid configuration, reporting selector names rather than supplied values:

```text
uv run --no-sync python e2e/lab_environment.py --private-dns excluded
```

The owning S19 context publishes the validated lab references and current actor
metadata explicitly, without the hosted `publish_runtime`:

```python
from lab_publication import publish_lab_runtime

async with publish_lab_runtime(
    lab_inputs, private_dns="excluded", directory=new_absolute_publication_dir,
) as path:
    snapshot = json.loads(path.read_text())
    # snapshot["inputs"] is the selected lab input mapping.
    # snapshot["actors"] records canonical DIDs and certificate IDs.
    # Start/verify the real services and separate-user runner in S19.
```

Publication runs the selected checkout CLI's offline local certificate/key
checks for agents. For HUMAN it reads public records only, verifies the human-kind
ID chain against fresh registry status and independent namespace DNS authority,
and records `custody="not_tested"` and `signing_readiness="not_tested"`.
It never calls the foreground human signer, reads the encrypted key store,
or reads or requires a human `signing.key`. An agent identity cannot substitute
for the human. The actual protected human gesture in the rehearsal establishes
signing readiness. Namespace DNS verification is required even when the separate
private-address refusal scenario is excluded.

For every actor publication verifies the current certificate against the selected AWID
registry, verifies the team's signed coordination-server record, and resolves
any `did:aw` to its current key. An unavailable, revoked or mismatched authority
refuses publication. CLI probes inherit neither driver API keys nor identity,
proxy or checkout dotenv configuration. Public identity metadata that selects a
different registry or server is refused. This certifies membership prerequisites,
not resource grants, human user verification, B2/B3 confirmation or readiness.

The new publication directory is 0700 and its sole `runtime.json` is 0600;
an existing directory is never adopted. The context removes its own snapshot
on normal exit or caller failure. The JSON has `profile="byot-native-kms-lab/1"`,
`inputs`, `actors`, the configured account's `runner_uid`, and `coverage` with
the selected DNS scenario and `full_release_gate=false`. It contains references
and public metadata, not entered values or command streams. The optional
`registry_transport` argument supports S19's real in-process registry, as the
runtime does; normal operation uses the configured registry over HTTPS.

The lab uses direct protected native-value input and real KMS. Its profile does
not require 1Password, Cloud accounts, hosted agent IDs, MCP OAuth files or a
hosted MCP endpoint. Those inputs are never adopted as BYOT authority. Protected
human terminal input and one-time runner-code delivery remain the reviewed G-B
client flow; no native-value/code file workaround is introduced. S19 still owns
actual service/bootstrap/TLS/SMTP configuration and installation/grant setup;
the typed job and its synthetic database fixture supply their reviewed target.
Passing this lab never satisfies the supported-backend or full release gate.
