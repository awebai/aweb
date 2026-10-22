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
| `LOGS_ORIGIN` | Absolute HTTPS logs origin for real audit ingestion/read proof. |
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

The hosted transport owner's contract is Streamable HTTP with normal OAuth
access tokens, one separate client per agent. Use the supplied SDK recipe and
verify each client's `whoami` public team/agent IDs before mutations. Follow
tool pagination and check protocol/tool errors and structured application
results. A successful HTTP status alone is insufficient. Identity homes are
not an alternative HTTP signing/authentication path.

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

S19 launches the real runner under its pre-provisioned OS user. M7's `doctor`
checks config/job/executable ownership, write authority and UID separation;
its state directory is 0700 and keys/journal are 0600. Preflight does not try
to traverse another user's private state or create users. Full scenario tests
must still establish real broker effects, passkey approvals, durable job
execution, revocation and audit ingestion into logs as described in RELEASE.md.
