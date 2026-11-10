# Run Secrets on a customer host

Build from the repository root, using a reviewed checkout:

```sh
docker build --build-arg SOURCE_COMMIT="$(git rev-parse HEAD)" \
  -f naapp/secrets/Dockerfile -t customer-secrets:reviewed .
```

The image runs the existing production root as UID 10001, without a runner or
supervisor. One listener on port 8770 serves the agent API and human console by
Host. Put it behind a TLS reverse proxy, preserve Host, and route both public
hostnames to that listener. The console hostname is its passkey relying party;
use a separate hostname from the agent API. Proxy headers are disabled. The
image contains code and dependencies, never deployment keys or credentials.

Choose the stable `SECRETS_APP_ID` and both origins **before** installing the
app on the customer team server. Changing these later does not migrate an
installation. Publish and install the manifest served by this deployment,
not another service's manifest.

Create a private operator environment file (0600) and a key directory readable
only by UID 10001. Mount that directory read-only at `/run/keys`. Supply every
required key separately; generate key material with an approved local secure
random source and never place it in a Dockerfile, build argument, image layer,
repository, command line, email or evidence. The startup constructor checks key
files, independent key material, manifest purposes and custody choice. It reads
environment variables only; it does not load a checkout's `.env`.

| Input | Required setting |
| --- | --- |
| `SECRETS_DATABASE_URL` | Customer PostgreSQL DSN; migrations run on startup. Keep the DSN in the private environment file. |
| `SECRETS_DB_SCHEMA` | App schema, default `public`; use an app-owned database role. |
| `SECRETS_APP_ID` | Stable customer app ID, chosen before installation. |
| `SECRETS_PUBLIC_ORIGIN` | HTTPS agent API origin. |
| `SECRETS_CONSOLE_ORIGIN` | Distinct HTTPS console origin. |
| `SECRETS_AWID_REGISTRY_URL` | Customer registry origin, matching the namespace's `_awid` TXT `registry=` selection. |
| `SECRETS_KMS_KEY_ID`, `SECRETS_KMS_REGION` | Recommended custody: customer AWS KMS key and region. Give the runtime's AWS role the required key operations; no static AWS keys in the image. |
| `SECRETS_CUSTODY_KEY_FILE` | Mounted local custody key, allowed in production and lab deployments. Configure exactly one of this or KMS. Keep the file private to the Secrets service account. |
| `SECRETS_SECRET_REQUEST_KEY_FILE` | Independent mounted request-sealing key. |
| `SECRETS_SECRET_PARAMS_KEY_FILE` | Independent mounted parameter-sealing key. |
| `SECRETS_RESPONSE_KEY_FILE` | Independent mounted response-sealing key. |
| `SECRETS_RUNNER_SERVICE_KEY_FILE` | Independent mounted runner service signing key; no runner runs in this container. |
| `SECRETS_APP_KEY_FILES` | JSON object mapping all four manifest kids to mounted Ed25519 key files, as shown below. |
| `SECRETS_MANIFEST_REQUEST_KEY_FILE` | Independent mounted single-purpose manifest-hook HMAC key. |
| `SECRETS_EMAIL_SMTP_HOST`, `SECRETS_EMAIL_SMTP_PORT` | Transactional SMTP server and port (default 587). |
| `SECRETS_EMAIL_TLS` | `starttls` (default) or `implicit`; TLS is required. |
| `SECRETS_EMAIL_USERNAME`, `SECRETS_EMAIL_PASSWORD_FILE`, `SECRETS_EMAIL_FROM` | Provider login, mounted password file and sender address. |
| `SECRETS_EMAIL_CA_FILE` | Optional mounted SMTP CA. |
| `SECRETS_EGRESS_DENIED_NETWORKS` | JSON array of deployment egress/metadata IP addresses or strict CIDRs; explicitly use `[]` if there are no additional ranges. Applies to broker **and hook** egress. |
| `SECRETS_GIT_SHA` | Set in the image from the required full 40-character `SOURCE_COMMIT` build argument; keep it unchanged at runtime. |

The app-key mapping uses paths, never key values:

```text
SECRETS_APP_KEY_FILES={"secrets.hook-event-1":"/run/keys/hook-event","secrets.hook-delivery-1":"/run/keys/hook-delivery","secrets:grant-read-1":"/run/keys/grant-read","secrets:hook-resolve-1":"/run/keys/hook-resolve"}
```

The shared K0 key-file format is a 32-byte seed encoded as 64 lowercase hex
characters, with an optional final newline, in a private file. See the
[service README](../README.md) for key purposes and existing operator inputs.

AWS KMS is recommended, with key policy and an independent audit trail, but it
is not required. Local key-file custody avoids the KMS dependency. Anything
that can read that key file can decrypt every stored value, so run Secrets
under its own OS account and make the key unreadable by agents. Use a private
parent directory and mode 0600, mount the file read-only, and protect backups
with the same boundary. The existing loader checks are not a guarantee of
read isolation. Loss of the key prevents decryption of its stored values.
An authorized service can decrypt with either provider; neither makes the
service zero-knowledge.

For the customer's Logs service, set `LOGS_AWID_REGISTRY_URL` to the **same**
customer registry. DNS selection, signed team-server discovery, current
membership, revocation and bounded freshness remain the existing contracts.
Setting the URL does not bypass DNS or authorize a different registry. A
namespace selecting another registry refuses with `registry_mismatch`.

## Hook delivery to customer Logs

Public-only delivery with system TLS trust is the default. Install the actual
served Logs manifest and activate both governance and use-hook registrations
through the existing owner flow. A hostname or an environment setting alone
does not install, designate or authorize a receiver.

For an internal Logs origin, set all three inputs together:

```text
SECRETS_HOOK_INTERNAL_DESTINATIONS=allowed
SECRETS_HOOK_INTERNAL_CIDR=10.20.30.0/24
SECRETS_HOOK_INTERNAL_ORIGINS=["https://logs.customer.example"]
SECRETS_HOOK_CA_FILE=/run/keys/hooks-ca.pem
```

These are documentation addresses; select the customer's actual network and
installed Logs origin. `allowed` is the only enabling value. A partial set,
empty origin list, wildcard, origin with a path, non-HTTPS origin, CIDR with host
bits, overly broad CIDR or overlap with the mandatory address floor refuses
startup. Origins normalize to the installed form: lowercase host, default
`:443` omitted, non-default port preserved. Before starting the runtime, every
A and AAAA answer must lie inside the CIDR and pass the deployment denials and
mandatory floor. DNS failure or any refused answer stops startup. Delivery
re-resolves and checks again, so a later DNS change does not bypass the guard.

`SECRETS_HOOK_CA_FILE` is optional, including for public delivery; it adds trust
anchors while keeping certificate verification. This trust applies to **all
hook deliveries**, including public origins outside the internal allowlist;
choose a CA authorized for that scope. Broker `SECRETS_EGRESS_CA_FILE`
and `SECRETS_INTERNAL_DESTINATIONS` are independent and never implicitly reused.
Unlisted origins retain public-only behavior; a registration cannot choose a
new internal origin or widen the operator set.

The hosted HO5 restriction is separate: hosted production must not set
`hook_internal_cidr` until Juan lifts that hold through Hestia. This customer
recipe and environment interface do not lift it.

## Start and check

```sh
docker run --detach --name customer-secrets \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --env-file /absolute/private/customer-secrets.env \
  --mount type=bind,src=/absolute/private/secrets-keys,dst=/run/keys,readonly \
  --publish 127.0.0.1:8770:8770 \
  customer-secrets:reviewed
```

The environment file supplies runtime configuration, including paths under
`/run/keys`; never pass key bytes as environment variables. Ensure mounted
files are readable by the container UID and satisfy the existing key-file
permission checks. No key files are generated by startup.

Check `/ready` using the configured agent Host through the reverse proxy. It
returns 200 only when the database, custody canary and outbox checks pass;
`/health` reports their booleans and numeric backlog detail, plus build identity.
Both `/health` and `/ready` report `labels.custody_mode` as `kms` or
`local_key_file`, derived from the selected provider even if its canary fails.
`checks.kms` is the existing selected-provider canary slot; the mode label
distinguishes which provider it checked.
A key-file run never counts as an AWS KMS proof. Readiness does not prove
SMTP delivery, an installed Logs registration, an owner ceremony or a complete
customer demo. Verify those actual operations separately. Do not publish raw
container logs or private environment files as acceptance evidence.

## Reproduce the bounded image proof

After building the image, from `naapp/secrets`, under the team's suite lock:

```sh
uv run --frozen --no-sync python e2e/package_lab.py --image customer-secrets:reviewed --source-commit "$(git rev-parse HEAD)"
```

Pass the commit used to build the image; the command assumes this checkout
still matches it. The lab checks the image's default UID/GID without a user
override, then requires its revision label and served build SHA to match that
commit. The mounted-fixture service processes continue to use the host UID.

This creates an internal Docker network, real PostgreSQL/Redis/AWID, an
answering TXT DNS server and a TLS registry, all with generated synthetic lab
state. It starts the packaged root and checks database/local-custody canary/
outbox readiness, the served app ID, real DNS-selected signed discovery,
mismatched-registry refusal, actual certificate revocation after the configured
cache expires, and failure after the unmodified directory's 60-second cache
expires during a real registry outage. It removes its own containers, network
and private generated files. External authority rows are fixture setup; the
proof does not claim customer namespace/team bootstrap, SMTP delivery, AWS KMS
or the full LF demo. The focused production-hook tests separately exercise the
environment loader with real DNS/TLS and the existing shared outbox drain into
the actual Logs ingest root, checking its persisted event and signed receipt.
Their [Logs fixture](../tests/production_logs.py) uses the existing S19 serving
lifecycle and actual served Logs manifest. Receiver installation and activated
bindings are external fixture preconditions; the owner activation ceremony and
designated-reader journey remain separate acceptance.
