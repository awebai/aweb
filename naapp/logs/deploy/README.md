# Run Logs on a customer host

Build from the repository root, using a reviewed checkout:

```sh
docker build --build-arg SOURCE_COMMIT="$(git rev-parse HEAD)" \
  -f naapp/logs/Dockerfile -t customer-logs:reviewed .
```

The build refuses a `SOURCE_COMMIT` that is not a full 40-character commit; the
image reports it as `LOGS_GIT_SHA` in `/health` and as its
`org.opencontainers.image.revision` label. The image runs `aweb_logs.app:serve`
as UID 10001. One listener on port 8765 (`PORT`) serves the public origin and
the reader console by Host. Put it behind a TLS reverse proxy, preserve Host,
and route both hostnames to that listener. The image contains code and
dependencies, never deployment keys or credentials.

Choose the stable `LOGS_APP_ID` and both origins **before** installing the app
on the customer team server. Changing them later orphans every team's
installation. Publish and install the manifest served by this deployment.

## Inputs

Logs reads environment variables only; it does not load a `.env` file from its
working directory. The [service README](../README.md#configuration) gives each
setting's meaning. A customer deployment sets:

| Input | Customer requirement |
| --- | --- |
| `LOGS_DATABASE_URL`, `LOGS_DB_SCHEMA` | Customer PostgreSQL DSN in the private environment file; an app-owned role and schema (default `public`). Migrations run on startup. |
| `LOGS_APP_ID` | Stable customer app id. The hosted id `logs` is refused at any other origin. |
| `LOGS_PUBLIC_ORIGIN` | HTTPS origin of ingest, the manifest and the member tools. |
| `LOGS_CONSOLE_ORIGIN` | Plain HTTPS reader-console origin. Startup refuses the public host itself and any parent of it, where readers' passkeys would be usable from the public host. A subdomain of the public host is accepted. |
| `LOGS_AWID_REGISTRY_URL` | The customer registry, the same one the customer's Secrets uses and the namespace's `_awid` TXT selects. The default is the public `api.awid.ai`. |
| `LOGS_APP_KEY_FILES` | JSON object mapping the four manifest kids to mounted key files, as below. |
| `LOGS_EMAIL_SMTP_HOST`, `LOGS_EMAIL_SMTP_PORT`, `LOGS_EMAIL_TLS`, `LOGS_EMAIL_USERNAME`, `LOGS_EMAIL_PASSWORD_FILE`, `LOGS_EMAIL_FROM`, `LOGS_EMAIL_CA_FILE` | Transactional SMTP for readers' enrolment links. All but TLS (default `starttls`) and the CA are required; the password is read only from its mounted file. |
| `LOGS_EGRESS_DENIED_NETWORKS` | JSON array of the deployment's metadata or internal ranges hook delivery must never reach; default none. |
| `LOGS_HOOK_*` | Optional internal hook destinations and CA, below. |
| `LOGS_GIT_SHA` | Set in the image from `SOURCE_COMMIT`; keep it unchanged at runtime. |

Defaults that a deployment may tune: `LOGS_CHECKPOINT_INTERVAL_SECONDS` (300),
`LOGS_RETENTION_INTERVAL_SECONDS` (3600), `LOGS_CLIENT_EVENTS_PER_MINUTE` (30)
and `LOGS_CLIENT_BYTES_PER_MINUTE` (131072). With no owner retention setting a
team keeps every event.

The app-key mapping uses paths, never key values:

```text
LOGS_APP_KEY_FILES={"logs-chain":"/run/keys/logs-chain","logs-resolve":"/run/keys/logs-resolve","logs-grants":"/run/keys/logs-grants","logs-governance":"/run/keys/logs-governance"}
```

Each file holds the shared K0 format: a 32-byte seed as 64 lowercase hex
characters, with an optional final newline. Generate each key independently
with an approved local secure random source. Never place one in a Dockerfile,
build argument, image layer, repository, command line, email or evidence.
Logs does not start without a key for every declared kid, with a key file for
any other kid, or with the receipt and checkpoint purposes on different keys.

## What each key and access can do

These statements bound what a deployment can claim. A deployment is an
operational grouping, not a security boundary: whoever can reach a key, the
database or the host holds the authority below, whatever their role.

| Key or access | Authority |
| --- | --- |
| `logs-chain` | Signs every receipt and checkpoint. With database write it can rewrite a team's history so that it verifies. |
| Database write, without `logs-chain` | Can delete a team's tail, or the checkpoints after a rewritten point, so that a shorter log still verifies. Can change `key_evidence`, which no hash or signature commits. |
| Database read | Reads every team's retained event content. |
| `logs-governance` | Signs logs' own governance hook events. |
| `logs-resolve`, `logs-grants` | Logs' read authority at the coordination server: hook resolution and each team's installation grant. |
| SMTP password | Sends mail as the configured sender. |

Tampering by whoever holds `logs-chain` and database write is detectable only
against a receipt or checkpoint held outside that boundary: the producer's
stored receipts, or a checkpoint or export a reader keeps. Logs alone cannot
prove a log complete ([what the chain proves](../../../docs/logs-chain.md)).

What this recipe enforces, and what it leaves to the host:

- **Container user.** The service runs as UID 10001. Key files, made readable
  only by that UID and mounted read-only, are out of reach of other UIDs on the
  host. They are not out of reach of root, of the host's container runtime
  administrators, or of any process that runs as UID 10001.
- **Key separation.** The four keys are independent files. Logs runs in one
  process, so a compromise of the service reaches all four. Separate files
  limit what a leaked file grants; they do not contain the process.
- **No key custody service.** Logs reads its keys from files; there is no KMS
  mode. The keys are as protected as the host's file permissions and backups.
- **Agents on the host.** Agents that run on this host as UID 10001, or as
  root, or in the docker group (which is root-equivalent), or that can
  impersonate a principal that can, share the service's
  trust boundary: they can sign as logs and rewrite the database. Running Logs
  on a host that agents do not reach is the deployment's choice; this recipe
  does not demonstrate it.
- **Reader console.** Readers' passkeys are bound to the console host, and the
  console's session cookie never reaches the public origin.
- **Database.** The database role is the customer's to restrict; backups hold
  every retained event's content.

## Hook delivery

Logs delivers its own governance events (`post-governance-hook`) through the
shared hook guard, with the same settings as the
[Secrets recipe](../../secrets/deploy/README.md#hook-delivery-to-customer-logs)
under the `LOGS_` prefix: `LOGS_HOOK_INTERNAL_DESTINATIONS`,
`LOGS_HOOK_INTERNAL_CIDR`, `LOGS_HOOK_INTERNAL_ORIGINS` and `LOGS_HOOK_CA_FILE`.
The default is public-only delivery with system TLS trust. Before the service
starts, every internal origin must resolve inside the CIDR, or startup stops.
`LOGS_HOOK_CA_FILE` is trusted for **every** hook delivery, which is why logs
reads it from its environment only.

## Start and check

```sh
docker run --detach --name customer-logs \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --env-file /absolute/private/customer-logs.env \
  --mount type=bind,src=/absolute/private/logs-keys,dst=/run/keys,readonly \
  --publish 127.0.0.1:8765:8765 \
  customer-logs:reviewed
```

The image's health check calls `/ready` on the public Host. `/ready` returns
200 only when the database and the outbox checks pass; `/health` reports them
and the build identity. Readiness does not prove SMTP delivery, an installed
registration, a delivered event, a reader's sign-in or a verified export.
Verify those operations separately. Do not publish raw container logs or the
private environment file as evidence.

## Reproduce the bounded image proof

After building the image, from `naapp/logs`, under the team's suite lock:

```sh
uv run --frozen --no-sync python e2e/package_lab.py --image customer-logs:reviewed
```

This runs the shared lab (`aweb_naapp_testing.package_lab`): an internal Docker
network, real PostgreSQL, Redis and AWID, an answering TXT DNS server and a TLS
registry, all with generated lab state. It starts the packaged service with its
generated keys and checks database and outbox readiness, the served app id,
DNS-selected signed discovery, refusal of a mismatched registry, certificate
revocation after the configured cache expires, and failure closed after the
directory's 60-second cache expires during a registry outage. It removes its
own containers, network and generated files. It does not claim namespace or
team bootstrap, SMTP delivery, event ingestion, a reader's journey or an
export.
