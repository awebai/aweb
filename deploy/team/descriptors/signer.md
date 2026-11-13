# Independent protected signer

This is the code-owned descriptor for the existing aweb protected host. The team
bundle maps these inputs into its **one `config.schema.json`**, reused as Helm
`values.schema.json`; it does not add a second DSN parser, secret transport or
signer configuration format. The existing public protected-service profile
continues to pin the exact request/human origins, RP, registry, namespace keys,
authority and policy. Public configuration grants no authority.

Source basis: `server/src/aweb/protected_signing/` with the database-URL file
and `/readyz` at `f8947bf94`, and the Compose service body at `1a86d3ff7`.

## Process, image and dependencies

Build the existing `server/Dockerfile` from the **current joined source** with
`AWEB_EXTRA=protected`; use its existing optional-extra support from the joined
lane, not an older Dockerfile without that argument. The deployment supplies the
image repository and immutable source/digest pin. No published protected
image tag is asserted here. The executable remains the existing aweb package:

```text
uvicorn aweb.protected_signing.host:create_app --factory --host 0.0.0.0 --port 8080 --no-proxy-headers
```

Run as **uid/gid 1001:1001**, with both configured external hostnames routed to
container TCP **8080**, preserving Host. The human origin requires TLS. The
shared origin splitter selects the two surfaces; a different Host returns 421.
Use a dedicated signer PostgreSQL database and role, ordinary registered member
credentials for private registry reads, the configured customer AWID registry,
and authenticated TLS SMTP. Redis is not a signer dependency. The PG role owns
the signer's schema/migrations and audit tables; agent workers receive neither
its DSN nor its controller volume. Provisioning authorizer/requester/B3 rows and
the real passkey is separate from startup: a missing binding refuses startup.

Readiness is **GET `/readyz` on the request origin**: fixed `{"ready":true}`/200
only after owned startup, migrations, current provisioning validation and router
mounting finish. Before startup, failed startup and shutdown it is false/503.
Responses are `no-store`; the human origin has no such route. It reveals no key,
profile or subject and performs no remote registry lookup or signing. It is a
lifecycle signal, not a fresh authority, SMTP or database-availability receipt;
protected operations still perform their own checks.

The owned Compose service body is `server/compose.signer.yaml`. It consumes the
shared schema's `x-env` names; the deployment layer adds the image, mounts,
networks, ports and dependencies. Its loopback probe takes the public request
origin as data, derives the Host authority, and ignores ambient HTTP proxies.

Kubernetes `readinessProbe.httpGet` must use port 8080, path `/readyz`, and a Host
header equal to the **authority of `profile.request_origin`**, including a
nondefault port if configured. A raw Pod-IP Host will correctly fail. Compose
can use the same GET via loopback with that Host, for example:

```text
curl --fail --silent --show-error --max-time 2 --header 'Host: <request-origin authority>' http://127.0.0.1:8080/readyz
```

Override the general server image's inherited `/live` port-8000 healthcheck
when selecting this entry point. Probe timing, restart policy and ingress TLS
termination are platform settings; no secret goes in the probe command.

## Host inputs

Paths below are concrete recommended mounts; required fields have no implicit
discovery/default. Environment entries carry only paths or nonsecret metadata.

| Input / environment or mount | Type | Default | Purpose |
| --- | --- | --- | --- |
| `AWEB_PROTECTED_PROFILE_FILE` → `/etc/aweb/signer/profile.json:ro` | path to existing public profile JSON | required | Exact origins/RP and public registry/key/policy references; no URL from a response. |
| `AWEB_PROTECTED_SCOPE_FILE` → `/etc/aweb/signer/scope.json:ro` | path to one complete profile binding scope | required | Explicit selected team-controller/H association and generation. |
| `AWEB_PROTECTED_DATABASE_URL_FILE` → `/run/secrets/signer/database-url:ro` | path; whole UTF-8 DSN, optional final LF, at most 1 KiB | required in the team bundle | Existing shared file reader; existing pgdbm/asyncpg adapter parses the DSN. No split password/user transport. |
| `AWEB_PROTECTED_DATABASE_SCHEMA` | lowercase schema identifier | `protected_signer` | Tables within the dedicated signer database. |
| `AWEB_PROTECTED_DATABASE_USES_TRANSACTION_POOLER` | boolean | `false` | Existing database adapter's transaction-pooler settings. |
| `AWEB_PROTECTED_CONTROLLER_KEY_FILE` → `/run/secrets/signer/private-controller/controller.key:ro` | private real file, 64-hex-character seed with optional LF | required | Actual team-controller custody, matching profile and current registry. |
| `AWEB_PROTECTED_MEMBER_KEYS_FILE` → `/run/secrets/signer/members.json:ro` | path to existing team-ID → PEM-file manifest | required | Ordinary member keys for private registry reads; relative paths resolve from this manifest. Controller substitution refuses. |
| Member PEM files → `/run/secrets/signer/member-*.pem:ro` | existing aw `ED25519 PRIVATE KEY` format | required referenced files | Registered member credentials and certificates, separate from controller custody. |
| `AWEB_PROTECTED_WORKER_UIDS` | JSON array of positive integer UIDs | required | Actual untrusted worker UIDs; none may be 0 or signer uid 1001. Do not omit a worker to bypass isolation. |
| `AWEB_PROTECTED_HUMAN_CSRF_KEY` | trusted ASCII storage-key identifier | `aweb.protected.console.csrf` | Shared page/LOGIN/governance wiring; not a secret or approval credential. |
| `AWEB_PROTECTED_TRUSTED_CLIENT_HEADER` | optional header name | unset | Limiter identity only; proxy must overwrite it and block direct access. Default ignores forwarded headers. |
| `AWEB_PROTECTED_EMAIL_SMTP_HOST`, `...EMAIL_SMTP_PORT` | hostname, TCP port | required | Existing outbound notification transport. |
| `AWEB_PROTECTED_EMAIL_TLS` | `starttls` or `implicit` | `starttls` | SMTP requires TLS. |
| `AWEB_PROTECTED_EMAIL_USERNAME`, `...EMAIL_FROM` | nonsecret account identifier, sender address | required | Existing SMTP metadata, not password values. |
| `AWEB_PROTECTED_EMAIL_PASSWORD_FILE` → `/run/secrets/signer/smtp-password:ro` | path to UTF-8 password | required | Existing shared Mailer file input. |
| `AWEB_PROTECTED_EMAIL_CA_FILE` → platform CA bundle `:ro` | optional path to public trust roots | system roots | Custom SMTP CA when needed. |

The existing `AWEB_PROTECTED_DATABASE_URL` value input remains compatible with
the current test lane, but the team bundle **omits it**. Setting it together with
`DATABASE_URL_FILE` refuses ambiguous configuration. File resolution preserves
the existing `HostSettings.database_url` SecretStr port for fixture/bootstrap
callers; DSN bytes do not enter environment values, argv or startup errors.

## Secret files and materialization

Only the signer container receives these mounts. No worker, CLI sidecar,
debugger or backup policy may expose the controller key. Mounted credential
files must not be group/world writable; the stricter controller rules below
are mandatory.

| Secret filename under `/run/secrets/signer` | Runtime uid/gid and mode | Provisioner |
| --- | --- | --- |
| `database-url` | recommended `1001:1001`, 0400; readable projected root-owned 0440/0444 files also use the existing shared file reader | Platform PostgreSQL provisioner: dedicated database/role, whole DSN. |
| `private-controller/controller.key` | **1001:1001, 0400** (0600 also supported); real parent directory **1001:1001, 0700** | Authorized controller custodian → private-volume materializer. No runtime key generation/import on a miss. |
| `member-*.pem` | recommended `1001:1001`, 0400, read-only signer mount | Existing team membership provisioner, with valid ordinary member certificates. |
| `smtp-password` | recommended `1001:1001`, 0400; readable nonwritable projected file supported by existing reader | Platform mail-account provisioner. |

A Kubernetes projected Secret's root-owned symlink is **not** controller
custody. Mount its source only in a trusted materialization init container;
copy the already-authorized key bytes to a private volume, make the real
directory uid/gid 1001:1001 mode 0700 and the real key uid/gid 1001:1001 mode
0400, then give only the signer a read-only mount of that volume at
`/run/secrets/signer/private-controller`. The runtime container does not receive
the projected source mount. Establish final modes after platform ownership
handling; do not rely on fsGroup or relax the adapter's `O_NOFOLLOW`, owner or
mode checks. Compose uses the same private-volume contract, materialized by
its trusted provisioning step. Other ordinary secret-file inputs may follow
projected symlinks through the existing file reader.

## Platform-only settings

| Platform-only input | Why it stays outside the signer/profile |
| --- | --- |
| Image repository/digest, build source and `AWEB_EXTRA=protected`, entrypoint/8080 | Artifact selection and process launch; no new signer implementation or published-pin assumption. |
| One bundle `config.schema.json` reused as `values.schema.json` | Helm and Compose validate the same nonsecret configuration source; no copied signer schema/parser. |
| Secret resources, private-volume init/materialization, runAs uid/gid and worker UIDs | Platform enforces filesystem/process/mount isolation; a Secret name or pod label cannot grant custody. |
| Dedicated PG role/database and first provisioning/migration procedure | Establishes the declared SQL and B3 bindings; startup never bootstraps authority on a miss. |
| TLS ingress/DNS for the two profile origins and RP, service/probe Host, trusted proxy network | Platform transport/routing must match the exact existing profile; host headers do not select proof authority. |
| Readiness timing, resource limits, restart/replica policy, network policy and SMTP CA delivery | Operational availability and placement; not human approval or current registry evidence. |

The signed revoke act is retained in the receipt and local transactional audit.
This process does not apply it remotely. The joined aw/browser flow remains the
integration priority; this descriptor and the two host inputs do not repin or
interrupt its current run.

Operator bootstrap and key runbook: [HOST.md](../../../server/src/aweb/protected_signing/HOST.md#first-operator-enrollment).
Use the same package's local `python -m aweb.protected_signing.operator bootstrap`
under the protected uid and private mounts before serving; the emailed link now
uses the mounted shared `/enrolment` page and real B3 UV registration. The
operator action is once-only, with exact pending resumption and no replacement
or recovery. `install-controller --source-pem <private-file>` creates the
validated private hex-seed file without overwriting. The owner's protected
offline controller copy is the backup; preserve the private database and
consumed-bootstrap history separately. Controller rotation/recovery remains a
separate protected operation, never a reset of this bootstrap.
