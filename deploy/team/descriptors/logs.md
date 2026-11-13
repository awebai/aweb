Image: `logs.image`, built from `naapp/logs/Dockerfile` at one SOURCE_COMMIT, user `10001:10001`; same artifact and settings on both platforms.
Port: `8765` HTTP at `logs:8765`; external API and console HTTPS Hosts both route here; no serving TLS key in this container.
Health endpoint: API Host `GET /live` for liveness; `GET /ready` for readiness (database, outbox); `/health` adds build/check detail. Readiness is not owner/hook-activation acceptance.
Depends on: provision mounted files, the dedicated PostgreSQL database/role and the purge ledger's own database/role first; DNS/customer registry/team-server and SMTP reachable; startup applies package migrations/stores before serving. Start before Secrets hook activation; receiver installation, reader designation and passkey enrolment use supported APIs, never seeded rows.

| Schema key | Existing env name or mount | Type/constraint | Default | Purpose |
| --- | --- | --- | --- | --- |
| logs.image | wrapper image reference | Immutable image digest; same in Helm and Compose | required | Build with SOURCE_COMMIT; no credentials in layers |
| logs.secrets | /run/secrets/logs/ | Existing Kubernetes Secret reference or Compose directory reference; read-only | required | Reference only; never credential values in deployment.yaml/env/argv |
| logs.databaseUrlFile | LOGS_DATABASE_URL_FILE | Path to whole UTF-8 DSN, including role password; <=1 KiB, one optional LF | /run/secrets/logs/database-url | Secret file; dedicated logs database and role; replaces env-valued DATABASE_URL |
| logs.purgeLedgerDatabaseUrlFile | LOGS_PURGE_LEDGER_DATABASE_URL_FILE | Path to whole UTF-8 DSN, including role password; <=1 KiB, one optional LF | /run/secrets/logs/purge-ledger-database-url | Secret file; the purge ledger's own database and role (`logsledger` in the bundled PostgreSQL); Logs refuses to start without it, with the variable and the file both set, or when it reaches the content database |
| logs.dbSchema | LOGS_DB_SCHEMA | PostgreSQL schema identifier | public | Plain config; startup migrations use this schema |
| logs.appId | LOGS_APP_ID | Stable installed app ID | required | Plain config; choose before installing served manifest |
| logs.publicOrigin | LOGS_PUBLIC_ORIGIN | Plain HTTPS API origin | required | Plain config; proxy/Ingress preserves external Host; DNS/TLS must match |
| logs.consoleOrigin | LOGS_CONSOLE_ORIGIN | Plain HTTPS console origin on its own host, never a parent of the API host | required | Plain config; passkeys bind this host; proxy routes to same service port |
| logs.awidRegistryUrl | LOGS_AWID_REGISTRY_URL | HTTPS customer registry selected by namespace _awid TXT | required | Plain config; no public-registry writes; URL does not bypass DNS selection |
| logs.awidMemberCredentials | LOGS_AWID_MEMBER_CREDENTIALS | JSON map: team ID -> signing_key_file and certificate_file paths | required for private team | Plain references to service-owned ordinary member credentials; no AWID_SERVICE_TOKEN |
| logs.appKeyFiles | LOGS_APP_KEY_FILES | JSON path map: logs-chain -> /run/secrets/logs/logs-chain; logs-resolve -> /run/secrets/logs/logs-resolve; logs-grants -> /run/secrets/logs/logs-grants; logs-governance -> /run/secrets/logs/logs-governance | required | Plain path references; key bytes are secret files; manifest fixes purpose binding |
| logs.emailSmtpHost | LOGS_EMAIL_SMTP_HOST | SMTP DNS hostname | required | Plain config; endpoint reachable from service |
| logs.emailSmtpPort | LOGS_EMAIL_SMTP_PORT | TCP port 1..65535 | 587 | Plain config; wrapper supplies the selected port explicitly |
| logs.emailTls | LOGS_EMAIL_TLS | starttls or implicit; plaintext refused | starttls | Plain config |
| logs.emailUsernameFile | LOGS_EMAIL_USERNAME_FILE | UTF-8 credential file; <=1 KiB, one optional LF | /run/secrets/logs/smtp-username | Secret file; shared mounted-value source |
| logs.emailPasswordFile | LOGS_EMAIL_PASSWORD_FILE | Mounted UTF-8 password; <=1 KiB, one optional LF | /run/secrets/logs/smtp-password | Secret file; existing email password reader; raw EMAIL_PASSWORD refused |
| logs.emailFrom | LOGS_EMAIL_FROM | Valid sender address | required | Plain config |
| logs.emailCaFile | LOGS_EMAIL_CA_FILE | Optional SMTP CA PEM path | unset | Public trust file reference; no TLS private key in app |
| logs.hookInternalDestinations | LOGS_HOOK_INTERNAL_DESTINATIONS | allowed only; set together with CIDR and origins | unset/public-only | Plain config; private receivers require the complete set |
| logs.hookInternalCidr | LOGS_HOOK_INTERNAL_CIDR | Exact permitted receiver network inside network.servicesCidr; contains all A/AAAA answers | unset | Plain config; operator must bind to actual private services network |
| logs.hookInternalOrigins | LOGS_HOOK_INTERNAL_ORIGINS | JSON array of exact HTTPS installed receiver origins; no wildcard/path | unset | Plain config; Secrets includes Logs public origin when private; Logs only its own governance receivers |
| logs.hookCaFile | LOGS_HOOK_CA_FILE | Optional PEM trust anchors for hook HTTPS | unset/system trust | Public trust file reference; verifies all hook delivery TLS; no client-key setting |
| logs.egressDeniedNetworks | LOGS_EGRESS_DENIED_NETWORKS | JSON array of strict IP/CIDR denials | [] | Plain config; cannot weaken mandatory egress floor |
| logs.clientAddressHeader | LOGS_CLIENT_ADDRESS_HEADER | Optional trusted proxy-overwritten client-IP header | unset/peer address | Plain config; never trust caller-controlled forwarding headers |
| fixed | /tmp | Private writable ephemeral mount; root filesystem may be read-only | ephemeral | Only writable filesystem requirement; all durable state is in PostgreSQL |
| fixed | all /run/secrets/logs mounts | Read-only; never shared with agents or the other service | required | Secret payloads stay out of pod/chart env, values and argv |
| fixed | network peers | Private PostgreSQL; customer AWID/DNS; team aweb HTTPS; SMTP; installed hook receivers | required | No agent access to keys or databases; broker upstream peers are policy-limited |
| logs.checkpointIntervalSeconds | LOGS_CHECKPOINT_INTERVAL_SECONDS | Positive seconds | 300 | Plain config; background signed checkpoints |
| logs.retentionIntervalSeconds | LOGS_RETENTION_INTERVAL_SECONDS | Positive seconds | 3600 | Plain config; background retention uses owner policy |

| File name under `/run/secrets/logs/` | Owner/mode | Who provisions it |
| --- | --- | --- |
| `database-url` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; whole DSN for dedicated role; never chart values/env/argv |
| `purge-ledger-database-url` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; whole DSN for the purge ledger's own role and database; never chart values/env/argv |
| `smtp-username` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; credential payload; never chart values/env/argv |
| `smtp-password` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; credential payload; never chart values/env/argv |
| `awid-member-key` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; independent K0 key material (64 lowercase hex), except AWID member key uses aw-compatible PEM; never chart values/env/argv |
| `logs-chain` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; independent K0 key material (64 lowercase hex), except AWID member key uses aw-compatible PEM; never chart values/env/argv |
| `logs-resolve` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; independent K0 key material (64 lowercase hex), except AWID member key uses aw-compatible PEM; never chart values/env/argv |
| `logs-grants` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; independent K0 key material (64 lowercase hex), except AWID member key uses aw-compatible PEM; never chart values/env/argv |
| `logs-governance` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; independent K0 key material (64 lowercase hex), except AWID member key uses aw-compatible PEM; never chart values/env/argv |
| `awid-member-certificate` | Same service-only owner/read permissions | Customer team authority; JSON certificate matching `awid-member-key`; ordinary service member, no controller key |
| `hook-ca.pem`, `smtp-ca.pem` | Read-only public trust files, `0444` permitted | Operator trust authority; public certificates only, serving/private TLS keys stay with proxy/Ingress |

| Key | Platform | Why no shared form |
| --- | --- | --- |
| `logs.kubernetes.fsGroup` (fixed `10001`) | Kubernetes | Secret projections are root-owned; `0440` plus service-only group makes files readable to UID10001 without agent access |
| `logs.kubernetes.resources`, `logs.kubernetes.imagePullSecrets`, `logs.kubernetes.networkPolicy` | Kubernetes | Cluster resource/registry credentials and peer selectors are Kubernetes objects; no service credential values |
| `logs.compose.bindSources`, `logs.compose.pidsLimit` | Compose | Host paths and process limits are host-runtime details; secret-source ownership/mode must be set on host |
