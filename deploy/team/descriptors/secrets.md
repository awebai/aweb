Image: `secrets.image`, built from `naapp/secrets/Dockerfile` at one SOURCE_COMMIT, user `10001:10001`; same artifact and settings on both platforms.
Port: `8770` HTTP at `secrets:8770`; external API and console HTTPS Hosts both route here; no serving TLS key in this container.
Health endpoint: API Host `GET /live` for liveness; `GET /ready` for readiness (database, custody canary, outbox); `/health` adds build/check detail. Readiness is not owner/hook-activation acceptance.
Depends on: provision mounted files and dedicated PostgreSQL database/role first; DNS/customer registry/team-server and SMTP reachable; startup applies package migrations/stores before serving. Internal-hook DNS/TLS preflight runs before stores. Install manifests and activate hook bindings through supported owner APIs after both services are ready; start the journey after that.

| Schema key | Existing env name or mount | Type/constraint | Default | Purpose |
| --- | --- | --- | --- | --- |
| secrets.image | wrapper image reference | Immutable image digest; same in Helm and Compose | required | Build with SOURCE_COMMIT; no credentials in layers |
| secrets.secrets | /run/secrets/secrets/ | Existing Kubernetes Secret reference or Compose directory reference; read-only | required | Reference only; never credential values in deployment.yaml/env/argv |
| secrets.databaseUrlFile | SECRETS_DATABASE_URL_FILE | Path to whole UTF-8 DSN, including role password; <=1 KiB, one optional LF | /run/secrets/secrets/database-url | Secret file; dedicated secrets database and role; replaces env-valued DATABASE_URL |
| secrets.dbSchema | SECRETS_DB_SCHEMA | PostgreSQL schema identifier | public | Plain config; startup migrations use this schema |
| secrets.appId | SECRETS_APP_ID | Stable installed app ID | required | Plain config; choose before installing served manifest |
| secrets.publicOrigin | SECRETS_PUBLIC_ORIGIN | Plain HTTPS API origin | required | Plain config; proxy/Ingress preserves external Host; DNS/TLS must match |
| secrets.consoleOrigin | SECRETS_CONSOLE_ORIGIN | Distinct plain HTTPS console origin | required | Plain config; passkeys bind this host; proxy routes to same service port |
| secrets.awidRegistryUrl | SECRETS_AWID_REGISTRY_URL | HTTPS customer registry selected by namespace _awid TXT | required | Plain config; no public-registry writes; URL does not bypass DNS selection |
| secrets.awidMemberCredentials | SECRETS_AWID_MEMBER_CREDENTIALS | JSON map: team ID -> signing_key_file and certificate_file paths | required for private team | Plain references to service-owned ordinary member credentials; no AWID_SERVICE_TOKEN |
| secrets.appKeyFiles | SECRETS_APP_KEY_FILES | JSON path map: secrets.hook-event-1 -> /run/secrets/secrets/hook-event; secrets.hook-delivery-1 -> /run/secrets/secrets/hook-delivery; secrets:grant-read-1 -> /run/secrets/secrets/grant-read; secrets:hook-resolve-1 -> /run/secrets/secrets/hook-resolve | required | Plain path references; key bytes are secret files; manifest fixes purpose binding |
| secrets.manifestRequestKeyFile | SECRETS_MANIFEST_REQUEST_KEY_FILE | Independent manifest-hook HMAC key path | /run/secrets/secrets/manifest-request-key | Secret file reference |
| secrets.emailSmtpHost | SECRETS_EMAIL_SMTP_HOST | SMTP DNS hostname | required | Plain config; endpoint reachable from service |
| secrets.emailSmtpPort | SECRETS_EMAIL_SMTP_PORT | TCP port 1..65535 | 587 | Plain config; wrapper supplies the selected port explicitly |
| secrets.emailTls | SECRETS_EMAIL_TLS | starttls or implicit; plaintext refused | starttls | Plain config |
| secrets.emailUsernameFile | SECRETS_EMAIL_USERNAME_FILE | UTF-8 credential file; <=1 KiB, one optional LF | /run/secrets/secrets/smtp-username | Secret file; shared mounted-value source |
| secrets.emailPasswordFile | SECRETS_EMAIL_PASSWORD_FILE | Mounted UTF-8 password; <=1 KiB, one optional LF | /run/secrets/secrets/smtp-password | Secret file; existing email password reader; raw EMAIL_PASSWORD refused |
| secrets.emailFrom | SECRETS_EMAIL_FROM | Valid sender address | required | Plain config |
| secrets.emailCaFile | SECRETS_EMAIL_CA_FILE | Optional SMTP CA PEM path | unset | Public trust file reference; no TLS private key in app |
| secrets.hookInternalDestinations | SECRETS_HOOK_INTERNAL_DESTINATIONS | allowed only; set together with CIDR and origins | unset/public-only | Plain config; private receivers require the complete set |
| secrets.hookInternalCidr | SECRETS_HOOK_INTERNAL_CIDR | Exact permitted receiver network inside network.servicesCidr; contains all A/AAAA answers | unset | Plain config; operator must bind to actual private services network |
| secrets.hookInternalOrigins | SECRETS_HOOK_INTERNAL_ORIGINS | JSON array of exact HTTPS installed receiver origins; no wildcard/path | unset | Plain config; Secrets includes Logs public origin when private; Logs only its own governance receivers |
| secrets.hookCaFile | SECRETS_HOOK_CA_FILE | Optional PEM trust anchors for hook HTTPS | unset/system trust | Public trust file reference; verifies all hook delivery TLS; no client-key setting |
| secrets.egressDeniedNetworks | SECRETS_EGRESS_DENIED_NETWORKS | JSON array of strict IP/CIDR denials | explicit JSON array required | Plain config; cannot weaken mandatory egress floor |
| secrets.clientAddressHeader | SECRETS_CLIENT_ADDRESS_HEADER | Optional trusted proxy-overwritten client-IP header | unset/peer address | Plain config; never trust caller-controlled forwarding headers |
| fixed | /tmp | Private writable ephemeral mount; root filesystem may be read-only | ephemeral | Only writable filesystem requirement; all durable state is in PostgreSQL |
| fixed | all /run/secrets/secrets mounts | Read-only; never shared with agents or the other service | required | Secret payloads stay out of pod/chart env, values and argv |
| fixed | network peers | Private PostgreSQL; customer AWID/DNS; team aweb HTTPS; SMTP; installed hook receivers | required | No agent access to keys or databases; broker upstream peers are policy-limited |
| secrets.custodyKeyFile | SECRETS_CUSTODY_KEY_FILE | Mounted local custody key; exactly one of this or KMS | /run/secrets/secrets/custody-key | Secret file; local custody selected for bundle, no AWS static credential inputs |
| secrets.kmsKeyId / secrets.kmsRegion | SECRETS_KMS_KEY_ID / SECRETS_KMS_REGION | Optional alternative to custodyKeyFile; AWS workload identity | unset | Plain identifiers; omit custody file when selected; permit KMS endpoint only then |
| secrets.secretRequestKeyFile | SECRETS_SECRET_REQUEST_KEY_FILE | Independent request-sealing key path | /run/secrets/secrets/request-seal-key | Secret file reference |
| secrets.secretParamsKeyFile | SECRETS_SECRET_PARAMS_KEY_FILE | Independent parameter-sealing key path | /run/secrets/secrets/params-seal-key | Secret file reference |
| secrets.responseKeyFile | SECRETS_RESPONSE_KEY_FILE | Independent response-sealing key path | /run/secrets/secrets/response-seal-key | Secret file reference |
| secrets.runnerServiceKeyFile | SECRETS_RUNNER_SERVICE_KEY_FILE | Independent runner-service signing key path | /run/secrets/secrets/runner-service-key | Secret file reference; no runner/supervisor in this image |
| secrets.egressCaFile | SECRETS_EGRESS_CA_FILE | Optional broker upstream trust anchors | unset | Public trust file reference; separate from hook TLS trust |

| File name under `/run/secrets/secrets/` | Owner/mode | Who provisions it |
| --- | --- | --- |
| `database-url` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; whole DSN for dedicated role; never chart values/env/argv |
| `smtp-username` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; credential payload; never chart values/env/argv |
| `smtp-password` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; credential payload; never chart values/env/argv |
| `awid-member-key` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; independent K0 key material (64 lowercase hex), except AWID member key uses aw-compatible PEM; never chart values/env/argv |
| `custody-key` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; independent K0 key material (64 lowercase hex), except AWID member key uses aw-compatible PEM; never chart values/env/argv |
| `request-seal-key` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; independent K0 key material (64 lowercase hex), except AWID member key uses aw-compatible PEM; never chart values/env/argv |
| `params-seal-key` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; independent K0 key material (64 lowercase hex), except AWID member key uses aw-compatible PEM; never chart values/env/argv |
| `response-seal-key` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; independent K0 key material (64 lowercase hex), except AWID member key uses aw-compatible PEM; never chart values/env/argv |
| `runner-service-key` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; independent K0 key material (64 lowercase hex), except AWID member key uses aw-compatible PEM; never chart values/env/argv |
| `manifest-request-key` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; independent K0 key material (64 lowercase hex), except AWID member key uses aw-compatible PEM; never chart values/env/argv |
| `hook-event` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; credential payload; never chart values/env/argv |
| `hook-delivery` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; credential payload; never chart values/env/argv |
| `grant-read` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; credential payload; never chart values/env/argv |
| `hook-resolve` | `10001:10001` mode `0400`, or `0:10001` mode `0440`; read-only | Operator/approved provisioner; credential payload; never chart values/env/argv |
| `awid-member-certificate` | Same service-only owner/read permissions | Customer team authority; JSON certificate matching `awid-member-key`; ordinary service member, no controller key |
| `hook-ca.pem`, `smtp-ca.pem`, `broker-ca.pem` | Read-only public trust files, `0444` permitted | Operator trust authority; public certificates only, serving/private TLS keys stay with proxy/Ingress |

| Key | Platform | Why no shared form |
| --- | --- | --- |
| `secrets.kubernetes.fsGroup` (fixed `10001`) | Kubernetes | Secret projections are root-owned; `0440` plus service-only group makes files readable to UID10001 without agent access |
| `secrets.kubernetes.resources`, `secrets.kubernetes.imagePullSecrets`, `secrets.kubernetes.networkPolicy` | Kubernetes | Cluster resource/registry credentials and peer selectors are Kubernetes objects; no service credential values |
| `secrets.compose.bindSources`, `secrets.compose.pidsLimit` | Compose | Host paths and process limits are host-runtime details; secret-source ownership/mode must be set on host |
