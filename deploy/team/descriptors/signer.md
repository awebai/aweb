# Signer: protected human approval

The existing independent protected host, built from `server/Dockerfile` with `AWEB_EXTRA=protected`. It uses the shared signer, B2/B3, ConsoleSessions and handoff page. Source basis: `server/src/aweb/protected_signing/{host,profile,custody}.py` at `14b2b0477821c975680f1889a0b12c77be9ce482` and `HOST.md` at `dc16013cc`. The whole-DSN file input and dedicated readiness route are pending with the embedding owner; their absence must not be replaced by credential values in the rendered environment.

## Inputs

| Key | Becomes | Constraint | Default | Purpose |
| --- | --- | --- | --- | --- |
| `signer.image` | service image | `repository@sha256:<64 lowercase hex>`; contains the protected extra | none | Same protected-host image in Compose and Helm. |
| `signer.profileFile` | configuration mount; `AWEB_PROTECTED_PROFILE_FILE` | existing `ProtectedServiceProfile` JSON; readable configuration file | none | The single service/registry/namespace/authority/policy binding profile. Preserve it as one file, not flattened fields. |
| `signer.scopeFile` | configuration mount; `AWEB_PROTECTED_SCOPE_FILE` | JSON exactly matching one complete `bindings[].scope` in that profile | none | Select the existing authority/human binding; not a new grant. |
| `signer.requestOrigin` | proxy/Ingress route; compared to profile `request_origin` | HTTPS origin, exactly equal to profile | none | aw prepare and authenticated receipt surface. No second host environment override. |
| `signer.humanOrigin` | proxy/Ingress route; compared to profile `human_origin` | HTTPS origin; hostname equals profile `rp_id`; preserve existing origin-separation validation | none | Browser LOGIN and exact-act passkey approval surface. |
| `team.registryUrl` | compared to profile `registry_origin` | exact equality; use the existing profile registry client | `https://api.awid.ai` | Prevent the bundle and signer from selecting different registries. No `AWID_SERVICE_TOKEN`. |
| `team.id` | compared to selected scope/team authority and member manifest | canonical team id; exact configured team match | none | Keep authority, custody and private-team membership aligned. |
| `signer.secrets` | mount at `/run/secrets/signer` | existing Secret name in Kubernetes; directory reference under `compose.secretsDir` in Compose | `signer` | File sources below; never secret values in YAML/env/argv. |
| `signer.workerUids` | `AWEB_PROTECTED_WORKER_UIDS` | nonempty JSON array of positive integers; must include actual agent/worker UIDs and exclude signer uid 1001 | none | Existing custody refusal check; wrapper validates against agents' configured UID. |
| `signer.databaseSchema` | `AWEB_PROTECTED_DATABASE_SCHEMA` | `^[a-z][a-z0-9_]{0,62}$` | `protected_signer` | Schema in the signer's own database and role. |
| `signer.databaseUsesTransactionPooler` | `AWEB_PROTECTED_DATABASE_USES_TRANSACTION_POOLER` | boolean, rendered in service-supported form | `false` | Match the selected database connection mode. |
| `signer.humanCsrfKey` | `AWEB_PROTECTED_HUMAN_CSRF_KEY` | `^[A-Za-z0-9._-]{1,128}$`; public storage-key name, not a credential | `aweb.protected.console.csrf` | Existing page/session CSRF storage binding. |
| `signer.trustedClientHeader` | `AWEB_PROTECTED_TRUSTED_CLIENT_HEADER` | optional HTTP header name; only when the trusted proxy strips caller values, sets its own and excludes direct untrusted access | unset | Rate-limit client identification only; never authority or origin selection. |
| `signer.emailSmtpHost` | `AWEB_PROTECTED_EMAIL_SMTP_HOST` | hostname reachable by the signer | none | Existing TLS notification mailer. |
| `signer.emailSmtpPort` | `AWEB_PROTECTED_EMAIL_SMTP_PORT` | integer 1..65535 | none | SMTP listener. |
| `signer.emailUsername` | `AWEB_PROTECTED_EMAIL_USERNAME` | SMTP account identifier, not password | none | Existing mailer authentication. |
| `signer.emailFrom` | `AWEB_PROTECTED_EMAIL_FROM` | valid sender accepted by the existing mailer | none | Enrollment/contact notification sender. |
| `signer.emailTls` | `AWEB_PROTECTED_EMAIL_TLS` | `starttls` or `implicit` | `starttls` | TLS mode; no plaintext notification profile. |
| `signer.emailCaFile` | configuration mount; `AWEB_PROTECTED_EMAIL_CA_FILE` | optional readable CA certificate file | system trust | Operator/private-CA SMTP trust. |

Fixed: uid `1001`; command `uvicorn aweb.protected_signing.host:create_app --factory --host 0.0.0.0 --port 8080 --no-proxy-headers`; `AWEB_PROTECTED_CONTROLLER_KEY_FILE=/run/secrets/signer/controller.key`; `AWEB_PROTECTED_MEMBER_KEYS_FILE=/run/secrets/signer/member-keys.json`; `AWEB_PROTECTED_EMAIL_PASSWORD_FILE=/run/secrets/signer/smtp-password`. Target file setting `AWEB_PROTECTED_DATABASE_URL_FILE=/run/secrets/signer/database-url` is pending the embedding change; current source requires `AWEB_PROTECTED_DATABASE_URL`, which must not be emitted with a credential to work around that gap. Profile, scope and optional CA mount outside `/run/secrets`. JSON collections stay JSON; the wrapper must not lose their types while rendering.

## Secret files

| Name | Owner and mode | Provisioned by |
| --- | --- | --- |
| `controller.key` | signer uid 1001; regular non-symlink file `0400` or `0600`; containing directory owned by uid 1001 with mode `0700` | Authorized operator provisioning: 32-byte Ed25519 seed encoded as 64 hex characters, optional newline; must match current registry controller and selected public profile. Startup never creates a replacement. |
| `member-keys.json` | uid 1001, `0400` | Operator: existing canonical-team-to-relative-PEM-path mapping. Contains paths, not key material. |
| `<name>.key` | uid 1001, `0400` | Operator after ordinary service-member admission; existing aw Ed25519 seed PEM format and current certificate. Controller-as-member refuses. |
| `database-url` | uid 1001, `0400` | Operator/PostgreSQL provisioning: whole DSN for database `signer`, role `signer`; not a shared aweb/Secrets/Logs role. File-reader implementation pending. |
| `smtp-password` | uid 1001, `0400` | Operator: password for the configured notification account; existing file reader. |

All files and the containing custody volume are excluded from agent mounts, privileges and runtime access. The host retains approvals, passkeys, sessions, authority, signatures/receipts and local audit in PostgreSQL. Existing authorized provisioning must initialize its declared authority and B3 enrollment; absent provisioning refuses startup.

## Platform-only inputs

| Key | Platform | Why |
| --- | --- | --- |
| `signer.compose.bindAddress`, `signer.compose.port` | Compose | Default `127.0.0.1:8080` for the operator proxy; Kubernetes routes both external hosts to Service `signer:8080`. |
| `signer.kubernetes.configMap` | Kubernetes | Existing ConfigMap supplying profile, scope and optional CA configuration files; Compose uses operator file mounts named above. Map the same file contents, without a second profile format. |
| `signer.kubernetes` private-volume materialization (fixed chart behavior, not a disable switch) | Kubernetes | Projected Secret files can be symlinks/root-owned. Copy the provisioned signer secrets into a signer-private volume with the ownership/modes above before starting; mount read-only in the signer and never in agents. Preserve the existing custody verifier rather than weakening it. No separate custody implementation. |

Image: pinned aweb server image built with the protected extra.
Port: `8080`, Service/DNS `signer`, request and human hosts both routed with original Host.
Health: no dedicated `/ready` or `/health` endpoint in the source above; embedding owns the minimal readiness addition, so do not configure an invented HTTP probe.
Depends on: its PostgreSQL database/role, the configured registry, provisioned controller/member/profile/scope/authority/B3 enrollment, and TLS/auth SMTP configuration. No Redis dependency.
