# Lab3: exact-source service installation and health; STOP before owner-dependent use

Target: **server175356165, Ubuntu 24.04, linux/amd64, 8 GB**. Hestia is the administrator; oatsagent has neither general sudo nor Docker-group authority. This replaces fh1/polaris and its relay. Root sends this to Secrets; Secrets sends ONE technical handoff through aweb to Hestia. Servers tracks, without forwarding.

The ready portion is the reviewed Secrets/Logs source-build, private configuration and health sequence below. The protected runner archive is independently ACKed for build/staging, not installation. Do not install its sudo rule or attempt registration/use from this handoff.

## 1. Pin source and preserve the running cohort

Build only **dfa093a396409e4132cf96127a3c30a48e71f7f8**, tree **dafd78d3d05aeb66f21df47ed8ba35598bd5cdd5**. Label the receipt **source-candidate: reviewed, ungated, unmerged**. The immutable origin ref is `refs/heads/coordinator/train-secrets-34b`. Its eleven reviewed heads are c77c5145c, 8e7ca8565, 6c21e3b00, 046ef7238, cfeee4df6, 6bfb5f47b, 07d42c81c, 3654e9eb1, 10262dc1e, 7a9a1be7e and f080f7573. The full lane-train gate and landing after finals remain pending. Reassess any future source delta; do not substitute another train tip.

The existing registry `https://awid.byotlab.oatshq.com`, coordination `https://aweb.byotlab.oatshq.com` and namespace `oatspec.io` stay on **e3a1d9f76**. Do not install server rc2 from PyPI or upgrade either running service. A newer AWID library in a container is not a registry upgrade.

Use a fresh operator-owned checkout, separate from the running cohort's checkout. The path below is an operator-selected source directory, not an identity home:

```bash
# Run in the administrator's shell on the named Lab3 host.
set -euo pipefail
[ "$(uname -m)" = x86_64 ]
lab3_source=/absolute/operator-owned/lab3-source
# This must be a NEW directory. Do not reset an existing checkout.
git clone --no-checkout https://github.com/awebai/aweb.git "$lab3_source"
git -C "$lab3_source" fetch origin refs/heads/coordinator/train-secrets-34b
git -C "$lab3_source" checkout --detach dfa093a396409e4132cf96127a3c30a48e71f7f8
[ "$(git -C "$lab3_source" rev-parse HEAD)" = dfa093a396409e4132cf96127a3c30a48e71f7f8 ]
[ "$(git -C "$lab3_source" rev-parse HEAD^{tree})" = dafd78d3d05aeb66f21df47ed8ba35598bd5cdd5 ]
[ -z "$(git -C "$lab3_source" status --porcelain)" ]
```

Secrets and Logs are each version0.1.0, with co-located **awid-service0.5.36 and aweb-naapp0.5.1 from that exact source tree**, Python3.12.16 in the measured images. Dockerfiles copy those path sources and sync their committed locks with `--frozen --no-dev`. They do not resolve server rc2 from PyPI. The selected team-auth, signed team-server discovery and app-grant client files are byte-identical between e3a1d9f76 and dfa; e3 exposes their certificate/team-server, `/v1/apps/self/grant` and signed hook-resolution routes. This supports those wire paths; it is not proof of the missing owner workflow or of this installation's team-read authority. Stage5 below must refuse on any actual registry/authority mismatch.

## 2. Build and record the actual installed image identities

Use the existing Docker daemon as the administrator. Do not add oatsagent to Docker or change AppArmor/user namespaces. If Docker or the separate operator-owned PostgreSQL databases/roles are unavailable, STOP and return that prerequisite. Before starting, the operator records the independent PostgreSQL endpoint and confirms that both containers can reach it from the default Docker bridge. A Compose-only hostname is unsuitable without its network. This handoff does not create databases/roles in, or change, the e3 cohort's PostgreSQL server; if no independent reachable endpoint exists, STOP.

```bash
for service in secrets logs; do
  git -C "$lab3_source" archive dfa093a396409e4132cf96127a3c30a48e71f7f8 |
    sudo docker build --platform linux/amd64 \
      --build-arg SOURCE_COMMIT=dfa093a396409e4132cf96127a3c30a48e71f7f8 \
      -f "naapp/$service/Dockerfile" -t "lab3-$service:dfa093a39-amd64" -
  sudo docker image inspect "lab3-$service:dfa093a39-amd64" \
    --format '{{.Id}} {{.Os}}/{{.Architecture}} {{.Size}} {{index .Config.Labels "org.opencontainers.image.revision"}}'
done
```

Require linux/amd64 and the exact revision. Record the target's image IDs before starting; tags alone are insufficient. Root's measured local image IDs are:

- Secrets `sha256:afc69a0a579694a9f71423733127bf793d2cbacf1eba8f0d8e09540e3be90497`.
- Logs `sha256:20db99a034d2389334db723dcbb17db7868b2ade0af98feb4f32e1c6c5ec685a`.

These are local image IDs, not published registry digests. A target rebuild records its actual IDs; byte-identical rebuilds are not assumed. Both root-built amd64 images imported their co-located dependencies and started through the existing packaged probes, with real PG/registry/DNS, mismatch/revocation/cache-outage refusals and cleanup PASS. Execution was emulated on an ARM64 Docker host. Generated component authority is not Lab3 admission, owner designation, SMTP, delivery or reader evidence.

## 3. Private operator inputs: names and paths only

Prepare `/etc/aweb-lab3/secrets.env` and `/etc/aweb-lab3/logs.env` as0600 files and separate key directories `/etc/aweb-lab3/secrets-keys` and `/etc/aweb-lab3/logs-keys`, readable by service UID10001 and inaccessible to oatsagent. Mount each at `/run/keys` in its own container, read-only. Every configured `*_EMAIL_PASSWORD_FILE` and `*_EMAIL_CA_FILE` must also be beneath `/run/keys`, the only file mount. Generate independent keys using the recipe's K0 format; no value belongs in a command argument, mail, image or evidence. Do not source these files as shell programs or print their contents.

Use the exact candidate's reviewed `naapp/secrets/deploy/README.md` and `naapp/logs/deploy/README.md` for formats. Required mappings:

- Both prefixes: `*_DATABASE_URL`, `*_DB_SCHEMA`, `*_APP_ID`, `*_PUBLIC_ORIGIN`, `*_CONSOLE_ORIGIN`, `*_AWID_REGISTRY_URL`, `*_APP_KEY_FILES`, `*_EMAIL_SMTP_HOST`, `*_EMAIL_SMTP_PORT`, `*_EMAIL_TLS`, `*_EMAIL_USERNAME`, `*_EMAIL_PASSWORD_FILE`, `*_EMAIL_FROM`; optional `*_EMAIL_CA_FILE`. App IDs are stable customer IDs, not the reserved hosted Logs identity. Actual service origins/DNS/TLS and private DSNs must be supplied by the operator; do not invent a live mapping.
- Secrets local custody for this smoke: `SECRETS_CUSTODY_KEY_FILE=/run/keys/custody`; leave KMS selection unset. Also `SECRETS_SECRET_REQUEST_KEY_FILE`, `SECRETS_SECRET_PARAMS_KEY_FILE`, `SECRETS_RESPONSE_KEY_FILE`, `SECRETS_RUNNER_SERVICE_KEY_FILE`, `SECRETS_MANIFEST_REQUEST_KEY_FILE`, each naming an independent file beneath `/run/keys`.
- Secrets app-key kids: `secrets.hook-event-1`, `secrets.hook-delivery-1`, `secrets:grant-read-1`, `secrets:hook-resolve-1`. Logs kids: `logs-chain`, `logs-resolve`, `logs-grants`, `logs-governance`; each maps to its own mounted file.
- `SECRETS_AWID_REGISTRY_URL` and `LOGS_AWID_REGISTRY_URL` select the supplied customer registry. Verify the actual `_awid.oatspec.io` selection and signed team-server publication; do not rewrite them. For a private installation team, establish the supported team-read authority before continuing. Optional `*_AWID_SERVICE_TOKEN` is an existing input, not evidence that a token exists or is accepted; never copy one from another service.
- `*_EGRESS_DENIED_NETWORKS` retains the mandatory floor. Internal hooks require all three `*_HOOK_INTERNAL_DESTINATIONS=allowed`, `*_HOOK_INTERNAL_CIDR`, `*_HOOK_INTERNAL_ORIGINS`, with every origin resolving within that exact permitted network. Optional `*_HOOK_CA_FILE` adds trust to all hook deliveries. Do not copy the broker's internal/CA selection. Public-only/system-trust defaults remain available. Hosted HO5 restrictions are separate and are not lifted.

No actual Lab3 private settings, service-origin mapping, SMTP receipt or installation-team authorization has been supplied to root. Missing inputs STOP the corresponding stage; readiness does not create them.

## 4. Start the two reviewed roots, preserving Host and TLS

Before changing any shared TLS proxy, record its config path, a private backup path and the pre-change hash. Validate the new config with that installed proxy's native validator before reload; missing backup/validation is a STOP before editing. Preserve all existing e3 routes. Configure the proxy for the four actual origins, preserving Host: Secrets listener8770 and Logs listener8765. Logs' console must meet its own-host rule. Do not run a second process for its second origin. Keep the new app databases/keys isolated from the running registry/coordination cohort. Record `getent passwd 10001` and `id -u oatsagent` before starting: STOP if UID10001 belongs to an interactive/non-service host account or oatsagent. The later runner UID must differ from10001 as well. An existing UID10001 account is acceptable only as a dedicated non-login service account.

```bash
# STOP if either exact name already exists; inspect rather than deleting it.
sudo docker run --detach --name lab3-logs \
  --label aweb.lab3.source=dfa093a396409e4132cf96127a3c30a48e71f7f8 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --env-file /etc/aweb-lab3/logs.env \
  --mount type=bind,src=/etc/aweb-lab3/logs-keys,dst=/run/keys,readonly \
  --publish 127.0.0.1:8765:8765 lab3-logs:dfa093a39-amd64
sudo docker run --detach --name lab3-secrets \
  --label aweb.lab3.source=dfa093a396409e4132cf96127a3c30a48e71f7f8 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --env-file /etc/aweb-lab3/secrets.env \
  --mount type=bind,src=/etc/aweb-lab3/secrets-keys,dst=/run/keys,readonly \
  --publish 127.0.0.1:8770:8770 lab3-secrets:dfa093a39-amd64
```

These are the reviewed deploy recipes with Lab3 names. No runner or sudoers policy is installed by these images. Do not override the image's GIT_SHA.

## 5. Readiness, refusal and footprint before any effect

Record source/tree, actual image IDs, image UID10001, package versions and public app IDs/builds. With verified TLS, use this exact origin matrix:

| Origin | Required health/build acceptance |
| --- | --- |
| Secrets API | `/live`200; `/health`200 with database/outbox/selected-provider checks true; `/ready`200; `labels.custody_mode=local_key_file`; `build.git_sha` equals dfa |
| Secrets console | The same three health routes, checks, custody label and build assertion as the Secrets API |
| Logs public/API | `/live`200; `/health`200 with database/outbox checks true; `/ready`200; `build.git_sha` equals dfa |
| Logs console | No health/build routes are mounted here. Check TLS/Host routing separately using its reader routes; an unauthenticated `GET /v1/events` must return `401 console_session_required`; a `404` is a routing failure, not a pass. This does not create a reader or qualify the reader journey. |

`/health`200 alone is insufficient. Do not require Logs-console health or add new product routes to satisfy this procedure. Use only a configured CA, never a TLS bypass.

Check the actual served manifests and registry/DNS/team-server mapping against the public operator receipts. Refuse a mismatched registry and an unauthorized member request before any upstream effect. The component mismatch/outage tests already passed; live Lab3 checks still require its real certificate, team visibility and read authority. A missing team/credential or unknown result is not a pass. Record the fixed refusal/status and owner; do not print bodies, keys or raw logs.

Measure native target availability with `free -b`, `df -B1 /` and the Docker root directory. Sample `sudo docker stats --no-stream lab3-secrets lab3-logs` during startup/smoke, including required PG/OATS/authority processes and free headroom. Root's final Docker-reported image sizes were659468826 and540877286 bytes; the runner payload is214314207 bytes plus its archive. These are disk quantities. Logs' earlier ARM64 lab peak was150MiB including its probe, not an amd64 stack RAM bound. Eight GB allocated does not establish available memory or retained-data capacity. No Oracle is included; data growth and sustained-load capacity remain unmeasured.

**Any failed prerequisite STOPs the run.** Send sanitized stage/status/refusal plus exact source/artifact IDs to its existing owner through Secrets. Do not upgrade the e3 cohort, seed authority, relax permissions or redispatch an unknown effect to hide the failure.

## 6. Explicit STOP: owner bootstrap, registration and the one fixed TLS operation

At dfa, the supported H/N first-owner journey is not composed. Confirmed by app owner4d19b670. Blocking chain: **shared acwd.4.2 factory -> console acwd.4.4 / app acwd.4.5 -> shared acgh.16.41 -> app acgh.16.43**. The legacy owner-act endpoint and a production fixture's controller-signed body are not a verified operator bootstrap. Do not substitute SQL, fixture signing or a fake approval.

Human-only when that chain is reviewed and composed: owner signing/designation, passkey enrolment and distinct fresh APPROVE, synthetic secret value entry, and entry of the one-use owner-issued runner code. The existing runner README supports a dedicated-user hidden terminal prompt; the protected N4 aw display is not yet shipped. Codes/links/assertions never go through mail, argv, logs or evidence. Operator-installed code/account/sudo policy is a separate reviewed step, not a human-signing substitute.

The next and only workload remains the reviewed fixed TLS CLI: one approved run authenticates to the synthetic `/basic/echo`; one unapproved/unauthorized use refuses before credential release/target authentication; correlate actual request/job/dispatch IDs through the production outbox, Logs ingest, persisted event and signed receipt. Neither a direct CLI child nor enqueue alone qualifies this. No billable token or Oracle expansion.

Root has staged the Linux runner at source dfa, with four review inputs committed at **60f428ebd36ce74dd3e9acf5d73b1c8bdb60cf94**, path `naapp/secrets/deploy/artifacts/linux-amd64-dfa093a39/`. Ordinary ACK ba0ce689; Athena ACK0e9ff0cb cover BUILD/STAGE ONLY. Archive SHA256 **bb4d2b384d3f0096ee96daa0fa94f5c2c376bc8dea6deac4ca25a6077fc8ea0a**; manifest **2c5ef2b1dd7742bc57730b9cf94d67e3cdf6fd93e8d0d358f606378c260481b7**. The interpreter pin is bb4d05c1f88e8568985e8704afe1822e82700a54bad9317c05c8eb96d3186701; CLI pin e4bceeb2094a7fef3b81375071d6dd65f2f1642c2114f3327437b6740a8242e8. Exact archive bytes are retained in root's `artifacts/lab3-dfa/runner-linux-amd64-dfa093a39.tar.gz` for the existing authenticated handoff route, not a new download service.

Next root deliverable before runner installation: the reviewed operator script that verifies archive+every file/mode, enforces root ownership/parents, records native imports/ldd/help and actual oatsagent/aweb-runner UIDs/sudo denials, then fits the actual receiver origin/public username/CA and real runner ID with the runner owner. No native install/UID/sudo/lifecycle or final job pin is claimed yet. The first-owner STOP above remains even if this artifact passes.

## 7. Rollback and assurance limit

This is a fresh lab install, not a migration of the existing e3 services. If prerequisites fail, stop only the exact recorded new containers `lab3-secrets` and `lab3-logs`; remove those containers only after verifying their recorded IDs/labels. Retain app databases, keys and evidence for operator disposition; do not attempt schema downgrades, delete state or prune Docker. If this phase changed the shared TLS proxy, restore its recorded configuration/backup and validate before reload, preserving the e3 routes; the rollback record includes the restored hash. No runner sudo rule is enabled in this phase. Do not touch the existing registry, coordination, agents or their identity homes.

Hestia administers this shared-controller lab. It cannot prove protection FROM Hestia, per-agent identity containment within a shared UID, or independent audit governance/witness custody. Native lab success is not publication, the full release gate, or a passed reader journey.
