# Ordered BYOT source-candidate rehearsal and preflight: rows 3–6

Status: revision 2, preparation for review, 2026-11-09. This is one ordered run, using the
existing S19/acwd.5 profile and acwd.7 operations matrix. It adds no harness.
An operator stops at a missing prerequisite and records that row as blocked;
a later independent check may proceed only if it does not manufacture the
missing authority. No complete fresh-host run is recorded here yet.

## 1. Freeze the venue, source and receipt

Use a disposable, synthetic BYOT installation. No customer data or production
access is authorized. Label this receipt **source-candidate**. A later receipt
labelled **published-artifact** must install the released images/distributions
and verify their recorded digests/checksums; a source build cannot satisfy it.
Neither receipt replaces the full Secrets/M9 gate.

| Input | Current exact source or handoff | Limit |
| --- | --- | --- |
| OATS host target | Ubuntu 24.04 LTS noble server cloud image amd64 (Canonical noble-server-cloudimg-amd64.img), QEMU/KVM on polaris; OATS/VM owners, receipt7b3d32b9 via secrets a5036c6d | Fresh base per run; 4vCPU/4GiB RAM/30GiB thin overlay; tester account, forwarded SSH port. Checksum verification dated2026-11-03 is owner-reported; retain actual image checksum/kernel/disk/RAM observations at execution. BYOT fresh-run remains unqualified. |
| Host tooling | Published OATS CLI/Desktop 0.69.12, oats.aweb v1.38.0; Node 22+, git, tmux; record installed harness versions | OATS does not pin harness versions. Human logins are separate steps. Windows and resident/global custody are outside this baseline. |
| OATS-managed agent CLI | Published aw 1.36.56, the OATS owner's baseline | Confirm the selected Desktop accepts this exact CLI before installation; keep its runtime selection separate from the integrated candidate below. |
| Integrated human/Secrets candidate client and coordination server | aw 1.36.57-rc.1 / server 1.27.49rc1 (RC); aweb main9a54c7392429bd98bc6be58b991458d9da921e9c is the pinned main-only alternative | Human-kind row2 artifact89bf111d splits released subsetA from RC/main subsetB; real authority inputs are still unsupplied. Confirm Desktop/CLI compatibility and explicit binary selection with the OATS owner; do not replace the managed CLI globally. This is source-candidate, never final-release qualification. |
| Service/runtime source | aweb main 9a54c7392429bd98bc6be58b991458d9da921e9c; Secrets/Logs 0.1.0, naapp 0.5.1, awid-service 0.5.36 in manifests | Use the checkout's frozen locks. The Secrets Dockerfile pins Python 3.12 and uv 0.11.21 by OCI index digest. Record actual image Python version, platform and image ID; the minor-version tag alone is not an execution inventory. |
| Lab input/publication source | acwd.5 head 2b7827ab9373c18f01deb725c24444c59a407cbb, landed in main | This landed profile is KMS-only: byot-native-kms-lab/1. Key-file selection is reviewed c47773b8feb9d49c7d3f5bc518f946c629eabf31 under acgh.44.1, queued, not landed at this baseline. |
| Assurance wording candidate | 533cdbd8ca148d9c284a403372f3e80695971564, four docs-only commits over main9a54 | R53669c8f, Athena c50d55cb, Logs-row bcf339d0. Freshness/CHECKS still queued. Product/lock source is unchanged from main9a54. |
| Source image platforms | Secrets component build: linux/arm64 from product source9a54; Secrets and Logs fresh-host images: linux/amd64, not yet built | Record each image ID/digest and full source SHA when built. The ARM64 component probe is not an x64 source-candidate image or a fresh-host receipt. The x64 host builds its own. |
| Runner/job | Supervisor5c91e730b; Oracle source3718174d2, manifest sha256:fa2782091c925e235e8f9bc868fd0b0c7eb01af523f0af11e8aab9eb99520ecd, linux/arm64 | This retained archive does not qualify Linux x64. Oracle is optional for initial host/service smoke checks. Not on the first run critical path: first workload is the existing fixed TLS CLI, per secrets d1c1a66c. Oracle amd64 qualification is separate and retains this ARM64 archive. Never silently repin. |

The matrix above is labelled source-candidate and keeps the OATS host/agent
baseline separate from the integrated human/Secrets candidate. Add the first
TLS job's computed job/1 digest and exact target Python/CA pins before runner use;
those are not available from a macOS build.

On the fresh host, retain `cat /etc/os-release`, `uname -srm`, `getconf
GNU_LIBC_VERSION`, `node --version`, `tmux -V`, `git --version`, `uv --version`,
`docker version`, selected `aw version`, OATS version and harness versions.
Record source SHA, lock identities and generated image IDs without environment
contents, keys, login links or raw I/O. The exact fresh-host receipt remains
unfilled until execution on the allocated VM; the shared development host is
not that venue. The 17:45Z VM-host observation (16CPU/31GiB,11GiB free) is dated,
not a capacity guarantee. Pre-supplied VM-test Claude/GitHub logins exclude the
real login ceremony from coverage; no credentials enter evidence. OATS owner and VM campaign owner must confirm capacity
and VM-host load before starting. Do not acquire a paid host or mutate a shared
host as an implicit fallback.

## 2. Complete host and identity prerequisites first

Before installing either CLI, the OATS owner must confirm that Desktop0.69.12's
accepted CLI version range includes the selected aw version. If it does not,
the owner supplies a compatible Desktop/CLI pair. Never upgrade the CLI alone.
Keep the published OATS agent baseline and integrated candidate explicitly
separate. A side-by-side candidate is usable only with an owner-confirmed
selection that does not change the Desktop-managed runtime. Record exact
binary/version choices in the source-candidate matrix above.

Consume the existing OATS `skills/oats-getting-started/SKILL.md` and, for a
headless host, `docs/servers.md` at the selected OATS version. The row-1 owner
supplies their exact source pin. OATS' supported remote route is
`oats server connect <id> --ssh <alias> --dir <absolute-directory> --install-oats`,
then `oats server check`. Do not treat that currently unqualified fresh-install
route as having passed. Run `oats doctor`, `oats readiness --home <home> --json`
and `oats aweb setup --check-only --json` from the intended instance/deployment.

Human-only, flagged before setup when not pre-supplied by the VM owner: GitHub device login; each harness' private
provider login; namespace-owner acts; entering invite tokens through stdin;
and approval of the setup agent's change list. Never automate or retain those
inputs. BYOT OATS setup uses its existing namespace creation or invite-stdin
join route. Run it only with row-2's selected namespace/registry/coordination
inputs and command/version artifact. Do not create another team or identity
as a substitute for a failed prerequisite. Human-kind89bf111d supplies the
source-qualified row2 sequence: released aw1.36.56/server1.27.48 at
e3a1d9f76cb4f08913603accd48ba04120f3df82 for controller-issued local invitations;
separate human participation uses RCcfdc06255e2ad00e63640255f4f6d4b294d30f4f.
Actual namespace/TXT, controller public DID and custody boundary, registry
origin/cohort, coordination origin/TLS and resource-use authorization must
still be supplied. Server/Python v3 support exists in the RC, but main9a54's Go
reader accepts v1/v2 only: complete v3 CLI/owner designation is missing. Do not
merge the released local-agent receipt and later RC/main extension into one
baseline or treat ordinary install-admin authority as human designation.

Use real human/agent membership, canonical team IDs, current certificates and
namespace `_awid` DNS. The selected customer registry and signed coordination
publication must agree. Local directories do not certify authority. The
existing packaging probe's external AWID fixture SQL is component setup, not
this identity/admission journey; never copy it into fresh-host provisioning.

## 3. Enumerate private references and the actual trust boundary

Before starting either service, the operator creates private, non-repository
configuration and generated lab key files. Values stay in private memory/files,
not shell arguments, mail, fixtures or evidence. Inventory selector names and
readiness only. Do not source runtime.json or a file containing arbitrary shell.

The landed lab loader selects exactly these `AWEB_SECRETS_E2E_` suffixes:

| Group | Selected names |
| --- | --- |
| Authority and services | TEAM_ID, API_ORIGIN, CONSOLE_ORIGIN, LOGS_ORIGIN, LOGS_CONSOLE_ORIGIN, AWID_REGISTRY_URL, COORDINATION_ORIGIN |
| Custody | KMS_KEY_ARN, AWS_REGION, KMS_CREDENTIALS_FILE |
| Runner | RUNNER_BINARY, RUNNER_CONFIG_FILE, RUNNER_USER, RUNNER_STATE_DIR |
| CLI and actors | AW_BINARY, HUMAN_IDENTITY_HOME, AGENT_A_IDENTITY_HOME, AGENT_B_IDENTITY_HOME |

Choose private DNS coverage explicitly; `included` additionally requires
PRIVATE_DNS_NAME and its real refusal scenario. `excluded` means outside
coverage, not passed. Registry/namespace DNS is still required. From
`naapp/secrets`, first `uv sync --frozen` installs the selected checkout dependencies;
then `uv run --frozen --no-sync python e2e/lab_environment.py --private-dns excluded` checks references and exits2 on missing/invalid inputs.
It does not open credentials, start services or prove KMS or human signing.

Choose one custody mode per run. KMS is recommended, not mandatory for the
Secrets service: configure SECRETS_KMS_KEY_ID/SECRETS_KMS_REGION with the
operator-authorized AWS runtime role; provider login/permissions are human-only
where the provider requires them. The driver's KMS_CREDENTIALS_FILE must identify
a lab-only principal scoped to the one lab key. Record exactly which OS users,
groups, agents and privileged interfaces can read that file or exercise its
AWS authority. The OATS driver UID is shared by its agents, so driver-readable
KMS credentials place their decrypt authority inside that shared boundary;
a KMS-mode pass does not establish service-only decrypt authority. Local mode uses SECRETS_CUSTODY_KEY_FILE and
omits KMS. The current lab profile cannot publish a local-key run until
acgh.44.1 lands; record that mode as blocked instead of putting a local key
behind a KMS label. A selected-mode canary failure is failure evidence, not
successful backend use. Never count local-key execution as KMS qualification.
The native lab does not require 1Password; full release acceptance still does.

OATS agents share their deployment OS user and reachable keys: one trust
boundary. Per-principal permissions attribute and prevent mistakes but do not
isolate a compromised agent. Secrets' image UID10001 and read-only key mount
require actual host isolation; an agent with Docker/host administration can
cross that boundary. Keep Secrets, driver and runner execution distinct where
claimed. Record actual UIDs, readable credentials/signing interfaces and allowed
privileged invocations. A runner under a second process with the same UID is
not a separate-user proof. Follow OPERATIONS.md's assurance matrix, including
cross-principal attempts and output restrictions; do not infer isolation from
identity-home variables or normal API refusal.

## 4. Install and start the two service roots (acceptance row3)

1. Freeze each stable app ID and four HTTPS origins before installation:
   Secrets API and console; Logs API and console. Keep console hosts distinct
   from their API hosts; Logs' console cannot be a parent of its API hostname.
   S19's agreed loopback listeners are Secrets API/console as configured, Logs
   ingest18403 and console18404. Host routing must match the actual origins and
   preserve TLS verification. A fresh host needs its own explicit DNS/TLS and
   externally reachable route if a remote browser is used; no TLS bypass.
2. Provision app-owned PostgreSQL roles/databases using the existing operator
   route; migrations run in each root's lifespan. Do not create Secrets or Logs
   domain authority rows directly. Keep dependency services alive until drains
   and app lifespans finish.
3. Populate Secrets' environment-only recipe in `naapp/secrets/deploy/README.md`:
   DATABASE_URL, DB_SCHEMA, APP_ID, PUBLIC_ORIGIN, CONSOLE_ORIGIN,
   AWID_REGISTRY_URL, the chosen custody inputs, SECRET_REQUEST_KEY_FILE,
   SECRET_PARAMS_KEY_FILE, RESPONSE_KEY_FILE, RUNNER_SERVICE_KEY_FILE,
   MANIFEST_REQUEST_KEY_FILE, APP_KEY_FILES and EMAIL_* under SECRETS_. SMTP
   needs host/port/TLS, username, private password-file, sender and optional CA.
   Use independent key material with the recipe's private ownership/mounts.
   APP_KEY_FILES maps the manifest's event, delivery, grant-read and resolve kids.
4. Populate Logs' current LOGS_DATABASE_URL, DB_SCHEMA, APP_ID, PUBLIC_ORIGIN,
   CONSOLE_ORIGIN, AWID_REGISTRY_URL, APP_KEY_FILES and EMAIL_* inputs.
   Four app keys: logs-chain (receipt/checkpoint), logs-governance (hook-event),
   logs-resolve and logs-grants. Logs has no Secrets custody backend. A database
   reader can read retained content across teams. Chain signing plus database
   write can rewrite/re-sign history; detection requires external witnesses
   covering affected positions. A preceding witness does not cover a lost tail.
5. Configure Secrets broker/hook egress separately. SECRETS_EGRESS_DENIED_NETWORKS
   reaches both guards. Public/system trust is default. Internal hook delivery
   requires all of SECRETS_HOOK_INTERNAL_DESTINATIONS=allowed,
   SECRETS_HOOK_INTERNAL_CIDR and SECRETS_HOOK_INTERNAL_ORIGINS; use only the
   exact installed Logs origin and actual listener network. Every DNS answer
   must be inside the CIDR and outside immutable/deployment denials. Optional
   SECRETS_HOOK_CA_FILE trusts all hook deliveries, not just that origin. No
   implicit broker CA/switch reuse. Hosted HO5's separate hold is unaffected.
   Equivalent Logs inputs/preflight are acwd.9, not current landed behavior.
6. Build Secrets from the pinned checkout, following its existing Dockerfile:
   `docker build --build-arg SOURCE_COMMIT=<full-checkout-SHA> -f
   naapp/secrets/Dockerfile -t <run-local-image> .` Record image ID/revision;
   do not push it. Use the recipe's non-root, read-only container and key mount
   behind verified TLS. Logs currently launches `uvicorn aweb_logs.app:serve
   --factory` on8765 and reads ambient .env. Environment-only launch, build
   identity, fixed UID10001, HEALTHCHECK and the supported recipe/proof wait
   on acwd.9 -> acwd.8. Its source API is
   `create_app(LogsSettings(_env_file=None, ...), email=EmailSettings(...))`;
   S19 can compose it with the existing serving(), not a new launcher.
7. Check actual HTTPS /live, /health, /ready on intended origins. Secrets
   /health always200 is diagnostic, /ready gates checks, and labels.custody_mode
   must match the selected provider even on failure. Logs /ready checks database
   and outbox query, not age as a threshold; its checkpoint loop isn't readiness.
   Record non-secret check states, build identity, UID and expected refusals.
8. Install each *actually served* manifest through the row-2/owner command path,
   with its stable ID/origin/key purposes and scopes. Activate required real
   governance/use audit bindings before effects. Merely configuring an origin
   or reaching readiness does not install or activate it. This final row3 leg
   shares row4's missing owner/designation flow. Do not use fixture activation
   or direct SQL as the fresh-host receipt.

## 5. Human administration and workload (row4)

The supported sequence is: actual owner designation -> protected handoff ->
VIEW/LOGIN and distinct fresh APPROVE as required -> terminal/vault protected
value ingress -> real secret/operation/grant confirmation -> real runner-code
issuance -> register/doctor/run -> pinned synthetic workload. Every stage
retains its actual request/approval/job/dispatch IDs and canonical principal.
No component bootstrap fixture, invented email, direct database seeding or
fake SDK stands in for designation, approval or registration.

CURRENT STOP: acwd.4.2/.3 browser handoff (secrets-shared) feeds16.41 delivery
(shared),16.43 Secrets holding (app),16.44 Logs holding (Logs), consoles4.4,
app4.5 and owner-act commands4.6. Commands4.6 also consume4.9 and C3's app
half. Use the owners' landed/released exact command handoff once available;
W1/W2 subtree contracts are not prerequisites for this baseline.

Human-only: passkey enrolment and actual UV/confirmation; protected value input;
owner-issued runner registration. The authorized disposable-VM operator installs
the reviewed Linux exec chain/config/state and exact no-argument sudoers rule
from SUPERVISOR.md inside the VM only; this is not an install on Juan's host.
Other agents do not install it. The operator is the existing onboarding VM lead,
oats.aweb.ai/oats-operator-expert-onboarding-vm-campaign. Root supplies the artifact,
SHA256 manifest, exact commands and expected outputs directly, copying secrets,
servers and oats-expert-juan; actual outputs return to root. Source preparation
needs no BYOT member authority, but follow the VM owner's host -> BYOT -> runner
execution order. Real approval and registration remain required. The Linux install/worker boundary must be qualified;
existing macOS installed evidence is not Linux execution evidence. After real
registration doctor must pass before run. Root stages a Linux x64 interpreter/import/native closure under the existing
/opt/aweb-secrets-e2e prefix, with unchanged supervisor/launcher. The operator
creates a locked system aweb-runner account; records its UID and tester's UID
rather than copying macOS499; protects root-owned ancestors/code, runner-owned
0700 state and0600 config; validates the included sudoers rule with visudo and
sudo -l. Exact artifact/install commands and their review remain an S19 gap.
The existing S19 control pipe owns lifecycle; no systemd unit is added for this
rehearsal. Keep the same identity/journal/locks across restart. Prove INT via the actual sudo PID, and grace kill via a
noncooperative worker. Any privileged worker-only STOP is the disposable VM operator's explicit line
at that gate, not an agent sudo bypass.

Runner acwd.4.7 is queued in train33 per secrets' capability map. Real
registration completes HO6 step6. Doctor on an unregistered bootstrap can
correctly exit1; it is not job-success evidence. A matching reviewed job and
local/runtime pins are required. The retained ARM64 Oracle archive cannot
qualify Linuxx64. Use the chosen existing e2e/upstream/cli.py with its synthetic TLS receiver:
one GET /basic/echo, verified TLS, explicit CA, 10-second timeout and bounded
authenticated/refused output. Script SHA256 is
e4bceeb2094a7fef3b81375071d6dd65f2f1642c2114f3327437b6740a8242e8.
Root stages it; runner seat fits the fixed job/1 and matching local pin against
the target Python path/hash, sorted script/CA paths/hashes, fixed receiver
origin/public username, actual UIDs and registered runner ID. Never include the
approved CLI password or registration code in that handoff. Oracle and its OCI
user-namespace/tmpfs qualification are a later run, not this first exec job.

## 6. Permitted effects and refusal (row5)

Continue the same real run, after rows3–4 prerequisites. Use the actual member
signer/admission, a real lab target and the configured policy. API routes are
POST /v1/secrets/{secret}/requests, POST /v1/jobs/{job}/runs and
GET /v1/status/{ref}. These are APIs, not shell commands with secret arguments.

| Exercise | Required observation and refusal control |
| --- | --- |
| Permitted broker/job | Target observes the intended effect exactly as policy allows; caller receives only the approved projection/redacted result. Correlate request/job/dispatch/actor through Activity, drain, Logs ingest and the actual designated-reader session. |
| Unauthorized operation | Same real actor requests an operation outside its current grant. Admission refuses and the target's effect counter stays unchanged. A tool being listed is not authority. |
| Absent audit binding | Remove/withhold the binding through its supported owner operation in a distinct test case. An effect requiring audit must not proceed. Restore through that operation, not by writing binding tables. Keep the original refusal/status and target observations; do not infer a fixed public code without checking that route. |
| Revoked access | Revoke through actual owner/coordination authority. After the documented cache/fence rules, the next use is refused while the authorized neighbor still works. Check final-fence effects, not only a UI label. |
| Unknown outcome | Induce response loss using the existing upstream POST /{scheme}/reset or /{scheme}/slow path after a possible effect, and inspect GET /{scheme}/status/{key}. Retain original request/dispatch and target evidence. Poll original status; use the actual owner reconciliation VIEW/fresh decision path and its public reference. Verify the recorded settlement and absence of a second target effect. Never allocate a fresh request to hide uncertainty or clear state/outbox rows. |

CURRENT GAP: root S19 single-context startup/publication/browser/runner
integration (acgh.18.21) and row4 handoffs; app owns broker/use_ref/Logs-reader
journey (acgh.18.14). Component unknown-outcome/approval tests do not complete
this fresh-host run. Genuine 1Password same-reference version reconciliation
is separately open under18.54 and HO6 vault inputs; the native lab doesn't
qualify it. Keep that backend proof distinct from unknown-outcome settlement.

Record the actual demonstrated boundary, not just principal success/refusal.
OATS' shared UID/reachable keys are one boundary. Test whether A can reach B's
key/signing or privileged invocation before claiming narrower containment.
Driver-to-runner isolation requires the real installed chain/sudo and output
proof. No stronger per-worker claim follows from the broker's correct role check.

## 7. Operations and teardown (row6)

Use `naapp/secrets/deploy/OPERATIONS.md` and its exact arrangement/backend
matrix. Exercise restart with persistent state, supported upgrade with prior
state, revoke/containment and metadata-only incident diagnosis. A clean idle
restart does not prove durable pending-result acknowledgement. Logs reader
revocation must end the existing session on its next authorized read.

Backup/restore (pre-serve tombstones and expiry), native/Logs signing-key
rotation, export endpoint and operator chain verification remain named gaps
until their existing owners supply reviewed procedures and lab evidence.
Do not run a plain DB restore as an approved recovery or erase/rotate keys as
an unqualified repair. Logs L5 owns its missing tombstone replay; acgg.13 is the
closed rule source, not an open implementation blocker. acwd.7 stays open.

Exit scenario/reader/browser work first, stop/reap the sole RunnerHarness,
unpublish the selected runtime, then close the actual roots/lifespans/drains
and finally DNS/TLS/SMTP/target dependencies in reverse owned order. Keep the
runner journal for deliberate restart/recovery; remove only run-owned disposable
resources. The VM owner's vm.sh down removes the disposable overlay. Delete any private
awtest-* repository only by its exact recorded name/ID. No Docker prune or other
broad cleanup. Retain only sanitized
source/platform/mode/digest/ID/status/control/cleanup evidence. Publication JSON
is private state, not the acceptance record.

## 8. Capacity preflight, executed preparation and next steps

Before starting workloads on the 4GiB/30GiB VM, record df -B1, free -b and
Docker's root filesystem capacity; inspect exact image IDs/platforms/sizes and
run-owned container RAM/CPU during the smoke test. Account for unpacked images,
shared-layer deduplication, build scratch/cache, database volumes, runner Python
closure, host/OATS/harness memory and free operating headroom. A cold image size
is not a runtime RAM measurement; thin overlay capacity is not free space.
Read-only capability probes must establish Docker access, /dev/shm/tmpfs and
user-namespace availability as applicable. Container administration is reachable
privileged authority in the tester/agent boundary, not worker isolation.
Do not alter the VM's kernel settings or limits to make a probe pass silently.
On the VM, the operator records these bounded probes (no environment dump):

```sh
uname -srm
cat /etc/os-release
free -b
df -B1 /
findmnt -no FSTYPE,OPTIONS /dev/shm
docker info --format '{{.Architecture}} {{.Driver}} {{.DockerRootDir}}'
unshare --user --map-root-user true
```

Use the returned Docker root directory for its disk-capacity check. Record
failed/unavailable probes as such. User namespaces are needed by the later OCI
workload, not by the first fixed exec job; a failure excludes OCI qualification
rather than silently enabling namespaces. During each owned smoke run, use
`docker stats --no-stream --format '{{.Name}} {{.MemUsage}} {{.CPUPerc}}'
<owned-container-ids>` and inspect only those image IDs' Size/Os/Architecture.
Do not include other users' containers or configuration in evidence.

First sequence is Secrets+Logs+PG/Redis and the fixed TLS CLI; Oracle is
separate. Source Oracle lab.py requests a3GiB container memory limit plus
a768MiB proof tmpfs; those configured bounds are not measured resident usage
and do not justify co-locating the Oracle stack on this4GiB VM. Cached ARM64
image measurements on the development host: postgres:16-alpine388377970bytes,
redis:7-alpine58221010bytes, CoreDNS1.11.3 81818859bytes. These are ARM64 image
sizes only, not x64 footprints or total runtime memory. Secrets image, Logs
image, runner closure, actual x64 measurements and VM free capacity remain
unmeasured. Capacity fit is therefore pending, not a pass. If the first stack
does not fit, return measured shortfall and minimum justified capacity or a
sequencing change through secrets/servers to the existing VM owner; do not
resize or silently switch architecture.

Executed preparation follows.

Observed 2026-11-09 on the existing shared development host, **not** the fresh
Linux target: macOS27.2 build26B123, Darwin27.2.0 arm64; driverUID501;
uv0.13.7; DockerDesktop4.93.0/Engine29.8.1, Linuxarm64 kernel7.0.14-linuxkit;
OATS0.69.9; installed aw1.36.54/67a0083bc (too old for row2); checkout Python
3.13.15, Secrets/Logs0.1.0, naapp0.5.1, uvicorn0.54.0, FastAPI0.152.0,
asyncpg0.32.0. These are observations, not selected fresh-host versions.

Executed the real landed e2e/lab_environment.py with an explicitly empty input
environment and --private-dns excluded: exit2/lab_inputs_invalid with all18
selector names, no supplied values/credentials opened. This is expected
missing-prerequisite refusal, not service readiness or actor signing proof.

Queued under the existing suite lock with load<8: build an archived exact
main9a54 Secrets source context for linux/arm64 and run the existing
e2e/package_lab.py against it. Record the actual image architecture/digest;
this is ARM64 component evidence only. The fresh Linux x64 host builds and
qualifies its own linux/amd64 image. The probe uses
real disposable PostgreSQL/Redis/AWID/DNS/TLS and generated synthetic authority;
it proves a component, not row2 admission or row4 owner acts. Its AWID fixture
SQL must not be copied into the ordered host journey. Its local-key readiness
is separate from KMS and from the KMS-only published lab profile. No result
claimed yet. The product source is pinned; no second harness is introduced.

| Acceptance row | Next executable step | Current blocking dependency / owner |
| --- | --- | --- |
| 3 Services | Finish the source Secrets build/probe under the lock; on the reserved fresh host apply the actual private settings and run real root readiness | Allocated Ubuntu24.04amd64 VM: capacity/capability/readiness still required from root + VM operator; real row2 authority inputs: lab operator; Logs .9->.8: Logs owner. Audit activation also waits on row4. |
| 4 Human/workload | Consume the reviewed4.2 handback, drive actual first-owner/reader designation and protected confirmation, then register the operator-installed runner | 4.2/.3 ->16.41/16.43/16.44 and4.4/.5/.6;4.9/C3; Root Linux artifact/install instructions and runner-fitted TLS job pins under4.7/HO6. Owners as named in section5. |
| 5 Effects/refusal | Enter one S19 runtime and execute the five cases in section6 with actual target/read evidence | Rows3–4 and S19 context18.21 (root); app18.14 consumer; no invented approval or binding. |
| 6 Operations/support | Exercise each supported OPERATIONS matrix path against that same exact arrangement; leave unsupported paths blocked | Row3–5 state and each existing restore/rotation/export procedure gap; accountable root/acwd.7 with Logs reviewing its part. |

Review requested before this artifact becomes an operator receipt. Missing
human/host/packaging prerequisites remain visible rather than skipped. Actual
source-candidate execution outcomes must replace the queued/unfilled entries;
then the published-artifact replay and full product gates still stand.
