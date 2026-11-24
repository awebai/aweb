# BYOT rehearsal and preflight

Run this procedure in order on a disposable, synthetic BYOT installation. If a
prerequisite is missing, record that step as blocked. Continue an independent
check only when it can use its own valid authority. Keep customer data and
production credentials out of the rehearsal.

## 1. Select the target and freeze the input versions

Classify the run as a source-candidate or published-artifact rehearsal. A
published-artifact rehearsal installs the published images and distributions
and verifies their digests or checksums. Keep both receipts separate from the
full Secrets release gate.

| Input | Record before starting |
| --- | --- |
| Disposable Linux target | Distribution, architecture, kernel, base-image digest, and supported provisioning procedure |
| Host tooling | OATS, Git, Node, tmux, selected harnesses, Docker and Compose versions |
| OATS-managed agent client | Compatible OATS Desktop and `aw` versions, if Desktop is in use |
| Human and coordination clients | Separate pinned `aw` and server versions that support the selected owner and reader ceremonies |
| Service source and deployment | Source SHA, frozen locks, image platform and digest, and the selected private deployment recipe |
| Runner and first workload | Supervisor, runtime and workload artifacts for the target architecture, with job definition digest and local pins |

Use the frozen locks and target-platform images. Retain version output from
`cat /etc/os-release`, `uname -srm`, `getconf GNU_LIBC_VERSION`, the tool
version commands, and the selected `aw`, OATS and harness binaries. Keep
actual host, actor and receipt details in the operator's private run record.
Confirm capacity and permission with the host operator before starting. Complete the [capacity preflight](#8-capacity-preflight)
before deployment.

## 2. Complete host and identity prerequisites first

Where Desktop manages the selected CLI, confirm that its supported range
includes the selected `aw` version. If needed, select a compatible pair. For a
headless worker, use CLI and SSH. Human keychain operations stay on the
operator's machine. Keep the managed agent CLI separate from a candidate CLI
used for the rehearsal.

Follow the OATS getting-started skill and headless server guide for the
selected OATS version. The supported remote connection uses
`oats server connect <id> --ssh <alias> --dir <absolute-directory> --install-oats`
and then `oats server check`. Run `oats doctor`,
`oats readiness --home <home> --json`, and `oats aweb setup --check-only --json`
from the intended deployment.

Use the selected namespace creation or invite-stdin join route with the
authorized namespace, registry and coordination inputs. Reserve provider
sign-in, namespace-owner actions, invite input and approval of setup changes
for the authorized humans. Record when a pre-supplied login leaves part of
that ceremony untested.

A native invitation does not transfer the local issuer record or controller
key. For a worker with its own supported signing identity, use the
cross-machine sequence `aw id team request`, controller `aw id team add-member`,
worker `aw id team fetch-cert`, then workspace connect. If the worker's
signing identity cannot be prepared through the selected release's supported
operations, stop at that prerequisite.

Use real human and agent membership, canonical team IDs, current certificates
and namespace `_awid` DNS. Verify that the selected registry, namespace and
signed coordination publication agree. Use the exact client versions that
support the served role and owner-act contract. Keep install authority
separate from human designation. Packaging fixture SQL cannot qualify fresh
host identity or admission.

## 3. Enumerate private references and the actual trust boundary

Before starting either service, the operator creates private, non-repository
configuration and generated lab key files. Values stay in private memory/files,
not shell arguments, mail, fixtures or evidence. Inventory selector names and
readiness only. Do not source runtime.json or a file containing arbitrary shell.

Set the `AWEB_SECRETS_E2E_` selectors required by the
[lab loader](../e2e/lab_environment.py).

| Group | Selected names |
| --- | --- |
| Authority and services | TEAM_ID, API_ORIGIN, CONSOLE_ORIGIN, LOGS_ORIGIN, LOGS_CONSOLE_ORIGIN, AWID_REGISTRY_URL, COORDINATION_ORIGIN |
| Custody | CUSTODY_MODE and either CUSTODY_KEY_FILE or KMS_KEY_ARN, AWS_REGION and KMS_CREDENTIALS_FILE |
| Runner | RUNNER_BINARY, RUNNER_CONFIG_FILE, RUNNER_USER, RUNNER_STATE_DIR |
| CLI and actors | AW_BINARY, HUMAN_IDENTITY_HOME, AGENT_A_IDENTITY_HOME, AGENT_B_IDENTITY_HOME |

Choose the private DNS mode explicitly. `included` requires PRIVATE_DNS_NAME
and the refusal scenario. `excluded` leaves this scenario outside coverage.
Registry and namespace DNS are required for either mode. From `naapp/secrets`,
install the checkout's dependencies with `uv sync --frozen`. For example,
run `uv run --frozen --no-sync python e2e/lab_environment.py --private-dns excluded`
to validate the selected references. Missing or invalid input exits with
status 2. This check leaves credentials unopened and services stopped.

Choose one custody mode per run. For KMS, configure
`SECRETS_KMS_KEY_ID` and `SECRETS_KMS_REGION` with an authorized runtime
principal, and give the driver a separate lab-only principal restricted to
the selected lab key. Local mode uses `SECRETS_CUSTODY_KEY_FILE`. Confirm that
the selected lab profile supports the chosen mode. Treat a failed canary as a
refusal, and report local and KMS results separately. Native and 1Password
qualifications also remain separate.

Keep the operator, agent driver, Secrets runtime and runner distinct where
the rehearsal claims OS-level isolation. Have the operator record privileges
and relevant access privately. Agents that share a UID and can reach one
another's keys or signing interfaces share a trust boundary. A driver that
can use a KMS key shares that decrypt authority. An agent with Docker or host
administration can cross the container boundary. Verify access denials from
the agent context before claiming isolation, following the assurance matrix
in [Operations](OPERATIONS.md).

## 4. Install and start the two service roots

### Operator container prerequisites

The operator installs the selected supported Docker and Compose packages.
For Ubuntu, use the signed distribution repository and record the actual
package sources and versions. Run the following from the operator context.

```sh
sudo apt-get update
LC_ALL=C apt-cache policy docker.io docker-compose-v2
docker_pkg_version=$(LC_ALL=C apt-cache policy docker.io | awk '/Candidate:/ {print $2}')
compose_pkg_version=$(LC_ALL=C apt-cache policy docker-compose-v2 | awk '/Candidate:/ {print $2}')
test -n "$docker_pkg_version" && test "$docker_pkg_version" != '(none)'
test -n "$compose_pkg_version" && test "$compose_pkg_version" != '(none)'
sudo apt-get install -y --no-install-recommends "docker.io=$docker_pkg_version" "docker-compose-v2=$compose_pkg_version"
sudo systemctl enable --now docker
dpkg-query -W -f='${Package} ${Version} ${Architecture}\n' docker.io docker-compose-v2 containerd runc
sudo docker version
sudo docker compose version
sudo docker info --format '{{.OSType}}/{{.Architecture}} {{.Driver}} {{.DockerRootDir}}'
```

If a candidate is unavailable, stop and retain the package-source status.
Keep Docker operator-controlled and the socket inaccessible to agents. Apply
the same context to all build, inspect, runtime and cleanup commands. Keep
negative agent-context probes unprivileged.

Prepare the reviewed Compose configuration for the two services, PostgreSQL
and Redis, together with the selected AWID and coordination origins, TLS,
SMTP and synthetic target. Use disposable state. Stop if the deployment
recipe or its private inputs are missing. The isolated Secrets packaging
probe qualifies its own component path. Keep its unprivileged driver and
fixture dependencies separate from this operator-run configuration.
Record the Compose file identity privately. Avoid capturing resolved Compose
configuration, which can include private environment values.

### Service configuration and start order

1. Freeze each stable app ID and the four HTTPS origins for the Secrets and
   Logs APIs and consoles. Give the consoles separate hosts from their APIs.
   The Logs console must not be a parent of its API hostname. Match the
   actual listener configuration and host routing to the public origins.
   Verify TLS and browser reachability from the intended client.

2. Provision PostgreSQL roles and databases using the existing operator route.
   Prepare the Secrets schema and initialise its erasure ledger with the
   operator role before first start. Secrets uses the restricted runtime role
   to verify the prepared store. Logs applies its migrations at startup. Do
   not create Secrets or Logs domain authority rows directly. Keep dependency
   services alive until drains and app lifespans finish.
3. Configure Secrets using its [deployment inputs](README.md). Mount the
   runtime database DSN, keys and SMTP credentials as private files. Assign
   independent keys to the expected manifest purposes.
4. Configure Logs using its [deployment inputs](../../logs/deploy/README.md).
   A database reader can read retained content across teams. Chain signing
   plus database write can rewrite and re-sign history. Detection requires
   external witnesses covering the affected positions.

5. Configure Secrets broker/hook egress separately. SECRETS_EGRESS_DENIED_NETWORKS
   reaches both guards. Public/system trust is default. Internal hook delivery
   requires all of SECRETS_HOOK_INTERNAL_DESTINATIONS=allowed,
   SECRETS_HOOK_INTERNAL_CIDR and SECRETS_HOOK_INTERNAL_ORIGINS; use only the
   exact installed Logs origin and actual listener network. Every DNS answer
   must be inside the CIDR and outside immutable/deployment denials. Optional
   SECRETS_HOOK_CA_FILE applies to all hook deliveries. Keep broker CA and
   routing decisions separate.
6. Follow the maintained [Secrets](README.md) and
   [Logs](../../logs/deploy/README.md) deployment recipes. For a source
   candidate, build from the pinned checkout with its Dockerfiles and record
   the source and image identities privately. Use the recipes' non-root,
   read-only containers and mounted key files behind verified TLS.

7. Check HTTPS `/live`, `/health` and `/ready` on the intended origins.
   Secrets health is diagnostic. Use readiness to decide when to proceed,
   and verify `labels.custody_mode` on success and failure. Logs readiness
   checks database and outbox access.
   Record non-secret check states, build identity, UID and expected refusals.
8. Install each *actually served* manifest through the authorized install command,
   with its stable ID/origin/key purposes and scopes. Activate required real
   governance/use audit bindings before effects. Merely configuring an origin
   or reaching readiness does not install or activate an app. Complete the
   owner/designation steps below before treating audit binding as active.
   Use product routes for activation.

## 5. Human administration and workload

The supported sequence is: actual owner designation -> protected handoff ->
VIEW/LOGIN and distinct fresh APPROVE as required -> terminal/vault protected
value ingress -> real secret/operation/grant confirmation -> real runner-code
issuance -> register/doctor/run -> pinned synthetic workload. Every stage
retains its actual request/approval/job/dispatch IDs and canonical principal.
No component bootstrap fixture, invented email, direct database seeding or
fake SDK stands in for designation, approval or registration.

Confirm that the selected release provides the owner-act, handoff and
confirmation commands and that the corresponding service and console
support them. Stop at any missing deployment or command prerequisite.

Reserve passkey enrolment, user verification, protected value input and
runner registration approval for the authorized humans. The operator uses
the reviewed installation instructions and
[supervisor boundary](../e2e/SUPERVISOR.md) to install the target-platform
Linux exec chain. Require the artifact, digest and instructions before
installation. Run the installation inside the disposable environment.

Use a dedicated non-login runner UID distinct from the operator and agent.
Protect the root-owned chain, runner-owned 0700 state directory and 0600
configuration. Validate the exact no-argument sudoers entry with `visudo`
and check its effective policy with `sudo -n -l`. From the agent context,
verify that general root access, Docker socket access, unrelated privileged
commands, and reads of existing operator or runner private files all refuse.
Verify private files exist from their owner context without recording their
contents. If the agent can regain operator authority, report lifecycle
mechanics and leave UID isolation unqualified.

Use the existing supervisor control pipe. Keep the runner identity, journal
and locks across restart. Exercise INT through the actual process boundary
and bounded grace kill with a noncooperative workload. Reserve any
privileged worker-only stop for the disposable environment's operator.

Issue a real registration code through the owner flow. Register the runner
and require doctor to pass before running the job. Prepare the fixed
[e2e TLS CLI](../e2e/upstream/cli.py) and its synthetic receiver. Pin the
job definition and the actual interpreter, script and CA paths and digests.
Use verified TLS, the fixed receiver route and bounded output. Keep
registration codes and credentials out of the handoff. Treat the optional
OCI workload as a separate run requiring its own reviewed artifact,
user-namespace and tmpfs preflight.

## 6. Permitted effects and refusal

Continue with the same installation after service readiness and runner
qualification. Use the actual member signer, lab target and policy. API routes are
POST /v1/secrets/{secret}/requests, POST /v1/jobs/{job}/runs and
GET /v1/status/{ref}. These are APIs, not shell commands with secret arguments.

| Exercise | Required observation and refusal control |
| --- | --- |
| Permitted broker/job | Target observes the intended effect exactly as policy allows; caller receives only the approved projection/redacted result. Correlate request/job/dispatch/actor through Activity, drain, Logs ingest and the actual designated-reader session. |
| Unauthorized operation | Same real actor requests an operation outside its current grant. Admission refuses and the target's effect counter stays unchanged. A tool being listed is not authority. |
| Absent audit binding | Remove/withhold the binding through its supported owner operation in a distinct test case. An effect requiring audit must not proceed. Restore through that operation, not by writing binding tables. Keep the original refusal/status and target observations; do not infer a fixed public code without checking that route. |
| Revoked access | Revoke through actual owner/coordination authority. After the documented cache/fence rules, the next use is refused while the authorized neighbor still works. Check final-fence effects, not only a UI label. |
| Unknown outcome | Induce response loss using the existing upstream POST /{scheme}/reset or /{scheme}/slow path after a possible effect, and inspect GET /{scheme}/status/{key}. Retain original request/dispatch and target evidence. Poll original status; use the actual owner reconciliation VIEW/fresh decision path and its public reference. Verify the recorded settlement and absence of a second target effect. Never allocate a fresh request to hide uncertainty or clear state/outbox rows. |

Run these scenarios in the same prepared deployment, using its real browser,
runner and audit bindings. Component procedures support diagnosis. They do
not substitute for the same-installation observations. Track 1Password
same-reference version reconciliation separately from unknown-outcome
settlement.

Record the actual demonstrated boundary, not just principal success/refusal.
OATS' shared UID/reachable keys are one boundary. Test whether A can reach B's
key/signing or privileged invocation before claiming narrower containment.
Driver-to-runner isolation requires the real installed chain/sudo and output
proof. No stronger per-worker claim follows from the broker's correct role check.

## 7. Operations and teardown

Use `naapp/secrets/deploy/OPERATIONS.md` and its exact arrangement/backend
matrix. Exercise restart with persistent state, revoke/containment and
metadata-only incident diagnosis. Secrets upgrade with prior state remains
pending under `aweb-adtj`. Check pending-result acknowledgement across
restart and check that reader revocation ends an existing Logs session on
its next authorized read.

Exercise backup/restore, signing-key rotation, export or operator chain
verification only with a reviewed procedure for the selected deployment.
Include pre-serve tombstones and expiry in any supported restore procedure.
Record unsupported operations as gaps.

Exit scenario/reader/browser work first, stop/reap the sole RunnerHarness,
unpublish the selected runtime, then close the actual roots/lifespans/drains
and finally DNS/TLS/SMTP/target dependencies in reverse owned order. Keep the
runner journal for deliberate restart/recovery; remove only run-owned disposable
resources through the reviewed deployment and host tools. Preserve no
credential or raw runtime configuration in the evidence. Retain sanitized
source, platform, mode, digests, statuses, controls and cleanup observations.

## 8. Capacity preflight

Before starting either service, check the host, Docker storage and memory
with operating headroom. Account for image layers, build scratch space,
database volumes, runner closure, OATS and the harness. Measure the selected
target rather than reusing figures for a different architecture or run.
Validate Docker and tmpfs access. Check user namespaces where the selected
workload requires them. Record unavailable probes and keep the host's
configured security policy.

From the operator context, collect the bounded probes that apply:

```sh
uname -srm
cat /etc/os-release
id -u
id -g
id -Gn
sudo -n -l
free -b
df -B1 /
findmnt -no FSTYPE,OPTIONS /dev/shm
sudo docker info --format '{{.Architecture}} {{.Driver}} {{.DockerRootDir}}'
unshare --user --map-root-user true
```

Check free space on the filesystem that contains Docker's root directory.
During the smoke test, use `sudo docker stats --no-stream` for the owned
containers and `sudo docker image inspect` with the size, OS and architecture
fields for the owned images. Keep measured sizes, account inventory and
privileged command policy in the private run record.

Run Secrets, Logs, PostgreSQL, Redis and the fixed TLS CLI before optional
workloads. If the stack lacks capacity, record the shortfall and have the
operator review a compatible target or sequence. A complete result records
service readiness, human and runner qualification, permitted and refused
effects, and the supported operations the rehearsal exercises.
