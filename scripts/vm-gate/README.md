# vm-gate

Dispatch aweb's test-only candidate gate, or a focused command, to a disposable
Hetzner VM. The caller stays on the Mac; the gate executes as UID 1000 on Linux.
Each invocation keeps an independent VM and evidence directory. This increment
supports aweb; Cloud and warm caches are separate work.

## Install and configure

Use Python 3.12+ and an isolated environment. Install the pinned provider SDK:

```sh
python3 -m venv /your/external/venv
/your/external/venv/bin/pip install -r scripts/vm-gate/requirements.txt
```

Put that environment's bin directory on PATH. `scripts/vm-gate/vm-gate` is the
entry point. Local Git, SSH/scp/ssh-keygen, bash, make and the repository's lint
prerequisites must be available. Run as a normal operator account.

Create a private JSON config **outside the repository**, and select it with
`VM_GATE_CONFIG` or the global `--config` option. Operator configuration is not
committed or sent to reviewers.

| Field | Value |
|---|---|
| `repo` | Absolute local aweb checkout (optional default for snapshot) |
| `state_root` | Absolute private directory, shared by all dispatcher workers |
| `ledger` | Absolute canonical candidate-gate ledger, shared with the Mac gate |
| `token_file` | Absolute provider credential file, readable by the operator |
| `owner` | Provider-label-safe seat name |
| `location` | Provider location for both VM and Primary IP |
| `snapshot_id` | Integer ID of the existing verified Linux amd64 base |
| `snapshot_manifest` | Absolute path to that base's recorded host manifest |
| `cap_eur` | Cumulative lab ceiling, initially `"150"` |
| `seed_eur` | Historical lab charges before this registry; applied once |
| `run_ceiling_eur` | Optional smaller per-run reservation ceiling |
| `snapshot_type` | `ccx33` by default, or `ccx43` |
| `setup_seconds` | Optional setup bound, default 900 |
| `pull_seconds` | Optional evidence-transfer bound, default 600 |
| `cleanup_seconds` | Optional cleanup allowance, default 300 |
| `margin_seconds` | Optional completion margin, default 300 |
| `lint_timeout_seconds` | Optional total local lint bound, default 600 |

`state_root`, `ledger`, `token_file` and `snapshot_manifest` must be absolute
and outside the selected source repository. Protect config and credential files
with mode 0600. Token input goes only through `preflight.read_hcloud_token`,
selected by `HCLOUD_TOKEN_FILE` in the parent while constructing the provider
client. Its value is never exported to children. All workers must use the same
SQLite registry; creating another state root would create another spend ledger.
Seed historical and concurrent legacy-lab obligations conservatively before the
first dispatcher allocation. Changing `seed_eur` later does not rewrite history.

The manifest records `observed` Go/uv/Node/Python requirements, `commands` with
path/target/sha256 for go, uv, uvx, node, npm, python3, git, make, bash and docker,
and the exact `dpkg` inventory string. Start with the operator's verified base
receipt. Empty hashes or an unverified base are refused. Package/binary identity
and source-derived requirements are checked again on every VM.

## Run

```sh
vm-gate run --repo "$REPO" --sha "$SHA" --type ccx43
vm-gate run --repo "$REPO" --sha "$SHA" --stages 'checks integration'
vm-gate run --repo "$REPO" --sha "$SHA" --command 'make test-one-target' --timeout 1200
vm-gate run --repo "$REPO" --sha "$SHA" --intent train --type ccx43
vm-gate status
vm-gate reap
vm-gate snapshot --repo "$REPO" --sha "$SHA"
```

No selector uses the source's ordinary `make candidate-gate` entry. Stage
subsets use its existing selector. Train intent reproduces the coordinator's
explicit five-stage command: checks, user-paths, unit, artifacts, integration.
A train SHA must contain freshly refreshed real origin/main, and main must not
move before or during the run. A branch qualification recreates a frozen local
origin with its main at the selected SHA; the real main OID and both ancestry
relations remain in source.json/summary.json. The coordinator handles landing
and release tags. Focused commands run as supplied, with no inherited sizing
or stage environment overrides.

Before reading credentials, admission checks config, clean checkout, exact
commit, source pins versus base manifest, bundle refs and shell syntax. It then
runs the selected source's checks-list lint/format targets on a temporary exact
checkout. Containers are disabled there; a failing check prints its output and
refuses allocation. A formatter that changes bytes also refuses. The VM still
runs the requested checks stage unchanged. Local logs and pass lines are in
`local-checks.json` and summary.json, including on refusal.

Each admitted run reaps expired dispatcher resources before creating anything.
A capacity refusal names the server type and provider code, with no retry or
fallback. Other failed/uncertain creates reconcile labels and stop. SDK mutation
retries are disabled and read back using hcloud 2.27.0's real client layout.
Reads may retry transient failures three times. A per-run Ed25519 host key is
generated locally and injected with cloud-init's ssh_keys; its public key is
pinned under a separate alias for every server ID before SSH begins.
StrictHostKeyChecking=yes and a private known_hosts file prevent first-contact
key acceptance. After positive pinned readiness, a valid mismatched-key control
must fail specifically at host verification before setup continues. The host
private key exists in provider user-data and local private state for that
disposable run; cleanup and reaping remove the local keys after proven absence.
This is the accepted single-tenant VM trade-off. See the
[cloud-init SSH schema](https://docs.cloud-init.io/en/latest/reference/modules.html#ssh). The gate user belongs to the Docker group; UID admission
is not a privilege-separation claim.

Expiry includes setup, full command timeout, TERM/KILL grace, evidence pull,
cleanup and margin. No phase starts if its remaining budget cannot fit.
Deletion runs independently of log transfer, ignores repeated termination
signals during cleanup, and proves paginated-label plus recorded exact-ID
absence for server, Primary IP and SSH key. SIGKILL/host loss needs the next
`run` or an explicit `reap` after expiry. Missing or inconsistent expiry labels
fail closed with resource IDs while unrelated valid expired runs are cleaned.
B2 uses `aweb-vm-gate.*`; legacy B1 diagnostic labels are separate.

## Evidence, ledger and spend

`state_root/runs/<run-id>/summary.json` contains SHA/scope, requested work,
per-stage status/time, exit/classification, server/resources, timestamps, sampled
host peak and concurrent cgroup memory sum, estimated billed-hour cost and
cleanup proof. `REUSED` stages have their original log and no invented duration.
Focused commands may have no stages. Full logs, raw archive, source manifest,
bundle, provider events, summary.tsv files and immutable before/after gate
ledger copies remain beside it. Nested prerequisite evidence is retained, but
its unrelated SHA does not become the selected gate's stage result. Sampling
gaps/removal races remain explicit. Raw archives stay local/operator-only.

[errors.py](vm_gate/errors.py) is the single exit-code authority. Normal gate
exits pass through; refusal and infrastructure errors have separate classes.
Read `summary.infrastructure` to disambiguate a gate using the same numeric code.
An infrastructure failure cannot produce a successful exit. Partial evidence
is attempted after a controller failure without delaying provider cleanup past
its completion bound.

The canonical tree lease is held through source-ledger snapshot, VM execution
and import. Same-tree simultaneous attempts refuse; different trees run in
parallel. New rows append under a writer lock; the original prefix and all
failure rows survive. Remote gate logs are copied to the same absolute canonical
paths. Existing source failed-tree/reuse rules apply equally to VM and Mac rows.
A run never clears a failure row to retry it.

SQLite `registry.sqlite3` serializes registry/spend changes. Reservations count
historical seed, settled charges and all outstanding runs. They use live EUR
server and IPv4 pricing rounded conservatively for the completion budget.
Normal cleanup settles estimated provider billing hours. An uncertain outcome,
unknown pricing or unproven absence keeps the reservation. Reaping settles only
after label and recorded-ID absence, conservatively through reap time. Daily
charges plus outstanding reservations warn at EUR 20; cumulative reservations
refuse past the configured cap. Reconcile actual invoices separately.

## Snapshot updates

A pin mismatch names the tool, required/observed values and selected SHA, and
prints `vm-gate snapshot --sha <SHA>`. The command resolves exact public download
checksums locally, then builds from the configured snapshot, changes Go/uv/Node,
checks package/unrelated binary identity, scrubs source and credentials, and
creates a protected candidate snapshot. A separate restored VM verifies the
new receipt before config changes and before the old base is deleted. Python
base changes require a separate OS migration and refuse before allocation.

A stable exclusive config lease protects rebuild/publish against concurrent
runs using the old base. Config replacement is atomic and synced. Candidate
images are outside the transient cleanup selector from creation: a failed new
snapshot remains labelled and reported for the operator, while the old base is
retained. Successful restored verification publishes the new ID/manifest before
retiring the old image. Compute/IP charges and a conservative fourteen-day
snapshot-storage upper bound count against the cap; the storage allowance is
identified separately from observed compute. Do not delete a retained candidate
or adjust an unknown-cost reservation without reconciling the provider receipt.

## Tests and review

Deterministic tests need no Docker or external database:

```sh
PYTHONPATH=scripts/vm-gate python3 -m unittest discover -s scripts/vm-gate/tests -v
```

The real SDK constructor test makes no network call. The fake provider/SSH tests
cover failed creates, capacity refusal, lost evidence, SIGTERM during cleanup,
parallel reservations, exact-ID absence, stale main, source refs/pins, snapshot
restore failure and conditional old-base retirement.

Real provider acceptance is separate and **opt-in after source review**. Use a
private config pointing at the same lab registry, with `run_ceiling_eur` at most
one quarter of the separate test cap, and setup180/pull60/cleanup60/margin30.
Use two clean, reviewed SHAs with different trees and matching base pins:

```sh
VM_GATE_REAL_PROVIDER=1 python3 scripts/vm-gate/acceptance/real_provider.py \
  --config "$CONFIG" --repo "$REPO" --sha-a "$SHA_A" --sha-b "$SHA_B" \
  --output "$NEW_PRIVATE_RECEIPT_DIR" --max-eur 1.50
```

This runs the parallel and SIGKILL/reaper scenarios once: two overlapping CCX33
focused Docker commands, one killed mid-command, then one next invocation that
must reap the expired victim before its own planted exit-7 control. Four runs
maximum; every live-price reservation has the test ceiling. The output directory
has an exclusive started marker; failures stop instead of creating replacements.
The expiry wait is part of the reaper proof, not permission to shorten a live
run's completion bound. Report provider IDs, overlap, exit-7 propagation,
absence and total cost from acceptance.json. No full-gate PASS is inferred from
these focused infrastructure controls.

## Native ARM OCI consumer

`native-arm64-oci-v1` is a separate, narrowly scoped host profile. It uses
CAX21 in fsn1 and stock Ubuntu 24.04 ARM image 161547270. It does not claim
compatibility with a verified x86 snapshot or run a candidate gate. The
operator must obtain review/allocation authority for this profile and the
exact image-test source before using it.

An external config uses the same `state_root`, `ledger`, `token_file`,
`owner`, `location`, cap and seed as the existing dispatcher. Set
`host_profile` to `native-arm64-oci-v1` and `native_profile` to an absolute
external JSON path; omit `snapshot_id` and `snapshot_manifest`. The profile
JSON contains `profile` and `apt`: the official Docker Ubuntu URI,
`noble`/`stable`/`arm64`, signing-key primary fingerprint and SHA256, and
exact `Package`, `Version`, `Architecture`, `Filename` and `SHA256` entries
for docker-ce, docker-ce-cli and containerd.io. Package payloads must match
both those pins and the signed APT index. Preparation records the actual
kernel, package set and tool hashes. It reuses the account whose UID is
1000, adds Docker group membership, and verifies admission again in a fresh
non-root process. No runtime emulation is installed.

The CLI accepts only this focused consumer invocation (paths are examples):

```sh
scripts/vm-gate/vm-gate --config /operator/native-arm.json run \
  --repo /operator/checkout --sha <full-reviewed-source-sha> \
  --type cax21 --timeout 900 --command 'make test-server-image-build' \
  --archive-in /operator/x86-run/server.oci.tar \
  --amd64-receipt /operator/x86-run/native-receipt.json
```

Before provider access it verifies the local archive's size/SHA256, the x86
native success receipt, source/version, and the dual-platform OCI index
using the candidate's existing pure `oci-exact-publish.sh inspect-staged`.
Transfer uses a temporary path, explicit UID-1000 ownership and mode 0600,
then verifies size/SHA256 on the ARM host before publishing the fixed input
path. The consumer sets `AWEB_SERVER_IMAGE_ARCHIVE_IN`, never OUT. The
reviewed image harness independently validates source/version/platforms
before importing and executes only the Docker daemon's native architecture.

For the x86 build half, `run --archive-out --command 'make
test-server-image-build'` selects `ArchiveExecutor`, sets
`AWEB_SERVER_IMAGE_ARCHIVE_OUT=/evidence/server.oci.tar`, and explicitly
collects the actual tar with local SHA256/size verification before host
cleanup. It retains the tar even when a later runtime probe fails. This flag
adds retention; x86 build prerequisites still require the existing reviewed
x86 preparation adapter/manifest. An operator using that preparation
extension can subclass `ArchiveExecutor` through `Runtime.executor_factory`.
The flag does not admit changes to a snapshot's package/binary manifest.

Both halves emit `native-receipt.json`. A complete qualification requires
native amd64 AND native arm64 success, packaged UID 1001, and identical tar
SHA256/size, OCI index, source and version. One successful host never produces
a pair verdict. Archive retention failure is an infrastructure/refusal
result, and ordinary owned-resource cleanup still runs. Archives remain in
the local per-run directory after deletion; the operator owns their final
removal. SSH host pinning, wrong-key refusal, spend registry, expiry/reaper
and exact-ID cleanup are shared with the x86 dispatcher. The distinct
profile is recorded in the summary and on the server label.

Stock-host cloud-init admission records the original wait status, detailed
JSON status and warning/error lines before interpreting them. An unknown
recoverable error refuses even when cloud-init reports `done`. The production
allowlist is empty; adding an exact category/message requires review of an
observed diagnostic. Initialization runs as its own checked phase before
package preparation. Its private diagnostic bundle is retained locally even
when admission fails before the ordinary evidence collector can run.
[Cloud-init documents the distinct exit codes and detailed status](https://docs.cloud-init.io/en/24.3/explanation/return_codes.html).

Host-key user-data supplies the per-run `ssh_keys` directly and omits the
redundant empty `ssh_genkeytypes` array: the
[SSH schema requires a nonempty generation list when supplied](https://github.com/canonical/cloud-init/blob/main/cloudinit/config/schemas/schema-cloud-config-v1.json),
and [supplied keys select the existing-key branch rather than generation](https://github.com/canonical/cloud-init/blob/main/cloudinit/config/cc_ssh.py).
Strict host pinning and the valid wrong-key refusal still apply. This removes
a source-level schema violation; it does not establish which warning occurred
on a deleted host whose detailed initialization errors were not retained.
