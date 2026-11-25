# vm-gate

Dispatch aweb's test-only candidate gate, or a focused command, to a disposable
Linux VM on Hetzner or Merak. The Mac controller stages each invocation in
its own guest and evidence directory. The gate executes as UID 1000.

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
explicit six-stage command: static, checks, user-paths, unit, artifacts,
integration.
A train SHA must contain freshly refreshed real origin/main, and main must not
move before or during the run. A branch qualification recreates a frozen local
origin with its main at the selected SHA; the real main OID and both ancestry
relations remain in source.json/summary.json. The coordinator handles landing
and release tags. Focused commands run as supplied, with no inherited sizing
or stage environment overrides.

Before reading credentials, admission checks config, clean checkout, exact
commit, source pins versus base manifest, bundle refs and shell syntax.

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

The executor starts a detached, HUP-resistant `runuser` session. GNU timeout
runs inside that UID-1000 session and signals a small supervisor; the supervisor
forwards to the command's separate process group. It permits 120 seconds for
finalization, then kills that owned group. GNU timeout has a 130-second fallback,
and SSH/completion budgeting reserves 150 seconds. Actual command return codes,
forwarded signals, escalation times and completion receipts are retained.
A controller stop requests that same supervisor before collecting evidence.
A completed process group alone does not attest gate cleanup: on interruption,
`finalized` also requires registered current-run gate cleanup receipts, with
matching run IDs, successful wrapper verdicts and completed log writers.
The gate records completed stages first, forwards the signal to its direct
child, waits for child cleanup and its signal-resistant log writer, then records
that observed cleanup outcome in `interruption.tsv`.
Missing/late completion is inconclusive: bounded stop failure never prevents
the subsequent partial-evidence pull or provider cleanup.

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
gaps and failed reads remain explicit; a persistent read failure is not assumed
to be a removal race. Each failed cgroup read retains the known PID, cgroup,
failing filename and error type; unavailable context remains null. Other fields
successfully read for that container are retained. Each sample reports the
listed container count, readable `memory.current` count and complete-row count.
The concurrent current-memory figure is labelled **lower bound, N of M containers
read**, with its sample index and completeness, rather than a complete-container
peak or a sum of independent high-water values. Without a listed count, coverage
is inferred from recorded row/error IDs and labelled as such; missing inventory is unknown,
not zero. An incomplete final JSON line is an explicit sample error and cannot
discard completed gate stages. Old errors lacking path context cannot establish
which file failed or why. Raw archives stay local/operator-only.
The UID-1000 candidate can write LOGS, including exit/supervisor receipts; these
are operator observations, not an attestation against malicious candidate code.
Root stop validates the live PID/start-time/UID/command before sending a signal.

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

On TERM/INT the gate records only completed PASS rows with this invocation's
matching run-id, summary entry and nonempty stage log. It retains exit 143/130
and appends a `run INTERRUPTED` summary entry; an unfinished stage gets no
invented pass or code-failure verdict. Cleanup receipts remain separate.
An `artifacts` PASS certifies that the artifact build/validation targets passed
for the ledger's tree and effective inputs. It does **not** promise retained
wheels, archives, images or node modules in a later disposable runner.
`candidate-suite.sh` prepares node dependencies and the CLI build before a
resumed integration stage, even when artifacts is reused. The OSS journey
(including its controller-key mutation) builds its CLI and Compose images;
the exact-publish self-tests construct their own fixture outputs. Publication
of particular staged bytes still requires those bytes and their own receipts.

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

## CPU and contention evidence

Each native command captures `host-metrics-before.json`; collection captures
`host-metrics-after.json` even when the command did not return a completed exit
receipt. Each observation is best-effort: a 3-second remote timeout (1-second KILL
grace) and at most 5 seconds of transport time within the existing phase
deadline. Collector exit/stdout/stderr or transport errors are retained in
local `host-metrics-*-observation.json` sidecars when writable. Failed telemetry
does not stop execution or required archive collection; those checks remain
strict. These are guest-visible CPU model/family/stepping, raw `/proc/stat` and
aggregate ticks (including steal/iowait), with SC_CLK_TCK, and CPU/IO PSI text. They are archived
with the existing cgroup/memory samples. Missing/empty reads are explicit errors
with `status=partial`, never invented zeros. Check measurement telemetry quality
separately from the product and provider cleanup outcomes.

The [kernel proc documentation](https://docs.kernel.org/filesystems/proc.html)
notes that iowait is not a reliable universal utilization measure and may
decrease. Raw counters are preserved without guessed percentages. The
[PSI interface](https://docs.kernel.org/accounting/psi.html) supplies trend
averages and cumulative stall time; before/after data supports diagnosis but
does not on its own identify a physical host or prove noisy-neighbor causation.

### Cloud gate

`vm-gate cloud-gate --machine M --cloud-repo P --cloud-sha C --receipt R` runs
Cloud's full train gate, `make gate GATE_STAGES=all` (every stage, journeys
included, without the release-candidate checks), through the release job's own
path. Shared with a release:
- the Hermes key (operator `hermes_key_file`, 0600, removed before collect);
- the guest-measured budget split (Cloud has the whole guest);
- the cpu.stat sampler and evidence collection, including Cloud's
  `/tmp/ac-candidate-gate-*` run directory;
- the receipt and the ledger lease.

Differences from a release:
- C is a train head: admission requires real main in its history, and the
  bundle carries real main as main plus C, checked out detached.
- It builds no image and runs no aweb suite. The guest runs the launcher's own
  aweb commit.
- A stage run writes no Cloud ledger record, so the receipt is the evidence.
  It records each Cloud stage's verdict from Cloud's own summary, and it is
  green only when every stage there shows PASSED. Preflight writes no row (a failed
  preflight leaves no stage rows), and a missing row is red.

### Merak

Select the dedicated KVM host with `--target merak`. The Mac operator config
supplies `merak.host` (an SSH alias with a trusted host key),
`merak.base_sha256`, and `merak.launcher_image_id` (the immutable local Docker
image ID including `sha256:`). Set `merak.manifest` to the absolute path of
the approved Merak toolchain manifest and `merak.package_delta` to its recorded
OS package comparison. Each Merak receipt carries both file digests, the
observed Python binary hash and the package comparison itself. Build the launcher from `scripts/vm-gate/merak`
with a digest-pinned Debian base supplied as the `BASE` build argument.

The guest's size is measured, not configured. When it admits a run, the host
script reads its own CPU count and memory: the guest gets every CPU, and the
host keeps an eighth of its memory (at least 2 GiB) plus QEMU's own 4 GiB. The
admission record carries the guest size. Inside the guest each gate measures
its own Docker engine (`vm_gate/budget.py`), so nothing names a machine or
assumes a size. A release divides the measured capacity between its Cloud and
aweb gates, and the receipt records the measurement and the split.

Place the verified disk at `~/.local/share/aweb-gates/base/<sha256>.raw` with
mode 0444. Merak holds one slot from admission through cleanup. Each invocation
boots a new writable overlay and NoCloud seed under
`~/.local/share/aweb-gates/runs/<run-id>`. The controller reaches the guest SSH listener through the launcher container’s
loopback interface using the pinned host connection. The controller checks both SSH pins and runs the shared Linux
executor, host manifest checks and ledger import. The guest has its own Docker
daemon. Its writable disk contains its containers, volumes, networks and source
checkout. Closure records the removed launcher ID and disk directory, and is
read back on a fresh SSH connection.

Set `default_target` to `merak` to queue gates and qualifications on the
dedicated host. An explicit `--target hetzner`, `--type ccx33` or `--type ccx43` selects Hetzner.
The default for configurations without this setting is Hetzner.

The Merak closure includes sampled physical host memory use, minimum host
filesystem free space, peak allocated overlay bytes and the launcher's cgroup
memory peak when readable. Use those figures with the native stage times and
total elapsed time to assess capacity.

A Merak host administrator installs the reviewed helper with
`make merak-egress-install` from the repository root (`MERAK=<ssh host>`
selects the host). It copies `merak_egress.py` to the host, runs
`sudo ./merak_egress.py install` there and checks that the installed digest
equals the file's. Any change to `merak_egress.py`, formatting included,
needs this reinstall before the next Merak run. The installer
checks the nftables policy in a fresh network namespace and validates the
restricted sudo grant. The controller verifies the installed helper digest at
admission. Each run creates its own IPv4 bridge and nftables table before
booting its launcher. The table filters both original and translated destinations,
restricts forwarding to the physical public uplink and pins DNS to 1.1.1.1
and 9.9.9.9. Closure removes the launcher, bridge and table in that order.
