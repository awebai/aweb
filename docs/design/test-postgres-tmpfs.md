# Proposal: memory-backed PostgreSQL for disposable test stacks

Status: implementation authorized by coordinator a0d0120b; acic.4 remains held. Production and development
storage are outside this change.

## Evidence and unresolved cause

The native Antares PostgreSQL 17.11 probe captured 270 samples of one certificate
fixture INSERT waiting in IO/DataFileExtend, with no lock blockers, from
2026-10-21T03:39:09.357978Z to 03:39:15.308110Z. Its PostgreSQL log records
5966.353 ms completion at 03:39:15.311Z. The independent train-3 Docker runner
reported a POST /v1/messages client timeout in the overlapping interval.
The Docker PostgreSQL container was removed without retaining its log. There is
no measured Docker PostgreSQL wait and no retained host/VM clock-offset check.
The coincidence supports investigating host storage; it does not establish the
Docker handler's wait or a specific APFS/backup cause.

The original native DID INSERT was canceled at 02:53:41.100Z. That run did not
collect wait state or statement duration. Its WAL segment has been recycled.
Gandalf's bounded host retrospective found no event-time storage/suspension
trace; no other seat's event-time writer is established. The coordinator's own
covering and RC runs ended by 02:43:48Z. Item 1 (a common cause for the original
failure) is open. The host investigation belongs to Gandalf.

## Storage and memory rule

Every newly launched test PostgreSQL uses an explicit, bounded tmpfs mount at
/var/lib/postgresql/data for the currently pinned PostgreSQL 16/17 images.
PGDATA, pg_wal and temporary tablespaces stay beneath that mount. Keep fsync,
full_page_writes and synchronous_commit enabled, and keep existing client and
statement timeouts. No disk-backed fallback. A mount/configuration failure,
ENOSPC or OOM fails the run and retains the diagnostic evidence.

Tmpfs is charged to the container memory limit and can swap. Therefore set
memory-swap equal to memory (Compose memswap_limit equal to mem_limit), verify
memory.swap.max is zero, and assert mount type plus effective PGDATA and resolved
WAL path. Missing swap accounting is a hard failure, including CI; there is no
CI exception. The focused wrapper generates its password, publishes a random
loopback port and cleans up only its captured container ID. These
container controls do not prevent macOS from paging the Docker VM itself; the
host still needs memory headroom. Pytest capture, source builds and artifact
logs also retain their own disk-latency exposure; moving PostgreSQL alone is not
a claim that every test operation becomes independent of the host disk. See [Docker tmpfs documentation](https://docs.docker.com/engine/storage/tmpfs/)
and [memory/swap controls](https://docs.docker.com/engine/containers/resource_constraints/#--memory-swap-details).

Initial budgets, to be validated by peak usage in the covering train:

| Instance | PGDATA tmpfs ceiling | Total container RAM / RAM+swap |
| --- | --- | --- |
| Candidate gate shared PostgreSQL | 4 GiB | 6 GiB / 6 GiB |
| Isolated test-egress runner PostgreSQL | 4 GiB | 6 GiB / 6 GiB |
| Each GitHub Actions test service | 1 GiB | 2 GiB / 2 GiB |
| Standalone CLI AWID fixture | 1 GiB | 2 GiB / 2 GiB |
| Each federation, pooler or app e2e PostgreSQL | 1 GiB | 2 GiB / 2 GiB |
| Disposable focused server/naapp PostgreSQL | 2 GiB | 4 GiB / 4 GiB |

Ceilings are limits, not upfront reservations. The disk-backed native probe's
cluster occupied 319 MiB after 50 rounds. That supports the focused starting
budget, not a claim that a whole gate fits. One candidate plus one isolated
runner plus a three-PG federation stack would cap PostgreSQL containers at
18 GiB; focused proof adds 4 GiB. Account separately for runners, builders,
Redis and application services within the 96 GiB Docker VM. Record actual peak
memory and PGDATA usage before accepting the defaults.

## Exact change surface

- scripts/candidate-docker-gate.sh: replace its PostgreSQL named data volume
  with tmpfs, separate PG memory from generic service limits, update resource
  evidence and owned-volume cleanup. Keep Redis storage unchanged.
- scripts/test-egress/docker.py: give the PostgreSQL service tmpfs and its own
  memory/swap budget (currently grouped with Redis at 1 GiB). Retain PG logs,
  mount and memory evidence before cleanup, including failed runs.
- scripts/test-egress/awid_fixture.py: apply the standalone budget only when
  this fixture owns PostgreSQL; existing PGHOST means reuse the caller's test
  service. Keep its stdout protocol unchanged.
- scripts/e2e-federation-authority.sh (two PGs),
  scripts/e2e-cross-registry-messaging.sh (two), and
  scripts/e2e-oss-federation.sh (three): update the generated Compose services,
  remove only their obsolete PostgreSQL data-volume declarations, and retain
  their existing isolated project cleanup.
- awid/tests/pooler/docker-compose.yml: add the same bounded test mount.
- docker-compose.e2e.yml, scripts/e2e/folio-wakes.compose.yml,
  naapp/folio/docker-compose.e2e.yml and
  naapp/library/docker-compose.e2e.yml already use tmpfs. Add explicit size,
  memory and swap limits. scripts/e2e/grant-app-acceptance.compose.yml currently
  overrides PostgreSQL RAM to 1 GiB: raise it to the e2e budget so it cannot
  undo the parent setting. docker-compose.e2e.cache.yml has no PG override.
- .github/workflows/{test,server-ci,logs-ci,secrets-ci,folio-ci,library-ci}.yml:
  apply the same tmpfs/memory/swap options to their test service containers.
- Add scripts/test-postgres.sh for disposable native-host focused work: launch
  an owned loopback-only Docker PostgreSQL on tmpfs, export both PG* and
  TEST_DB_* connection variables to its child, and remove only that owned
  container on exit. The server and naapp fixture layers consume the supplied
  PG service; they do not launch native initdb themselves. Replace the aciq
  scratch initdb launcher with this path. External explicitly supplied test
  services must report their effective storage type; the test train owns its
  launcher and cannot silently fall back to an operator's disk-backed server.

Do not change awid/docker-compose.yml or server/docker-compose.yml: these are
persistent operator/development services, not disposable test stacks.

## Focused proof and acceptance

Run the original two naapp files against a disposable tmpfs PostgreSQL, plus
the addressless-sender HTTP/CLI regression that failed in train-3. At the same
time run a bounded host-disk writer (64 MiB/s ceiling, 240 seconds, one file
reused up to 2 GiB, fsync after each MiB, removed afterward). Keep the original
5-second SDK/client deadlines. Capture PG activity at 20 ms in RAM, flushing
after the run, so logging cannot itself block the observer on the tested disk.

Configuration acceptance under this bounded load: all selected tests pass; zero observed DataFileExtend waits longer
than 1 second; observer sampling gaps/errors are reported rather than treated
as absence; the mount and no-swap controls are verified; no OOM or ENOSPC; and
retained peak storage/memory fit the proposed budget. A passing bounded probe
proves that workload and configuration, not immunity to every host stall.

Proof completed on 2026-10-21, using the ACKed acic.4 source cd4f8095:

- Six runs of the original two naapp files: 342 passed. The addressless-sender
  file: 4 passed. No retries, skips, or timeout changes.
- The writer completed 16,106,127,360 bytes in 240.082 seconds, reusing its
  bounded 2 GiB file and removing it afterward.
- 10,874 activity observations, zero observer errors, median spacing 22.3 ms,
  maximum gap 214.9 ms. There were 31 DataFileExtend observations; the greatest
  statement age at those observations was 6.828 ms. Zero exceeded 1 second.
- The same detector reports 224 observations above 1 second on the retained
  disk-backed round-3 trace (maximum 5.962364 seconds). It was shown to detect
  the observed stall; removing tmpfs has not been shown to reproduce that
  stall under this synthetic writer, so this is not a proven causal A/B fix.
- The mount is tmpfs, memory.swap.max is zero, and fsync/full_page_writes/
  synchronous_commit remain on. The recorded post-test memory peak was
  135,348,224 bytes; final PGDATA occupied 55,932 KiB. No OOM events were
  reported at the post-test check. Both owned containers were removed.

Retained evidence is in this instance's tmp/aciq-tmpfs.HFbr8L: wait-summary.json,
persistent-pg-monitor.jsonl, mount-proof.txt, memory-storage-proof.txt,
pg-settings.txt, writer.log, PostgreSQL log/inspect and per-run test logs.
The disk-backed counterpart is tmp/acic4-stack.HJ7OGU/round-3.

The implementation changes only disposable test launchers. The
coordinator's single covering train, after independent review, must exercise
the actual changed launchers. Passing this bounded proof does not resolve the
original untraced failure or lift the acic.4 hold.

## Paired control follow-up

The subsequent acic.4 disk-backed control used the same six naapp runs,
addressless-sender file, container CPU/RAM and bounded 64 MiB/s writer as the
tmpfs proof. It also reported zero DataFileExtend samples on statements older
than 1 second (maximum 23.695 ms; 11,001 observations; no observer errors;
maximum gap 38.8 ms). Thus this writer did not reproduce the live-train stall
on disk-backed PostgreSQL. The tmpfs run demonstrates a working configuration
under this load, not a demonstrated causal mitigation in a paired experiment.
The original disk trace's 224 over-limit observations came from the live train
window, not this synthetic writer. An attempted main synthetic control passed twelve common-file runs but then
failed an extra server collection step because the partial archive omitted its
collection helper; cleanup stopped the writer early. It is excluded as a
completed paired experiment.

The coordinator requested a new real-train comparison, without a synthetic
writer: disk-backed acic.4, tmpfs acic.4 and disk-backed main run the same
byte-identical 49-test envelope file side by side through the train window.
Main has no acic.4 lifetime test file, so that file is excluded from all three
sides of this comparison. Source-path receipts bind each import to its expected
export or worktree. The completed results follow below; landing still requires the coordinator's disposition and covering train.

## Shared checker and hosted-runner proof

Compose stacks bind-mount scripts/test-postgres-storage.sh read-only; their
health checks execute that file. The gate copies it to its existing shared
bind directory and overrides the child mount to that host-visible path. Its
generic Compose wrapper preserves each PostgreSQL memory budget and matches
its swap limit, rather than replacing it with the generic sibling limit.
The checker waits for TCP readiness so the initdb-only socket server cannot
make a stack healthy early. Retained inspect output redacts POSTGRES_PASSWORD
and PGPASSWORD; the generated password file is removed at exit.

Real controls verify the gate wrapper keeps 2 GiB memory/swap and mounts the
shared checker read-only; a deliberately wrong checker refuses health before
the correct one succeeds. The normal PG16 Compose stack is also healthy.

The GitHub-hosted test.yml dispatch at 4895ea1a completed Initialize containers
successfully at 2026-10-21T04:29:27Z, then checkout/setup. All six workflows use
identical PostgreSQL options. Run 39544262826/job 119038756394 was cancelled
after this requested service proof; it is not a whole-suite green gate. The
reviewer independently verified the successful service step. Its condition
on hosted quoting/swap accounting is met.

## Completed real-train comparison

All three probes ran the same 49-test file with PostgreSQL 17, one CPU and
4 GiB memory with no swap. Only storage and the explicitly pinned main versus
acic.4 source differed. No synthetic writer ran. Source bindings were verified.
The shared observation interval was 2026-10-21T04:18:29.194786Z through
05:18:27Z (3597.805 seconds), excluding final-batch and trace-flush tails.

| Case | Completed tests | DataFileExtend samples on statements older than 1 s | Observed consecutive DataFileExtend spans over 1 s | Other I/O and checkpoint spans over 1 s |
| --- | ---: | ---: | ---: | ---: |
| acic.4, disk | 8,673 | 96 | 1 (2.996 s) | 95 |
| acic.4, tmpfs | 19,012 | 0 | 0 | 0 |
| main f064438b, disk | 9,604 | 0 | 0 | 99 |

Every batch passed all 49 tests, with no skips, retries or changed deadlines.
A span means consecutive observations of the same query and wait; a sampling
gap of 100 ms or more breaks a span. Samples are observations, not distinct
file-extension operations.

The literal DataFileExtend trigger repeated only on acic.4. That single episode
was CREATE TABLE team_custodians in 009_principal_attestation_records.sql,
whose bytes are unchanged from main. It was not the modified certificate table.
There were no lock blockers. The maximum statement age at DataFileExtend was
3.004569 s on acic.4 disk, 0.371325 s on main disk and 0.011181 s on tmpfs.

Both disk-backed cases had many other long waits: acic.4 reached 5.926 s in
WalSync and 6.663 s in CheckpointDone; main reached 5.973 s and 7.557 s.
Including the one DataFileExtend span, disk I/O/checkpoint counts were 96 and
99 (54.2 and 50.5 per 100 completed batches). Main additionally had two
long WALWrite lock spans, excluded from that comparison. Tmpfs had no observed
wait span over one second, despite completing more batches.

These results reproduce disk-dependent stalls on main as well as acic.4 and
show that tmpfs avoids those stalls under the concurrent train. They do not
reproduce the exact DataFileExtend trigger on main, identify the host storage
component, or establish the cause of the unsampled 02:53 cancellation. The
coordinator must assess that distinction before landing; the covering train
is still required.

There were 506,507 observations and zero observer errors. Maximum sampling
gaps were 124.1 ms (acic.4 disk), 126.4 ms (tmpfs), and 113.8 ms (main disk).
Observed host-minus-PostgreSQL timestamp offsets were positive and at most
97.4 ms; this applies to this experiment, not the historical 03:39 evidence.
The analyzer detects the retained native positive control: 224 over-limit
observations and a 5.950 s DataFileExtend span.

Retained summaries: tmp/aciq-real-comparison-summary.jsonl and the three
aciq-real-* directories in the instance home. All six owned PG/Redis services
were removed, inspect passwords redacted, and the main export deleted.
