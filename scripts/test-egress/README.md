# Test egress boundaries

`make test-cli`, `test-server`, and `test-awid` prepare dependencies, then run
behind the native deny proxy. Loopback stays direct. The exact existing
`127.0.0.1.nip.io` and `signer.example.com` fixtures are forwarded to 127.0.0.1
without DNS. The governance browser fixture explicitly selects this proxy for
both Chromium and Playwright driver requests. Its RP alias stays behind the
proxy; it is not a `NO_PROXY` or wildcard-domain exception. Reserved test
suffixes bypass the native proxy to retain normal DNS failure semantics. Other requests fail the wrapper even when
the caller ignores the error. The per-run refused-host report remains visible.

`make test-cli` sets `TMPDIR` to the canonical form of `/tmp` (`/private/tmp`
on macOS), keeping custody paths free of symlink parents and Unix sockets short.

Server preparation builds the distribution once before entering the guard, warming
uv's build-backend cache as well as its runtime dependencies. The guarded server
suite exports `UV_OFFLINE=1`, which also reaches the package-data test's `uv build`
child; `uv run --offline` alone does not prevent that child from revalidating PyPI.
The isolated image likewise prebuilds the server before disabling network access.
Its tools and suite setup are composed into one Docker build, so the host Docker
builder and the candidate gate's bounded docker-container builder use the same
path without needing access to a daemon-local intermediate image. The generated
Dockerfile is retained with the run's evidence.

This proxy is a **soft** guard: a client disabling proxy support bypasses it.
`make test-isolated` is the hard Go/Python/Node suite gate: dependencies are built
into an image before execution; the runner has only an internal Docker network,
no Docker socket, and a DNS sink with no upstream. Exact hosts entries map the
same two fixture names to loopback for driver requests when the native proxy
is disabled. It disables the native
proxy and the host's DNS search domains, keeping reserved fixture lookups from
expanding into queries for the host's network. Refused DNS retains normal connection-error semantics. PostgreSQL and Redis share
the runner's network namespace, so fixtures remain loopback. A denied DNS query
fails the run independently of the test process status. Logs and network inspect
receipts remain in `TEST_EGRESS_EVIDENCE` (a new directory per run).
The isolated unit runner streams timestamped `postgres-<port>.log` evidence
from each test database before suites start. Postgres logs lock waits and
statements that take at least 1,000 ms. PostgreSQL's bind-parameter logging is
disabled for both statement and error logs. SQL text and error messages can
still contain values, so use bind parameters for secrets and keep secrets out
of SQL text and application error messages. `host-load.jsonl` records the runner
host's 1-, 5- and 15-minute load averages every five seconds with Unix timestamps.
The shared naapp pytest fixture records each test's UTC start in `suite.log`.
It reports garbage collections longer than 0.5 s and dumps the main thread's
stack when the running asyncio loop misses its heartbeat for 2 s. These
observations leave pytest's capture, verdicts and timeouts in place.

`denied-reads.json` is empty: no production destination is exempt from failing
receipts. The init default-selection test checks selection without network I/O;
API-mount discovery is tested against local servers. New exceptions require
architecture review.

The real AWID init fixture registers the DID before publishing. It uses the
suite's PG/Redis when supplied, otherwise disposable local Docker services, and
runs the repository AWID service. No identity, registry-selection or release
code carries any of these mechanisms.

The Docker resolver qualification reproduces a CI host's inherited search domain
using the real Docker CLI, DNS sink and child `getaddrinfo`. Run it under the host
test policy with an existing Python image; no dependency image build is needed.
The DNS sidecar reads the repository DNS sink from a read-only bind mount:

```sh
python3 scripts/test-egress/test_docker_dns.py --image python:3.12-slim --evidence /tmp/dns-proof
```

A reserved-name lookup must leave the guard green even when the host supplies a
search domain; a public-name lookup must still fail the guard while the child
handles the DNS refusal successfully. Each control retains resolver configuration,
DNS logs, runner inspection and the child exit in its evidence directory. Neither
control needs an external DNS service or a route out of the internal network.

## CCX33 measurement

The portable runner retains its finite 2-CPU/8-GiB budget. It was introduced
with the isolated CI runner (79c78411d1); the isolation contract is the internal
network, independent DNS refusal, UID1000, no Docker socket/host credentials,
and bounded resources, rather than the particular two-CPU value.

`--profile ccx33` explicitly selects a 7-CPU/16-GiB runner for a disposable
8-vCPU/32-GB CCX33 server-suite measurement. PID2048, service limits, non-root
execution, network isolation and cleanup are unchanged. Seven is a CPU quota,
not an exclusive core reservation; PostgreSQL/Redis and the host still share
the VM. The 16-GiB cap allows more runner concurrency while leaving space for
services and build preparation in this server-only experiment. Full candidate
VMs keep their existing profile until the measurement is reviewed.

After operator review, use ONE pinned-main server measurement, not a unit-stage
ledger entry for a partial suite:

```sh
python3 scripts/test-egress/docker.py --profile ccx33 \
  --evidence /var/log/vm-gate/server-measurement \
  --command make TEST_EGRESS_RUNNER= test-server
```

Retain the actual `runner.json` resource readback, source identity, complete
pytest count/time, DNS report, primary exit and cleanup separately. Compare the
server's pytest interval with 3064.42s and 3980.80s, while reporting source and
host differences; the enclosing image-build/command time is a separate cost.
No automatic repetition or default quota change follows from one result.

## Parallel server unit stage

The normal unit path is `_candidate-unit-suites` ->
`candidate-suite.sh --isolated-suites` -> `make test-server`. The VM recipe
passes its selected type as `AWEB_GATE_UNIT_PROFILE`. On CCX33 this stage now
selects the measured seven-worker/profile-ccx33 path. Other callers retain the
portable serial unit path; `CANDIDATE_UNIT_PROFILE=portable` explicitly selects
it on a smaller host. Direct `make test-server` is still serial unless its
worker plan is explicitly provided.

The equivalent server-only measurement command is:

```sh
python3 scripts/test-egress/docker.py --profile ccx33 --server-workers 7 \
  --evidence /var/log/vm-gate/acgc-server-parallel \
  --command make TEST_EGRESS_RUNNER= test-server
```

This selects the same Make target with `-n 7 --dist loadscope
--max-worker-restart=0`, without filters, skips, retries or changed assertions.
The portable/default profile and serial command remain unchanged. Worker
restarts are disabled so a crashed worker cannot silently replace its test
execution.

Each worker gets its own PostgreSQL and Redis server in the runner's internal
network namespace. PG listens on 5432..5438; Redis on 6379..6385. There are no
host publications or Docker socket mounts. `server/tests/conftest.py` selects
these endpoints before importing pgdbm, plugins or test modules, using xdist's
worker identity and count; a missing/wrong plan refuses rather than sharing a
service. Worker 0 keeps the parent ports for later serial suites.

PostgreSQL's existing per-test database creation/drop is retained. The locked
pgdbm 0.5.0 factory already uses a UUID plus suffix for each database
(`testing.py:197-199`), with a pool capped at five connections and an admin
pool capped at two. Separate per-worker servers also isolate cluster-wide
state and connection budgets; no migrations or product pools change. Every PG
retains the tmpfs data/WAL and zero-swap checks, role-default search_path
control and pgcrypto setup.

A Redis database number alone is insufficient: [pub/sub is independent of the
selected database](https://redis.io/docs/latest/develop/pubsub/#database--scoping).
The suite has fixed named pub/sub channels as well as key caches. Separate
Redis servers isolate both; the real TCP fault proxy follows each worker URL.

Worker 0 keeps the original serial services' 2-GiB/1-CPU PostgreSQL and
1-GiB/1-CPU/PID512 Redis limits for AWID/naapp/CLI after the server workers
exit. The other six pairs use PostgreSQL 1280 MiB/1 CPU/PID512 and Redis
128 MiB/0.25 CPU/PID128. The runner is 16 GiB/7 CPU/PID2048 and DNS 128 MiB.
Their memory caps total 27.375 GiB, leaving 4.625 GiB of a nominal 32-GiB host
before kernel reservation, for the host and preparation. Quotas are caps, not
reserved cores. The reviewed seven-worker measurement at `0d556192b9` had
4763 passes and one expected failure in 640.96s versus 2798.88s serial.
The primary-service caps are retained for the later serial targets; the next
complete unit run qualifies this default wiring. Each PG keeps its existing
1-GiB tmpfs and bounded WAL. IDs are recorded as created and removed through
the existing reverse-order finalizer; worker/storage mappings are retained in
`worker-services.json`.

Four parametrizations with random UUID/time values now supply stable case IDs;
inputs and assertions stay unchanged. Fresh-process collection controls cover
all 24 affected cases. xdist 3.8.0 sets its worker environment before loading
conftest ([locked bootstrap source](https://github.com/pytest-dev/pytest-xdist/blob/v3.8.0/src/xdist/remote.py#L384-L388)), matching the early endpoint binding.

Temporary paths and the session CLI build use pytest's worker-specific
`tmp_path_factory`; each worker builds the same checkout CLI independently.
Live HTTP/DNS/fault-proxy listeners use kernel-assigned ports.

The activity emitter, trust-presentation and connection-restart modules share a
session fixture for each worker's Node runtime tree. It copies the three
packages and their already installed dependencies into a private run/worker
path, preserving dependency `dist` files and rebinding workspace symlinks to
that worker's core. Both plugin builds finish before the first reader starts;
subsequent module fixtures never rebuild that tree. Activity's host is copied
so its relative core imports stay private; channel, Pi and core readers use the
same worker root, including the restart module's imported fixture. Teardown
removes only that worker's tree. The serial fixture/build path stays unchanged.
There is no writer-only lock: workers cannot remove another reader's artifacts.

`scripts/test_server_runtime_trees.py` concurrently prepares two trees and
holds a real unlink/rebuild gap in one while the kept Node host scripts read the
other. It also removes the original shared core, which refuses with
`ERR_MODULE_NOT_FOUND`, while private readers succeed before the writer resumes.
Controlled npm outputs isolate the filesystem/import boundary; these controls
do not execute product builds or replace native runtime assertions.

Native qualification still needs all collected tests, the normal xfail policy,
actual seven-worker/service readbacks, CPU/PSI and memory/OOM evidence, and
separate source/Docker/provider cleanup. No parallel measurement result is
inferred from the source and local controls.

The first seven-worker measurement at `827931cda7` collected the same 4764
server cases as the serial baseline, but six teamctl capture assertions failed
at the follower identity check. The local Linux control reproduces a live
follower being refused: procps clips `ps -o command` under narrow `COLUMNS`;
xdist workers in the locked local control exported `COLUMNS=80`. The capture now
binds the PID it spawns and its start time before any witness/probe, rechecks that
identity before the agent starts, and keeps a full-width command only as receipt
diagnostics. Every capture cleanup rechecks that start time at the signal boundary; missing
or different identity never authorizes killing a reused PID.
`scripts/test_team_follower_identity.py` exercises the real capture helpers with
long paths/narrow columns, plus exited-child, wrong-start and wrong-container
negatives. Fixed Docker/interpreter transports make it a process-identity
control, not a whole deployment or parallel-suite qualification.

## Prepared package callers on an ephemeral VM

`package_image.py` owns the source/dependency image build for both the isolated
runner and `package_environment.py`. Package preparation uses the selected
checkout's tool Dockerfile and test-egress recipe, then synchronizes each selected
project with `uv sync --frozen`. Each installed Playwright version installs its
own Chromium headless shell and system dependencies. Browser revision numbers
and wheel versions are never copied from a prior run.

The image's UID1000 admission check creates a fresh temporary environment for
each selected project and runs a frozen offline sync. It also launches Chromium
through each project's own Playwright. Missing wheels/build backends or a missing
browser refuse preparation with a project-qualified setup error. The generated
recipe, preparation-tool hash, immutable image ID, exact source and lock hashes
remain in the binding. Tests begin only after this admission succeeds.

The package entry is for callers that own Compose services: it uses the
single-tenant VM's loopback and Docker socket, UID1000, bounded resources and a
private image HOME, with no host identity or credential-directory mount. The
ordinary isolated runner retains its internal network and has no Docker socket.
The socket-bearing package command may run only on a dedicated ephemeral VM
holding no credential, no ledger that survives the run, and no other run's
evidence. Image preparation alone may also prepare development leases; those
leases must not use this socket-bearing package command. Source/lock read-back
does not attest that code with the VM's Docker socket left evidence untouched.
Package commands retain their actual exit, JUnit when selected, and source/lock
read-back before container removal. A batch owns its preparation binding and
removes that binding's unique image tag at the end, including failed phases.
This preparation is a runner precondition and does not modify the gated tree.
