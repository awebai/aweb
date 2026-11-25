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

## Sizing from the gate budget

Runners are sized from the gate's budget, `GATE_CPUS` and `GATE_MEMORY_MIB`
(`scripts/gate_budget.py`). A value that is not given comes from the Docker
engine the suites run on. No profile or machine-type table exists. Each
runner's CPU cap is the budget's CPU count; caps are quotas, not reserved
cores, so concurrent runners share the machine. A runner's memory is 8 GiB
plus 1 GiB per parallel server worker. The isolation contract is the internal
network, independent DNS refusal, UID1000, no Docker socket/host credentials,
and bounded resources, rather than any particular size.

The budget sets the server's worker count: one fewer than the CPU budget,
while the worker plan's PostgreSQL and Redis memory limits fit half the memory
budget. A plan of one worker is serial. `scripts/test_gate_budget.py` checks
these bounds over a range of machines.

## Concurrent unit suites

The unit stage runs `_candidate-unit-suites`, which runs `docker.py --suites`
with every suite `candidate-suite.sh --list-unit-suites` names. Each Naapp
package is its own suite. All suites run at once, each in its own runner from
one prepared image, on one internal network with one DNS sink. Each runner has
its own PostgreSQL and Redis in its own network namespace, so the services a
suite reaches on 127.0.0.1 are its own. Each suite keeps its own log
(`test-egress/<suite>/suite.log`) and summary row. A failed suite fails the
stage, and nothing is retried.

`test-server` gets one PostgreSQL and Redis pair per worker. When the budget
allows parallel workers, the Secrets package (`test-naapp-secrets`) runs its
measured two-shard partition on two owned pairs in its runner.

A direct `make test-server` stays serial unless its worker plan is provided.
A server-only measurement at a chosen size:

```sh
GATE_CPUS=12 python3 scripts/test-egress/docker.py --server-workers 11 \
  --evidence /var/log/vm-gate/server-parallel \
  --command make TEST_EGRESS_RUNNER= test-server
```

This selects the same Make target with `-n <workers> --dist loadscope
--max-worker-restart=0`, without filters, skips, retries or changed assertions.
Worker restarts are disabled so a crashed worker cannot silently replace its
test execution.

Each worker gets its own PostgreSQL and Redis server in the runner's internal
network namespace. PG listens on 5432 upward, one port per worker; Redis on
6379 upward. There are no
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

Worker 0 keeps the primary pair's limits: PostgreSQL 2 GiB/1 CPU/PID512 and
Redis 1 GiB/1 CPU/PID512. Every further pair uses PostgreSQL 1280 MiB/1 CPU/
PID512 and Redis 128 MiB/0.25 CPU/PID128 (`server/tests/worker_services.py`).
Each PG keeps its existing 1-GiB tmpfs and bounded WAL. IDs are recorded as
created and removed through the existing reverse-order finalizer;
worker/storage mappings are retained in the suite's `worker-services.json`.

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

## Prepared package image

`package_image.py` owns the isolated runner's source/dependency image build.
Package preparation uses the selected checkout's tool Dockerfile and test-egress
recipe, then synchronizes each locked project with `uv sync --frozen`. Each installed Playwright version installs its
own Chromium headless shell and system dependencies. Browser revision numbers
and wheel versions are never copied from a prior run.

The image's UID1000 admission check creates a fresh temporary environment for
each selected project and runs a frozen offline sync. It also launches Chromium
through each project's own Playwright. Missing wheels/build backends or a missing
browser refuse preparation with a project-qualified setup error. The generated
recipe, preparation-tool hash, source SHA and source file hashes remain in the
evidence directory. Tests begin only after this admission succeeds.

This preparation is a runner precondition and does not modify the gated tree.
