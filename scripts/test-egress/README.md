# Test egress boundaries

The CI matrix and candidate unit stage use the same `make test-unit-*` groups:
`server-1`, `server-2`, `awid`, `naapp`, `cli`, and `channel-pi`. The CLI group
includes request-auth-v2; the Node group retains channel, live-name contract,
channel-core and Pi tests in order. Naapp runs each existing package target in
parallel, retaining its own log and lock check. Server shards retain the full
collection, partitioned by the SHA256 of each relative module path. Each worker
has a private TCP Redis process; shared Node build users stay in one loadgroup.

`make test-isolated` prepares one image, then runs the groups in separate
filesystems and internal networks. The candidate gate uses the same scheduler.
`candidate-gate/unit-settings.json` defines shard/worker counts, the release and
lane allocations, and report-only stage budgets. `AWEB_GATE_PROFILE=release`
selects concurrent groups; the lane profile runs them sequentially within its
smaller total allocation. The settings validator includes the outer runner,
builder and services in the aggregate. The unit stage records effective Docker
limits and restores the previous outer limits even after a group fails.

Each group retains `suite.log`, network/runner inspection, resource limits and
runner wall time. The parent `summary.tsv` includes group setup and cleanup;
the stage summary adds a budget next to duration. A stage overrun prints
`BUDGET EXCEEDED` in the wrapper verdict but does not yet change the test result.

Each isolated group sets `AWEB_UNIT_REPORT_DIR` to a fresh runner-local directory
and copies it to `<group>/reports` before container removal, even after test
failure. pytest reports contain setup + call + teardown time (`junit_duration_report=total`):
`server.xml`, `awid.xml`, `cli-auth.xml`, and one named XML per Naapp package
(`naapp-lib.xml`, `naapp-folio.xml`, `naapp-library.xml`, `naapp-secrets.xml`,
`naapp-logs.xml`). Server groups have separate directories. Vitest retains its
default console output alongside `channel.xml` and `channel-core.xml`.
`cli-go.jsonl` retains native Go test events with case outcomes and elapsed time;
`pi-extension.tap` retains Node's native case durations. No test selection,
ordering, timeout or retry is changed. Lightweight auxiliary Python controls
remain in `suite.log`. If a command stops before a framework emits a report,
that report is absent: absence is not zero tests or a pass. `report-copy.status`
and `report-copy.log` distinguish a copy failure from missing framework output.
Evidence retention failure fails the suite driver even when the tests passed.
Use the test outcome and finalization diagnostics separately: a failed report
copy or container log/inspect capture is an evidence failure, not a test assertion
failure. When startup already raised, that original exception remains primary.

Before cleanup, `containers/<role>.log` and `<role>.inspect.json` retain each
owned DNS/runner/PostgreSQL/Redis container, including failed starts. Containers
are created and registered before starting, so a start error cannot lose their
IDs. `<role>.capture.json` records read exit codes/errors; failed diagnostic reads
still permit all cleanup attempts and preserve the original startup exception.
Successful runs also retain these diagnostics. Inspect output stays with the
operator's full gate evidence, not public test reports.

Container-free orchestration and reporter controls run in `make test-shipping`.
With the locked Python/Node dependencies and Go installed, exercise real passing
and deliberately failing framework processes with:

```sh
python3 scripts/test_unit_reports.py --frameworks
```

These probes qualify report contents/status preservation, not Docker isolation
or the cause of a service failure on a VM.

Before handing off a gate change, run the touched packages' own contract tests
as well as the harness controls. Reporter probes alone do not qualify a package
Makefile: Folio requires its tools to run through its locked `uv` environment
without depending on a sibling checkout path. Run the following container-free
baseline at the exact handoff SHA, plus Ruff for touched Python files and
`go vet`/`go test` for any touched Go package:

```sh
make test-identity-primitives test-vector-provenance test-sot-source-inventories test-python-locks lint-naapp
```

The mandatory `make test-federation-authority-mutations` target currently invokes
PostgreSQL-backed activation fixtures, so it belongs in the authorized VM checks.
Retain its pass lines and each touched package's own test results with the
handoff. Tests requiring PostgreSQL or Docker need an authorized VM run; report
that coverage as pending until it executes. A merge or rebase requires a new
preflight at the resulting SHA.

`make test-cli`, `test-server`, and `test-awid` prepare dependencies, then run
behind the native deny proxy. Loopback stays direct. The exact existing
`127.0.0.1.nip.io` fixture is forwarded to 127.0.0.1 without DNS. Reserved test
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
no Docker socket, and a DNS sink with no upstream. It disables the native
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
The additional startup-failure control deliberately exits the DNS process before
it can serve queries, checks its retained stderr and exit state, and verifies
the container is absent after cleanup. The normal candidate checks stage runs
this control with its existing tools image and retains `dns-startup-control`
under the stage evidence root. The injected failing process needs no source
bind mount from the gate container onto the host daemon. Direct qualification
still requires the same Docker run slot.
