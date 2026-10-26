# Test egress boundaries

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

Use a fresh evidence path for each qualification run; existing control directories
are refused so a new result cannot overwrite an earlier receipt.
