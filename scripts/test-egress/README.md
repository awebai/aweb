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

This proxy is a **soft** guard: a client disabling proxy support bypasses it.
`make test-isolated` is the hard Go/Python/Node suite gate: dependencies are built
into an image before execution; the runner has only an internal Docker network,
no Docker socket, and a DNS sink with no upstream. It disables the native
proxy so refused DNS retains normal connection-error semantics. PostgreSQL and Redis share
the runner's network namespace, so fixtures remain loopback. A denied DNS query
fails the run independently of the test process status. Logs and network inspect
receipts remain in `TEST_EGRESS_EVIDENCE` (a new directory per run).

`denied-reads.json` is the reviewed one-entry exception, owned by
`TestResolveBaseURLForInitFallsBackToDefault`. All requests remain refused.
HTTP non-GETs fail. HTTPS CONNECT exposes no inner method: another test's HTTPS
write to this host would be visible but would not fail natively. Refusal is what
guarantees no production access. New entries require architecture review.

The real AWID init fixture registers the DID before publishing. It uses the
suite's PG/Redis when supplied, otherwise disposable local Docker services, and
runs the repository AWID service. No identity, registry-selection or release
code carries any of these mechanisms.
