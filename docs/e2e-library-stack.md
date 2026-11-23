# Optional Library Integration Test Stack

Status: **optional cross-repository maintainer harness**. In this filename and
Make target, `e2e` means end-to-end integration testing; it does **not** mean the
encrypted-message E2E protocol. Library is unnecessary for basic communication,
identity/team membership, or encrypted-v2 interoperability.

The self-hosted integration stack the optional profile/team/Library flow runs against. It
brings up, from source, on one Docker network:

| Service  | Source            | In-network endpoint |
|----------|-------------------|---------------------|
| postgres | `postgres:16`     | `postgres:5432`     |
| redis    | `redis:7`         | `redis:6379`        |
| awid     | `awid/Dockerfile` | `http://<awid name>:8010` |
| aweb     | `server/Dockerfile` | `https://<aweb name>:8000` |
| library  | `naapp/library/Dockerfile` | `https://<library name>:8765` |

Each `<name>` is the stack's project-scoped name for that service
(`scripts/candidate-network.py hostname <project> <service>`), the same name the
candidate gate's network adds. Nothing is published to the host.

It then **seeds** the current `aweb.team` catalog blueprint into Library over
real AWID team-certificate auth, as a team that installed Library, so the
materializer is exercised against the real folded-block-scalar blueprint
content (the same flow Library's own e2e suite runs).

## Where the journeys run, and why

The seed and the CLI suite run **inside the stack's network**, never from the
host:

- the coordination server fetches an app's manifest only over HTTPS from a
  pinned destination, so Library serves TLS at its in-network name with a
  certificate from a disposable stack CA, and aweb runs
  `scripts/e2e/stack_server.py` pinned to that origin;
- teams publish the stack's server as their team server, and `aw` accepts only
  an HTTPS team server outside loopback, so aweb serves TLS from the same CA.
  Library reads a team's grant from it only through its egress guard, as its
  operator's own listed team server on the stack's network
  (`LIBRARY_TEAM_SERVER_INTERNAL_ORIGINS`, and the network's own subnet as
  `LIBRARY_HOOK_INTERNAL_CIDR`, from `scripts/e2e/stack-subnet.compose.yml`), and
  trusts that CA (`LIBRARY_HOOK_CA_FILE`);
- Library admits a member request only for a team that installed it and
  granted the operation's scopes, so every journey team publishes the stack's
  server as its team server, is made an install admin there, and runs the real
  `aw plugin install` before it calls a member route. No path reaches Library's
  member routes without an install.

Inside the candidate gate the runner is already attached to the network. Any
other run (a developer's machine, CI) starts a disposable runner container on
the stack network (`scripts/e2e/journey-runner.Dockerfile`), with the checkout
mounted read-only and the stack CA in its `SSL_CERT_FILE`. Nothing is added to
the host: no `/etc/hosts` entries, no trusted CA, no published port. The
commands are the same in both places.

Library runs as app id `library` here because `aw`'s Library commands look the
plugin up by that id. The runtime serves the hosted id only at the template's
origin, so the stack publishes Library's committed template from its own origin
(`scripts/e2e/library_stack_prepare.py`, with `scripts/e2e/stack_manifest.py`)
and gives Library an owner-only grant-read key.

This harness contains postgres + redis + AWID + OSS aweb + Library. Hosted
service infrastructure and hosted controller-key flows are not part of this
compose or prerequisites for using it.

## Versioned inputs

The harness builds Library from `naapp/library/Dockerfile` with the repository
root as its context (`context: .`), like awid and aweb, because Library depends
on the in-repo awid and naapp-lib. It seeds the committed
`naapp/library/test-vectors/blueprints/team` aweb.team fixture. The local
release gate therefore records one clean exact source SHA for the complete
journey.

`LIBRARY_E2E_BLUEPRINT_SRC` remains an explicit maintainer override for testing
another checked-out blueprint. A release gate requires it to remain inside a
clean Git checkout; it does not accept an archive or an unversioned working
directory.

## Run it

One command — build, start, wait healthy, seed, verify, tear down:

```bash
make e2e-library-stack
```

Step by step (leaves the stack running between steps):

```bash
make e2e-library-stack-up     # build + prepare + start, wait until healthy
make e2e-library-stack-seed   # publish the aweb.team blueprint into Library
make e2e-library-stack-down   # remove containers AND all state (-v)
```

Or drive the script directly, including any command you want to run inside
the network (relative to the checkout):

```bash
./scripts/e2e-library-stack.sh up
./scripts/e2e-library-stack.sh seed
./scripts/e2e-library-stack.sh journey python3 -c 'import os,urllib.request; print(urllib.request.urlopen(os.environ["LIBRARY_E2E_LIBRARY_URL"] + "/v1/blueprints").read())'
./scripts/e2e-library-stack.sh down
```

## Teardown leaves no state

Postgres data lives on tmpfs and the stack's only named volumes (the fixture
and Library's prepared source) belong to its Compose project, so `down -v`
(what `e2e-library-stack-down` and the `all` trap run) removes every container
and all state. Teardown also queries Docker for container, network,
and volume labels belonging to the exact Compose project and fails if residue
remains; a successful test cannot hide a cleanup failure. The next `up` is a
clean slate, which is why the `library` database is (re)created by
`scripts/e2e/initdb/` on every boot.

## How the seed authenticates

`scripts/e2e/seed_catalog_blueprint.py` provisions a throwaway AWID identity and
team against the stack's awid, installs Library for it (team server, install
admin, `aw plugin install`), then `POST`s the selected catalog blueprint to
`/v1/blueprints/import` with `aw id request --team-auth`. The signed audience
(`aud`) is the `scheme://host` of the target URL, and Library rejects any
request whose audience does not match its `LIBRARY_PUBLIC_ORIGIN`. The stack
sets both to Library's one in-network origin.

## CLI real-stack e2e suite (`AW_E2E`)

On top of the stack above, the CLI ships a Go e2e suite that drives the
selected exact `aw` binary against the live services over `os/exec` — no
`httptest` servers, no injected mocks. The ordinary target builds that binary
from the checkout. It lives in `cli/go/e2e/` and is the
regression net for the real signed-request and team-certificate paths.

One command brings up the stack, builds `aw` inside the network, runs the seed
and the suite there, and tears down:

```bash
make -C cli e2e
```

The suite is **double-gated** so it never runs in the default `go test ./...`:

- the `e2e` build tag (`//go:build e2e`) — the files are invisible without
  `-tags e2e`, and `go test ./...` silently skips the package;
- the `AW_E2E=1` env var — with the tag but without it, every test `t.Skip`s, so
  a stray `-tags e2e` can't accidentally hit a stack that isn't up.

`make -C cli e2e` sets both and points the suite at the stack via `AWEB_URL`,
`AWID_REGISTRY_URL`, `LIBRARY_E2E_LIBRARY_URL` and `LIBRARY_E2E_PROJECT`; the
suite refuses to run without them. Each test provisions a **fresh throwaway
AWID team** in its own workspace and `HOME` (unique namespace per test), so
tests are isolated and never touch the shared cli team; a test that calls
Library's member routes installs Library for its team first. The temp dirs are
cleaned up by `t.TempDir`.

The suite covers:

- **`real_stack_e2e_test.go`** — team-certificate auth reaches Library, and the
  seeded `aweb.team` blueprint is visible in the public catalog.
- **`materialize_flow_e2e_test.go`** — the tight regression net for the three
  Library materialize bugs (shelf-adopt idempotency, folded-block-scalar mission
  round-trip + materialize, and materialize-failure atomicity), driven through
  the real binary against the real seeded Library.
- **`refresh_flow_e2e_test.go`** — the public-pin adoption and approved shelf
  refresh flow. It exercises first-team creation in the shared `local` AWID
  namespace, so it needs a fresh stack (`make -C cli e2e` resets the stack).
- **`team_create_flow_e2e_test.go`** — the full self-hosted
  `aw team admin create --profile` flow: adopting two profiles materializes both homes
  and connects each member to the aweb service so the coordination-docs step
  succeeds (the self-hostability fix). It bootstraps its own unique BYOT
  namespace and therefore does not contend for `local`.

## Environment overrides

| Variable | Default | Purpose |
|----------|---------|---------|
| `LIBRARY_E2E_BLUEPRINT_SRC` | `naapp/library/test-vectors/blueprints/team` | catalog blueprint source |
| `AW_BIN` | (built from source) | exact aw binary for the seed and the Go suite (release skew cells); otherwise each journey run builds aw inside the network |
| `AW_E2E` | (unset) | set to `1` to run the `cli/go/e2e` suite (else it skips) |
| `AW_E2E_TEST_RUN` | (unset) | optional exact Go `-run` selector |
| `LIBRARY_E2E_PROJECT` | `aweb-e2e-stack-<hash>` | compose project name; defaults to a per-checkout value so concurrent runs don't collide |
| `KEEP_UP` | (unset) | leave the stack up on success (`all` / `cli e2e`) |

The compose project name is derived per-checkout (a hash of the repo path), so an
author's run and a reviewer's run from different worktrees use separate stacks
and never tear down each other's. Override with `LIBRARY_E2E_PROJECT` if needed.
