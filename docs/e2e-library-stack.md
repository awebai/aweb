# Optional Library Integration Test Stack

Status: **optional cross-repository maintainer harness**. In this filename and
Make target, `e2e` means end-to-end integration testing; it does **not** mean the
encrypted-message E2E protocol. Library is unnecessary for basic communication,
identity/team membership, or encrypted-v2 interoperability.

The self-hosted integration stack the optional profile/team/Library flow runs against. It
brings up, from source, on one Docker network:

| Service  | Source            | Host port (default) | In-container |
|----------|-------------------|---------------------|--------------|
| postgres | `postgres:16`     | 55432               | 5432         |
| redis    | `redis:7`         | (internal only)     | 6379         |
| awid     | `awid/Dockerfile` | 18010               | 8010         |
| aweb     | `server/Dockerfile` | 18000             | 8000         |
| library  | `../library/Dockerfile` | 18765         | 8765         |

It then **seeds** the current `aweb.team` catalog blueprint into Library over
real AWID team-certificate auth, so the materializer is exercised against the
real folded-block-scalar blueprint content (the same flow Library's own e2e
suite runs).

This harness contains postgres + redis + AWID + OSS aweb + Library. Hosted
service infrastructure and hosted controller-key flows are not part of this
compose or prerequisites for using it.

## Cross-repo dependencies

This harness depends on two checkouts sitting beside the aweb repo:

- **`../library`** — the Library service. It is the build context for the
  `library` service. Override with `LIBRARY_E2E_LIBRARY_CONTEXT`.
- **`../blueprints/team`** — the `aweb.team` blueprint from the selected
  checkout that the seed publishes into Library. Override with
  `LIBRARY_E2E_BLUEPRINT_SRC`.

The clean local-Docker release gate records the exact commit and requires a
clean working tree for each sibling input before it starts. Pull-request CI
checks out the current public default branches without stale fixed pins.

The expected layout is the standard sibling checkout:

```
prj/awebai/
├── aweb/        <- this repo
├── library/
└── blueprints/
    └── team/
```

awid and aweb build from this repo (`context: .`), so they need no override.

These sibling paths are resolved automatically, **including from a git
worktree** — where `../library` would otherwise point beside the worktree
instead of beside the main checkout. The harness falls back to the main repo's
parent (via `git --git-common-dir`), so a worktree run needs no manual env vars.
Set `LIBRARY_E2E_LIBRARY_CONTEXT` / `LIBRARY_E2E_BLUEPRINT_SRC` only if your
layout is non-standard.

## Run it

One command — build, start, wait healthy, seed, verify, tear down:

```bash
make e2e-library-stack
```

Step by step (leaves the stack running between steps):

```bash
make e2e-library-stack-up     # build + start, wait until all three are healthy
make e2e-library-stack-seed   # publish the aweb.team blueprint into Library
make e2e-library-stack-down   # remove containers AND all state (-v)
```

Or drive the script directly:

```bash
./scripts/e2e-library-stack.sh up
./scripts/e2e-library-stack.sh seed
./scripts/e2e-library-stack.sh down
```

After `up`, the services are reachable on the host:

```bash
curl -s http://127.0.0.1:18010/health      # awid
curl -s http://127.0.0.1:18000/health      # aweb
curl -s http://127.0.0.1:18765/health      # library
curl -s http://127.0.0.1:18765/v1/blueprints | python3 -m json.tool   # after seed
```

## Teardown leaves no state

Postgres data lives on tmpfs and the stack defines no named volumes, so
`down -v` (what `e2e-library-stack-down` and the `all` trap run) removes every
container and all state. Teardown also queries Docker for container, network,
and volume labels belonging to the exact Compose project and fails if residue
remains; a successful test cannot hide a cleanup failure. The next `up` is a
clean slate, which is why the `library` database is (re)created by
`scripts/e2e/initdb/` on every boot.

## How the seed authenticates

`scripts/e2e/seed_catalog_blueprint.py` provisions a throwaway AWID identity and
team against the stack's awid, then `POST`s the selected catalog blueprint to
`/v1/blueprints/import` with `aw id request --team-auth`. The signed audience
(`aud`) is the `scheme://host` of the target URL, and Library rejects any
request whose audience does not match its `LIBRARY_PUBLIC_ORIGIN`. The harness
therefore pins `LIBRARY_PUBLIC_ORIGIN` to the same `http://127.0.0.1:<port>`
origin the seed posts to; if you change the library port, both move together.

## CLI real-stack e2e suite (`AW_E2E`)

On top of the stack above, the CLI ships a Go e2e suite that drives the
selected exact `aw` binary against the live services over `os/exec` — no
`httptest` servers, no injected mocks. The ordinary target builds that binary
from the checkout. It lives in `cli/go/e2e/` and is the
regression net for the real signed-request and team-certificate paths.

One command brings up the stack, builds `aw`, runs the suite, and tears down:

```bash
make -C cli e2e
```

The suite is **double-gated** so it never runs in the default `go test ./...`:

- the `e2e` build tag (`//go:build e2e`) — the files are invisible without
  `-tags e2e`, and `go test ./...` silently skips the package;
- the `AW_E2E=1` env var — with the tag but without it, every test `t.Skip`s, so
  a stray `-tags e2e` can't accidentally hit a stack that isn't up.

`make -C cli e2e` sets both and points the suite at the stack via `AWEB_URL`,
`AWID_REGISTRY_URL`, and `LIBRARY_E2E_LIBRARY_URL`. Each test provisions a
**fresh throwaway AWID team** in its own workspace and `HOME` (unique namespace
per test), so tests are isolated and never touch the shared cli team; the
temp dirs are cleaned up by `t.TempDir`.

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
  `aw team create --profile` flow: adopting two profiles materializes both homes
  and connects each member to the aweb service so the coordination-docs step
  succeeds (the self-hostability fix). It bootstraps its own unique BYOT
  namespace and therefore does not contend for `local`.

**Manifest fixture caveat.** Reaching Library through `aw` needs the library
plugin pointed at the stack. The committed Library manifest hardcodes
`origin: https://library.aweb.ai` and `aw plugin install` enforces origin/fetch
self-consistency, so a self-hosted Library cannot be installed normally — filed
as a self-hostability bug. The materialize suite works around this *for the test
only* by writing the served manifest with its origin rewritten to the stack URL.
When that bug is fixed (Library serves its own public origin), the fixture is
deleted and the suite installs the manifest the real way.

## Environment overrides

| Variable | Default | Purpose |
|----------|---------|---------|
| `LIBRARY_E2E_AWID_PORT` | 18010 | awid host port |
| `LIBRARY_E2E_AWEB_PORT` | 18000 | aweb host port |
| `LIBRARY_E2E_LIBRARY_PORT` | 18765 | library host port |
| `LIBRARY_E2E_POSTGRES_PORT` | 55432 | postgres host port |
| `LIBRARY_E2E_LIBRARY_CONTEXT` | `../library` | Library build context |
| `LIBRARY_E2E_BLUEPRINT_SRC` | `../blueprints/team` | catalog blueprint source |
| `LIBRARY_E2E_LIBRARY_URL` | `http://127.0.0.1:18765` | Library base URL the Go e2e suite drives |
| `AW_BIN` | `aw` | exact aw binary used to drive the seed / Go suite; `cli/scripts/e2e.sh` builds only when it is unset |
| `AW_E2E` | (unset) | set to `1` to run the `cli/go/e2e` suite (else it skips) |
| `AW_E2E_TEST_RUN` | (unset) | optional exact Go `-run` selector |
| `LIBRARY_E2E_PROJECT` | `aweb-e2e-stack-<hash>` | compose project name; defaults to a per-checkout value so concurrent runs don't collide |
| `KEEP_UP` | (unset) | leave the stack up on success (`all` / `cli e2e`) |

The compose project name is derived per-checkout (a hash of the repo path), so an
author's run and a reviewer's run from different worktrees use separate stacks
and never tear down each other's. Override with `LIBRARY_E2E_PROJECT` if needed.
