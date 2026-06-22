# Combined e2e stack: awid + aweb + Library, seeded

The self-hosted end-to-end stack the profile/team/Library flow runs against. It
brings up, from source, on one Docker network:

| Service  | Source            | Host port (default) | In-container |
|----------|-------------------|---------------------|--------------|
| postgres | `postgres:16`     | 55432               | 5432         |
| redis    | `redis:7`         | (internal only)     | 6379         |
| awid     | `awid/Dockerfile` | 18010               | 8010         |
| aweb     | `server/Dockerfile` | 18000             | 8000         |
| library  | `../library/Dockerfile` | 18765         | 8765         |

It then **seeds** the `aweb.engineering` pack into Library over real AWID
team-certificate auth, so the materializer is exercised against the real
folded-block-scalar pack content (the same flow Library's own e2e suite runs).

This is the *self-hosted* tier (`default-aabq.1`): postgres + redis + awid + OSS
aweb + Library. The *hosted* tier (awid + aweb-cloud + Library, exercising the
server-side controller-key flow) is a separate, AC-coordinated piece and is not
part of this compose.

## Cross-repo dependencies

This harness depends on two sibling checkouts of the aweb repo:

- **`../library`** — the Library service. It is the build context for the
  `library` service. Override with `LIBRARY_E2E_LIBRARY_CONTEXT`.
- **`../blueprints/engineering`** — the `aweb.engineering` pack (v0.2.3) that the
  seed publishes into Library. Override with `LIBRARY_E2E_BLUEPRINT_SRC`.

The expected layout is the standard sibling checkout:

```
prj/awebai/
├── aweb/        <- this repo
├── library/
└── blueprints/
    └── engineering/
```

awid and aweb build from this repo (`context: .`), so they need no override.

## Run it

One command — build, start, wait healthy, seed, verify, tear down:

```bash
make e2e-library-stack
```

Step by step (leaves the stack running between steps):

```bash
make e2e-library-stack-up     # build + start, wait until all three are healthy
make e2e-library-stack-seed   # publish the engineering pack into Library
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
container and all state. The next `up` is a clean slate, which is why the
`library` database is (re)created by `scripts/e2e/initdb/` on every boot.

## How the seed authenticates

`scripts/e2e/seed_engineering_pack.py` provisions a throwaway AWID identity and
team against the stack's awid, then `POST`s the engineering blueprint to
`/v1/blueprints/import` with `aw id request --team-auth`. The signed audience
(`aud`) is the `scheme://host` of the target URL, and Library rejects any
request whose audience does not match its `LIBRARY_PUBLIC_ORIGIN`. The harness
therefore pins `LIBRARY_PUBLIC_ORIGIN` to the same `http://127.0.0.1:<port>`
origin the seed posts to; if you change the library port, both move together.

## Environment overrides

| Variable | Default | Purpose |
|----------|---------|---------|
| `LIBRARY_E2E_AWID_PORT` | 18010 | awid host port |
| `LIBRARY_E2E_AWEB_PORT` | 18000 | aweb host port |
| `LIBRARY_E2E_LIBRARY_PORT` | 18765 | library host port |
| `LIBRARY_E2E_POSTGRES_PORT` | 55432 | postgres host port |
| `LIBRARY_E2E_LIBRARY_CONTEXT` | `../library` | Library build context |
| `LIBRARY_E2E_BLUEPRINT_SRC` | `../blueprints/engineering` | seed pack source |
| `AW_BIN` | `aw` | aw binary used to drive the seed |
| `KEEP_UP` | (unset) | with `all`, leave the stack up on success |
