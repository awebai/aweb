# Contributing Guide

This guide is for developers working inside the monorepo.

## Repository Layout

| Path | Purpose |
| --- | --- |
| `server/` | Python package, FastAPI app, MCP server, migrations, tests |
| `server/src/aweb/` | Server runtime code |
| `server/src/aweb/routes/` | Core REST routers |
| `server/src/aweb/coordination/routes/` | Coordination-specific REST routers |
| `server/src/aweb/mcp/` | MCP server and tool implementations |
| `awid/src/awid/` | Identity, signing, custody, continuity — a separate Python package the server imports (`from awid...`), not a subdirectory of the server |
| `cli/go/` | Go CLI and supporting client library |
| `cli/go/cmd/aw/` | Cobra command tree |
| `docs/` | Top-level protocol and developer docs |
| `scripts/` | End-to-end and support scripts |

## Local Development

### Server

```bash
cd server
uv sync
UV_CACHE_DIR=/tmp/uv-cache uv run pytest -q
uv run aweb serve
```

### CLI

```bash
cd cli/go
make build
make test
```

Equivalent direct Go commands:

```bash
cd cli/go
GOCACHE=/tmp/go-build-aweb go test ./...
```

### End-to-End

```bash
./scripts/e2e-oss-user-journey.sh
```

## How to Add a REST Endpoint

1. Add or update the route module under:
   - [`server/src/aweb/routes/`](../server/src/aweb/routes)
   - or [`server/src/aweb/coordination/routes/`](../server/src/aweb/coordination/routes)
2. Use explicit request and response models where practical so OpenAPI stays
   useful.
3. Mount the router in
   [`server/src/aweb/api.py`](../server/src/aweb/api.py).
4. Add route-level tests under
   [`server/tests/`](../server/tests).
5. If the feature should be exposed to MCP, register a matching tool.
6. If the feature should be exposed in the CLI, add or update the Cobra command.
7. Update the docs under [`docs/`](../docs).

## How to Add an MCP Tool

1. Implement the behavior under
   [`server/src/aweb/mcp/tools/`](../server/src/aweb/mcp/tools).
2. Register the tool in
   [`server/src/aweb/mcp/server.py`](../server/src/aweb/mcp/server.py).
3. Keep tool parameters narrow and explicit.
4. Document the tool in [`docs/mcp-tools-reference.md`](./mcp-tools-reference.md).

## How to Add a CLI Command

1. Add or update a Cobra command under
   [`cli/go/cmd/aw/`](../cli/go/cmd/aw).
2. Wire it into the command tree from the appropriate parent command.
3. Add unit tests next to the command implementation.
4. Verify help output stays clear, because the docs are generated from the live
   command surface.
5. Update [`docs/cli-command-reference.md`](./cli-command-reference.md).

## Migrations

- Server schema migrations live under:
  - [`server/src/aweb/migrations/aweb/`](../server/src/aweb/migrations/aweb)
- Preserve old migrations once shipped.
- Add new migrations for schema changes instead of editing existing historical
  files.
- Use the pgdbm `{{schema}}` and `{{tables.*}}` templating conventions rather
  than hardcoding schema-qualified names.

## Testing Strategy

Recommended sequence for changes that cross layers:

1. targeted unit tests
2. full server or CLI suite
3. e2e user journey script for bootstrap/runtime changes

For changes touching identity resolution, address lookup, registry caching,
mail, chat, hosted custody, team certificates, or local aliases, the release
gate is the matrix in
[`identity-messaging-contract.md`](identity-messaging-contract.md#test-and-release-gates).
At minimum, prove both mail and chat across address first-contact,
`inbound_mode=open`, `inbound_mode=team_and_contacts`, unauthorized no-route
fail-closed, bare external `did:aw` first-contact fail-closed, and stored-route continuations. Cloud-only hosted
custody paths belong in the cloud e2e suite; shared identity/address behavior
belongs in the OSS e2e suite.

Useful commands:

```bash
cd server && UV_CACHE_DIR=/tmp/uv-cache uv run pytest -q
cd cli/go && GOCACHE=/tmp/go-build-aweb go test ./...
./scripts/e2e-oss-user-journey.sh
```

## Generated-artifact freshness

Some tracked files are generated from source and must not drift from it: the
`uv.lock` files (`awid/`, `server/`), the CLI command reference
(`docs/cli-command-reference.md`), the reserved-app-ids artifacts, resource
packs, the public AWID site mirrors of `docs/identity-guide.md` and
`docs/trust-model.md`, and the built claude-channel and pi-extension bundles
(both rebuilt from `channel-core` source at build time).

Before opening a release PR, run the single freshness command and commit any
regenerated output:

```
make freshness
```

The `Freshness` CI job runs the same check on every push and fails on drift.
Routine `make test` uses `uv run --frozen`, so tests never silently repair a
stale lock — regenerate it explicitly with `cd server && uv lock` (or `cd awid
&& uv lock`) and commit the result. An AWID version bump therefore also requires
regenerating `server/uv.lock` (the server depends on the editable AWID source).

## Documentation Discipline

- Use code as the source of truth, not stale design assumptions.
- Prefer FastAPI/OpenAPI, Cobra help, and MCP registration over handwritten
  guesses.
- When a route, tool, or command changes, update the corresponding docs in the
  same change.

### What the freshness gate checks, and what it cannot

`scripts/check-freshness.sh` mechanically verifies that committed generated
artifacts and public AWID site document mirrors still match their sources, and
that repository paths referenced in `docs/` actually exist
(`scripts/check-doc-paths.sh`).

It **cannot** verify that documentation prose is true. A path can resolve while
the sentence around it is wrong, a `:LINE` anchor can point at unrelated code
after a refactor, and a hand-written inventory can be stale while every link
still works. Those remain review obligations, so when you change code:

- Re-read the prose around any path you touched, not just the path itself.
- Prefer stable symbol names and links over `file:line` anchors — line numbers
  rot silently and are not checked.
- Do not hand-maintain inventories (test counts, ownership tables). Generate
  them, or state the date and SHA they were true at.

### Point-in-time documents

Analyses written to understand the tree at a moment (familiarization maps,
migration surveys) rot by construction. Do not quietly update them: either keep
them genuinely live, or move them to `docs/restructuring/archive/` with a
prominent header giving the date and SHA and stating that they are unmaintained.
Archived documents are excluded from the path check by design, because their
references are *expected* to be stale — that is what makes them a record.
