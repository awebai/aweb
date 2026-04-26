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
| `server/src/aweb/awid/` | Identity, signing, custody, continuity |
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
  - [`server/src/aweb/migrations/server/`](../server/src/aweb/migrations/server)
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
At minimum, prove both mail and chat across public, `org_only`,
`team_members_only`, unauthorized no-pin fail-closed, `nobody` known-pin
fallback, and direct `did:aw`/stable identity sends. Cloud-only hosted custody
paths belong in the cloud e2e suite; shared identity/address behavior belongs
in the OSS e2e suite.

Useful commands:

```bash
cd server && UV_CACHE_DIR=/tmp/uv-cache uv run pytest -q
cd cli/go && GOCACHE=/tmp/go-build-aweb go test ./...
./scripts/e2e-oss-user-journey.sh
```

## Documentation Discipline

- Use code as the source of truth, not stale design assumptions.
- Prefer FastAPI/OpenAPI, Cobra help, and MCP registration over handwritten
  guesses.
- When a route, tool, or command changes, update the corresponding docs in the
  same change.
