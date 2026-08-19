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
4. Classify the registered tool in `scripts/regenerate_mcp_reference.py`.
5. Run `make regenerate-mcp-tools-reference`, then
   `make test-mcp-tools-reference`. Do not edit the generated
   [`docs/mcp-tools-reference.md`](./mcp-tools-reference.md) by hand.

## How to Add a CLI Command

1. Add or update a Cobra command under
   [`cli/go/cmd/aw/`](../cli/go/cmd/aw).
2. Wire it into the command tree from the appropriate parent command.
3. Add unit tests next to the command implementation.
4. Verify help output stays clear, because the docs are generated from the live
   command surface.
5. Run `make regenerate-cli-reference`, then `make test-cli-reference`. Do not
   edit [`docs/cli-command-reference.md`](./cli-command-reference.md) by hand.
   The test compares the rendered root families with Cobra's independent
   completion inventory and fails for newly visible, removed, or stale commands.

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
(`docs/cli-command-reference.md`, regenerated and tested with the Make targets
above), the reserved-app-ids artifacts, resource
packs, the public AWID site mirrors of `docs/identity-guide.md` and
`docs/trust-model.md`, and the built claude-channel and pi-extension bundles
(both rebuilt from `channel-core` source at build time).

Before finalizing a candidate, run the single freshness command and commit any
regenerated output:

```
make freshness
```

The complete Docker candidate gate runs the same check and fails on drift.

Run the Node installs first if you are invoking it directly on a fresh checkout:

```
(cd channel && npm ci) && (cd pi-extension && npm ci)
```

Without them the bundle sections fail on a missing `esbuild` binary, and they
report it as `bundle stale or missing the security surface` — which reads as
artifact drift rather than as an absent install. The candidate gate
installs all three Node workspaces once before it reaches freshness; running
`make freshness` on its own skips that step.

## Reproducible OATS seam input

The OATS seam tests do not read a sibling working checkout by default. `make
prepare-oats-test-root` materializes the immutable repository and commit recorded
in `oats/upstream-test-pin.json` into the ignored `.cache/oats-pinned` directory;
`make test-oats`, `make test-oats-proof-helpers`, and the internal clean-Docker
gate all consume that clean checkout, so an aweb result is attributable to
committed inputs rather than another repository's uncommitted state.

This pin has a cost: it does not automatically exercise newer or uncommitted OATS
integration primitives. To test that leading edge deliberately, opt in without
changing or cleaning the local checkout:

```bash
make test-oats OATS_TEST_ROOT=/path/to/local/oats
make test-oats-proof-helpers OATS_TEST_ROOT=/path/to/local/oats
```

Treat that override as additional early-integration evidence, not as a substitute
for the pinned release result. Update the committed pin deliberately when the
reviewed OATS seam advances; a clean first run requires network access to fetch the
pinned commit, while later runs reuse and reset the repository-owned cache.

## Comprehensive candidate proof

`make release-candidate TAGS='...'` runs one gate in a clean local Docker
environment before creating any local release tag. Its complete product-test
list is the readable shell script `scripts/candidate-suite.sh`: release-shaped
packages/images, unit and contract suites, OATS and real-stack journeys,
freshness, process guards, and vulnerability audits. Every test runs for every
candidate; there is no artifact scoping or skipped proof. Hosted tag workflows
do not repeat this complete suite.

The suite stops on the first failing command and the gate retains its complete
output. Gate runs share lockfile-keyed
package and layer caches; determinism is carried by the committed lockfiles,
whose hashes the gate records in its evidence. It starts from one exact clean aweb commit, records the exact
clean Library and blueprint input commits, and rejects dirty or missing inputs.
The candidate command creates the requested local tags only after the exact
checkout remains clean and every test is green.

Reproducible here means reproducible on a clean runner with no helpful ambient
tools. The OATS seam builds `aw` from the exact aweb checkout and selects the real
Pi binary installed from `pi-extension/package-lock.json`; it prepends both exact
paths before spawning. It never substitutes a globally installed or previously
published CLI/runtime. A developer laptop is weak evidence for this property
precisely because its accumulated tools can hide missing setup.

Treat the workflow as a diagnostic signal, not an availability dependency. Fix
persistent failures rather than ignoring them, but keep the explicit human risk
acceptance usable when runners are unavailable or urgency warrants proceeding.

## Vulnerability audits

`make check-node-audit` and `make check-go-vulnerability-audit` audit the
dependencies a release ships. Both run from the complete Docker candidate
gate, and neither runs from `make test`: the Go audit pins itself to the toolchain in
`cli/go/go.mod` and refuses to run under any other, and both consult an
advisory database that moves without any repo change, which would make `make
test` non-deterministic.

These run **at release time only — nothing runs them on a schedule**. An
advisory published between two releases is not seen until the next release,
and the deferral deadlines in `.github/go-vulnerability-exceptions.json` are
only checked when an audit runs. This is an accepted limitation, tracked in
`default-aaoa`.

The Go audit refuses to run under the wrong toolchain and prints the two
commands that install the pinned one. `make check-node-audit` needs the
workspace dependencies installed (`npm ci` in `channel-core`, `channel` and
`pi-extension`); the candidate gate installs them before auditing.

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

Two further gates run in the same command and answer different questions:

- **`scripts/check-doc-links.py`** resolves every relative Markdown link between
  tracked documents. `check-doc-paths.sh` validates backtick-quoted repository
  paths, which start with a top-level directory; a bare `[text](sibling.md)`
  carries no such prefix and is invisible to it. Deleting a document therefore
  used to leave live cross-references pointing at nothing while every other gate
  stayed green.
- **`scripts/check-private-boundary.py`** keeps the hosted product's private
  surface out of the public repository: hosted-only HTTP endpoints, the hosted
  account model (`org_id`, `user_id`) as schema fields, and private repository
  paths. Naming `app.aweb.ai` as a deployment you can talk to is fine and is not
  what this looks for.

  The hosted coupling that exists today is frozen in that file as an enumerated
  **baseline**, not an allowlist: it names exact endpoint literals and exact
  struct names, so moving one to a different file still trips the gate and an
  eleventh endpoint fails. If you remove coupling, delete its baseline entry —
  that makes the gate stricter and needs no discussion. If you add coupling, the
  gate fails and that is a decision to argue in review, not a line to add.
  Re-measure with `scripts/check-private-boundary.py --derive`, which prints a
  freshly derived baseline and never writes.
- **`scripts/check-copied-resources.py`** compares hand-maintained copies against
  their sources. The Codex plugin ships its own copy of each canonical skill body
  and nothing regenerates it, so editing one side leaves two valid files that
  disagree. If you change a skill, change both — the gate names the copy, because
  the copy is the side that gets forgotten.

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
migration surveys) rot by construction. Do not quietly update them, and do not
park them: either keep them genuinely live, or delete them and let Git history
be the record. This repository keeps no archive directory, and the path check
has no archive exemption — every documented path must resolve.

If such a document holds an operational fact that is still true, move the fact
into the live document whose reader needs it before deleting the container. A
fact preserved only inside a stale document is a fact nobody will find.
