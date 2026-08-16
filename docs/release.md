# Releasing aweb

This repository owns the aweb open-source artifacts. Its complete release is one
rerunnable command from a clean checkout at `origin/main`:

```sh
make release
```

There is no prepare/continue split, release card, prompt, or release-time
compatibility decision. Reviewed source declares the versions. When the clean
gate passes, the command publishes every owed artifact and verifies the public
result. It never changes a running service.

Prerequisites the gate refuses without: a running Docker daemon, and clean git
checkouts of the Library (`../library` beside this repository) and the team
blueprints (`../blueprints/team`), overridable via `LIBRARY_E2E_LIBRARY_CONTEXT`
and `LIBRARY_E2E_BLUEPRINT_SRC`.

## Authority

- Package manifests declare package versions.
- Artifacts without manifests derive their next patch from their immutable tag
  history.
- An artifact's source tag identifies the commit that produced it.
- Registry observation establishes whether the desired output exists.
- Exact-publish helpers compare staged and served output. An occupied version
  with different bytes is a refusal, never an adoption.
- For OCI artifacts, the version tag and `latest` must resolve to the same
  immutable index digest.

## Artifact and dependency graph

The graph is explicit in `scripts/release.py`. `content_paths` is the
maintained build-input closure for each artifact: a change in any listed path
makes that artifact move. Package-manager dependencies remain in their normal
manifests; the release graph records additional bundled and shared-source edges.

| Artifact | Build-input closure | Version authority |
|---|---|---|
| PyPI `aweb` | `server/` | `server/pyproject.toml` |
| PyPI `awid-service` | `awid/` | `awid/pyproject.toml` |
| AWID image | `awid/` and `server/` | AWID manifest |
| `aw` CLI and platform npm packages | `cli/go/` | next `aw-v*` patch |
| Claude channel | `channel/` and bundled `channel-core/` | channel manifest |
| Pi extension | `pi-extension/`, bundled `channel-core/`, and the five default skills | Pi manifest |
| Skills packages and archives | both package layouts and the five default skills | skills manifest |
| A2A gateway image | `cli/go/` | next `a2a-gw-v*` patch |

The Python `aweb` package declares its `awid-service` floor in
`server/pyproject.toml`. Release selection requires that floor to equal the
exact desired AWID version, so an AWID version change also requires a reviewed
`aweb` floor and version change. The Pi extension's compatible `@awebai/aw`
range is not an exact co-release edge. Shared or copied sources are release
edges because their bytes are bundled into the consumer.

Any edit to this table in code requires a matching contract-test and
documentation update. This makes a new bundled dependency a visible reviewed
decision instead of an inferred side effect.

## Gate scope and caches

The gate is one fixed table, `release-gate/suite-map.tsv`, but a release runs
only the rows that guard what it publishes: rows naming any artifact key in the
release's publication scope, plus every `all` row (shared prerequisites and
repository-wide contracts). The scope is the moving set joined with every
artifact the triggered workflows can republish. Rows outside the scope are
recorded as `SKIPPED` in the summary, so the evidence names what was not run
and why. The artifact column is part of the reviewed release graph: the runner
refuses unknown keys, and editing the column requires the matching
contract-test update in `scripts/e2e/test_release.py`.

Gate runs share lockfile-keyed caches: uv, Go module and build, and npm caches,
and the persistent buildx builder's layer cache, which every invocation bounds
with a keep-storage reclaim on exit (and mid-run after the largest image build
when that row is selected). Determinism is carried by the committed lockfiles,
whose hashes the gate records in its evidence; a warm cache hit yields the same
bytes as a cold fetch. Gate invocations share the builder and cache root and
are expected not to overlap on one host.

## What the command does

1. Fetch tags and branches, reject a dirty checkout, and require the exact
   `origin/main` commit.
2. Find any unfinished intent. If none exists, compare every artifact's complete
   build-input closure with its newest source tag and validate all versions.
3. Observe the complete desired public artifact set. An absent artifact whose
   source did not move is not silently rebuilt under an occupied version; the
   command requires a version bump.
4. Run the fixed clean-Docker gate once, before creating publication state,
   scoped to the rows guarding the artifacts being published plus every row
   that guards all releases.
5. Write `release-intent-<source>`, whose canonical JSON binds the source SHA,
   all desired versions, and every publication still owed.
6. Fast-forward the path-scoped `release` branch. Workflows build the exact
   commit, publish or adopt exact bytes, verify the public result, and create
   source tags.
7. Re-observe the complete desired public set, update the public marketplace
   pointer when its packages moved, and write the matching
   `release-done-<source>` tag.

Publication grouping is only an execution optimization. The intent and final
observation always cover the complete desired artifact set.

## Failure and retry

Run `make release` again.

Before an intent tag exists, a failure made no publication decision. After the
tag exists, it is authoritative: a rerun uses its exact source, versions, and
owed publications. Already-correct public outputs are adopted; missing work is
continued; conflicting bytes, tags, or branch ancestry stop the run.

If the checkout's current `main` advanced while an older intent was unfinished,
the command finishes the recorded intent from an automatic detached worktree,
then continues through the current `main` desired state in the same invocation.

There is no resume subcommand and no editable operator state file. A terminated
shell, expired credential, workflow failure, or temporary registry outage does
not require a person to reconstruct context.

## Static site

The `awid.ai` Hugo site is independent of artifact release. Its source and
mirrored documents are reviewed on `main`; deployment never creates or repairs
a commit.

After production authorization, `make deploy-site` verifies the mirrors and
Hugo build, requires a clean checkout at the exact fetched `origin/main`, then
fast-forwards that SHA to `deploy-awid-landing` and reads the remote ref back.
Render must build `awid/site` from that branch. A successful branch push is a
delivery request, not proof that Render completed: verify the provider deploy
and the live `https://awid.ai` site afterward.

## Implementation map

- `scripts/release.py`: desired-state selection and reconciliation.
- `scripts/release-gate.sh`: fixed clean gate.
- `release-gate/suite-map.tsv`: named gate inventory; each row names the
  artifact keys it guards (`all` = every release).
- `scripts/*-exact-publish.sh`: exact npm, PyPI, and OCI decisions.
- `scripts/release-tag-helpers.sh`: immutable tag observation.
- `.github/workflows/*release.yml`: thin, path-scoped publishers.
- `scripts/e2e/test_release.py`: intent, retry, registry, and ownership
  contracts.

Low-level helpers are mechanisms, not alternate maintained release commands.
