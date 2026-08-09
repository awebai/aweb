---
name: release
description: Release any aweb artifact - aw CLI, aweb server, awid (PyPI and image), channel, Pi, skills. One driver owns the sequence for every lane. Use for any publication, and read the hazards before authorizing one.
argument-hint: [component] [version]
allowed-tools: Bash(make *), Bash(git *), Bash(gh run *), Bash(npm view *), Bash(curl *)
---

# Release an aweb artifact

One driver releases every artifact. Use the hosted workflow lane normally:

```
make release-plan AUTHORITY=github-workflow-artifacts
make release-run AUTHORITY=github-workflow-artifacts \
  PLAN_ID=<id> PLAN_ARTIFACT_ID=<id> \
  STAGE_ARTIFACT='component=<name>,ref=<ref>,source=<source>,digest=<digest>'
```

When hosted runners are unavailable, use the first-class local lane with an
explicit human risk acceptance:

```
make release-plan AUTHORITY=local-runnerless STORE_ROOT=<durable-local-dir>
make release-run AUTHORITY=local-runnerless \
  STORE_ROOT=<same-dir> PLAN_ID=<id> PLAN_ARTIFACT_ID=<id> \
  LOCAL_ADAPTER='<component>@<exact-reviewed-source-sha>=/absolute/path/to/direct-adapter' \
  LOCAL_RISK_AUTHORIZATION='<who>,<when>,<risk accepted>'
```

Append `EXTERNAL_CONTEXT='<repo>=/absolute/checkout'` to planning when the
graph names an external pin. Today that is the `ac-pin` lane: both its pins,
`release-pin.toml` and `backend/uv.lock`, live in the AC repository and are
resolved only from a declared context, never relative to this one.

```
make release-plan EXTERNAL_CONTEXT='github.com/awebai/ac=/absolute/path/to/ac'
```

Without it the driver refuses to guess, and both pins report as *unreadable in
its declared repository context* — which reads like a broken lane rather than a
missing argument. The checkout must be an absolute path whose `origin` is the
declared repository; the driver verifies both and refuses otherwise.

`DEFER_G5=1` is **not** covered by the runnerless risk authorization. Accepting a
runner outage and accepting unmeasured runtime support are different judgments;
deferral needs its own record, on every authority:

```
G5_AUTHORIZATION='who=<w>,when=<t>,source=<40hex>,plan=<64hex>,edges=<64hex>[+<64hex>],risk=<text>'
```

Take the edge ids verbatim from `release-plan`'s `deferrable_runtime_contracts`.
They are content hashes, not display strings, and an authorization naming the
wrong edge is refused.

Scope a release with `ONLY=<component>`, and supply a `POINTER_ADAPTER` for every
forced pointer the plan moves — a channel or skills release moves
`marketplace-pointer` and cannot execute without it:

```sh
make release-plan AUTHORITY=github-workflow-artifacts ONLY=channel

make release-run AUTHORITY=github-workflow-artifacts \
  PLAN_ID=<frozen_plan_id> PLAN_ARTIFACT_ID=<plan_artifact_id> \
  STAGE_ARTIFACT='component=channel,ref=gh-artifact:awebai/aweb:<run>:<artifact>,source=<40hex>,digest=sha256:<64hex>' \
  POINTER_ADAPTER="marketplace-pointer=$PWD/scripts/pointer-adapter-marketplace-pointer.py" \
  DEFER_G5=1 \
  G5_AUTHORIZATION='who=<w>,when=<t>,source=<40hex>,plan=<64hex>,edges=<64hex>,risk=<text no commas>'
```

The pointer adapter value uses double quotes so `$PWD` expands: the driver
requires an absolute path and rejects a literal `$PWD`. `risk=` must contain no
comma - the record is comma-separated.

No `DELIVERY_PROOF` at publish: restart evidence cannot exist before the version
does, so the receipt records the obligation as OUTSTANDING and it is discharged
afterwards. Use `RESUME=1
MANIFEST_ID=<id>` only to resume an interrupted release-run from its staged
manifest. A receipt's `deferred-hosting:*` / `tag-and-release` record is a
separate explicitly authorized continuation; release-run resume does not
perform it. The local adapter follows the protocol in
`docs/runnerless-release.md`; do not replace it with a hand-maintained stage or
publish sequence.

The driver reads the component graph (`release/components.toml`), works out
what moves and in what order, stages each artifact **once**, inspects the exact
bytes, refuses unless every guarantee holds, publishes those same bytes, tags,
verifies what landed, and seals a receipt. Components: `aw`, `server`,
`awid-pypi`, `awid-image`, `channel`, `pi`, `skills`, and `sites`.

There is no per-artifact step list any more. The driver performs the steps; a
human maintaining a parallel list is how the steps drift from reality.

## A tag push publishes nothing

Publishing workflows for the driver-owned components are
`workflow_dispatch`-only, in three modes: `stage-only` (build and inspect),
`publish-continuation` (publish the exact bytes a prior stage produced), and
`verify-only` (re-inspect a released version). Pushing one of those components'
tags runs no publishing code.

This is deliberate. A tag trigger meant CI rebuilt from source and published
whatever it happened to produce; that is how five of six aw releases shipped
wrong VCS stamps. The driver publishes bytes that were already inspected.

Exceptions must be verified per workflow rather than assumed. `aw-release.yml`
in this repo still triggers on `aw-v*` and syncs `cli/go` to `awebai/aw`; the
driver instead uses the dispatch-only workflow in `awebai/aw`. The A2A gateway
also retains a legacy tag-triggered workflow outside the release graph. Do not
generalize either legacy path into instructions for driver-owned components.

## Publication is not delivery

Publishing exact bytes is necessary and not sufficient. A release is complete
only when the user is running the new code:

- **npm packages** (`channel`, `pi`, `skills`) — the bytes are on the registry,
  **and** the marketplace pointer in `awebai/claude-plugins`
  (`.claude-plugin/marketplace.json`) pins the new version. That pointer is a
  forced edge in the component graph, not an optional follow-up: Claude Code
  only re-resolves an npm source when the marketplace entry advertises a
  version, so publishing alone is invisible to existing installs.

  The driver performs it. Pass the adapter and it stages the intended
  advertisement, applies it, and re-reads the repository, refusing unless it
  advertises exactly what was published:

  ```
  make release-run ... \
    POINTER_ADAPTER='marketplace-pointer=$PWD/scripts/pointer-adapter-marketplace-pointer.py'
  ```

  What it advertises comes from the frozen plan, never from the command line.
- **installed plugins** — an installed plugin keeps its loaded code until the
  session restarts. The `delivery_restart` obligation requires proof per host:
  plugin updated **and** process restarted on the published version. `claude
  plugin install` no-ops on an already-installed plugin, so an install is not
  an update.
- **Pi runtimes** — a Pi npm publish does not refresh `~/.pi/agent/npm` or
  reload running sessions. Inventory the live processes first, update the
  package-aware cache (never a global npm install - that updates the wrong
  copy), then prove the resolved cache version from the package Pi actually
  loads and that each affected runtime restarted on it.

Skipping delivery is the most common way a "shipped" fix reaches nobody.

## Publication is immutable

No published version is ever overwritten, deleted, re-stamped, or re-uploaded,
and no tag is ever moved. PyPI refuses re-upload outright, goreleaser's GitHub
Releases are immutable, and npm/GHCR must be treated the same way. **If
anything is wrong after publication, fix forward to a new version.**

Corollary for re-releasing an existing version: the driver only adopts bytes
that are byte-identical to what is already published. Go binaries are not
byte-reproducible across builds, so a previously published aw version can never
be re-adopted - it must become a new version.

## Versions

Each artifact has independent semver. Never derive one component's version from
another's - in particular the aw CLI version is not the server version. The
monotonicity guard refuses a proposal that is not strictly greater than the
latest published version for that artifact.

## Human risk acceptance

A runner outage or urgent release must not turn the fallback into a ceremony.
One explicit human authorization records who accepted which risk and lets the
runnerless driver proceed. It does not weaken build-once/exact-bytes: the local
adapter stages once, publication consumes that exact inventory, and the driver
records the result.
