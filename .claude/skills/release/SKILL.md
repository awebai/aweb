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
graph names an external pin. Add `DEFER_G5=1` only when that same authorization
accepts deferring runtime compatibility measurement. Resume with `RESUME=1 MANIFEST_ID=<id>` when the
driver reports a deferred continuation. The local adapter follows the protocol
in `docs/runnerless-release.md`; do not replace it with a hand-maintained stage
or publish sequence.

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
