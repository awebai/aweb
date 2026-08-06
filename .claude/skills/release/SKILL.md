---
name: release
description: Release any aweb artifact - aw CLI, aweb server, awid (PyPI and image), channel, Pi, skills. One driver owns the sequence for every lane. Use for any publication, and read the hazards before authorizing one.
argument-hint: [component] [version]
allowed-tools: Bash(make *), Bash(git *), Bash(gh run *), Bash(npm view *), Bash(curl *)
---

# Release an aweb artifact

There is one way to release, for every artifact:

```
make release-plan
make release-run PLAN_ID=<id> PLAN_ARTIFACT_ID=<id>
```

The driver reads the component graph (`release/components.toml`), works out
what moves and in what order, stages each artifact **once**, inspects the exact
bytes, refuses unless every guarantee holds, publishes those same bytes, tags,
verifies what landed, and seals a receipt. Components: `aw`, `server`,
`awid-pypi`, `awid-image`, `channel`, `pi`, `skills`.

There is no per-artifact step list any more. The driver performs the steps; a
human maintaining a parallel list is how the steps drift from reality.

## A tag push publishes nothing

Every publishing workflow is `workflow_dispatch`-only, in three modes:
`stage-only` (build and inspect), `publish-continuation` (publish the exact
bytes a prior stage produced), `verify-only` (re-inspect a released version).
Pushing a tag runs no publishing code at all.

This is deliberate. A tag trigger meant CI rebuilt from source and published
whatever it happened to produce; that is how five of six aw releases shipped
wrong VCS stamps. The driver publishes bytes that were already inspected.

Exception, verified per workflow rather than assumed: `aw-release.yml` in this
repo still triggers on `aw-v*` and syncs `cli/go` to `awebai/aw`. The driver
drives the aw lane through the dispatch-only workflow in `awebai/aw` itself, so
treat the tag-sync path as legacy; do not start an aw release by pushing a tag.

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

## Current gate state (delete this section when it stops being true)

The driver refuses any release whose runtime-contract edges have no measured
support. The G5 measurements are not yet anchored (epic `aweb-abbe`: `.12`
adaptation, then per-edge measurement), so lanes touching unmeasured edges will
refuse.

Until then a release needs an explicitly authorized exception. G1
build-once/exact-bytes still holds in full; only the G5 orchestration is
bypassed. The precedent - authorization structure, joint barrier across two
surfaces, and adopting existing staged artifacts rather than rebuilding - is
recorded on `aweb-abbt` (channel 1.7.2 + pi 0.3.2, 2026-08-05). Reuse that
shape; do not invent a new bypass, and never assume the exception.

## Verify what actually landed

Do not trust "the workflow said success". Check the bytes:

```
# npm
curl -s https://registry.npmjs.org/<pkg>/-/<file>.tgz | shasum -a 256
# PyPI: compare the release file digests to the staged manifest
# tags
git ls-remote origin refs/tags/<tag>
```

The published digest must equal the staged digest the driver recorded, and the
tag must dereference to the exact reviewed source commit. Byte identity is the
entire point of the lane.
