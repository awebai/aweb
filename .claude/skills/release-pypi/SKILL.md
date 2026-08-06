---
name: release-pypi
description: Prepare an aweb server release for PyPI. Runs quality gates, bumps version, builds, verifies, commits, tags, and pushes. The CI workflow then publishes to PyPI.
argument-hint: [version]
---

# Release aweb server to PyPI

> **STALE PROCESS WARNING — corrected 2026-08-05 (aweb-abbe.8).**
> The steps below describe the retired tag-triggered process. **A tag push now
> publishes nothing:** `.github/workflows/pypi-release.yml` is `workflow_dispatch`-only, in three modes
> (`stage-only` builds and inspects, `publish-continuation` publishes the exact
> bytes a prior stage produced, `verify-only` re-inspects a released version).
> A pushed tag runs no code at all. This is deliberate — a tag trigger meant CI
> rebuilt from source and published whatever it produced, which is how five of
> six aw releases shipped wrong stamps.
>
> **Use the driver instead:** `make release-plan` then
> `make release-run PLAN_ID=<id> PLAN_ARTIFACT_ID=<id>`. It stages once,
> inspects the exact bytes, publishes those same bytes, tags, verifies, and
> seals a receipt.
>
> The hazards below are still true and worth reading: publication is immutable
> (never overwrite, delete, re-stamp, or move a tag; fix forward), and
> publication is not delivery.
>
> Note the driver refuses lanes whose runtime-contract edges have no measured
> support; until the G5 measurements land (epic `aweb-abbe`), a release needs an
> explicitly authorized exception — the precedent is recorded on `aweb-abbt`.
> The full reduction of this skill follows once those measurements land.


The PyPI release is triggered by pushing a `server-vX.Y.Z` git tag. GitHub
Actions then runs [`.github/workflows/server-release.yml`](../../../.github/workflows/server-release.yml),
which runs `make release-server-gate` against the tagged commit and publishes
with `uv publish` only if it passes.

## The publish refuses unless the suite passed on the tagged commit

PyPI never lets a version be re-uploaded, so the workflow runs the aweb suite in
the same job as the publish, against the tree the tag points at. `uv publish`
uploads the `server/dist` that gate produced, so the artifact tested and the
artifact published are the same build.

The gate is `make release-server-gate`: `uv lock --check`, the aweb suite
against that committed lock, then `uv build` and an assertion that both
artifacts exist. It **verifies** the lockfile rather than repairing it — a stale
`server/uv.lock` fails the release instead of being resolved into something the
suite never ran against. Commit the lock before you tag.

Steps 3 to 5 below are what makes that pass. If the gate fails at release time,
the fix is the same work done earlier, not a bypass.

### What the gate does not cover

A tag push is the only trigger, and re-running the workflow re-runs the gate, so
this route is covered. Two routes are not, and neither can be closed from inside
this repository:

- A `server-v*` tag cut at a commit where the gate step was edited out. A
  tag-triggered workflow runs the file as it exists at the tagged commit, and
  `main` cannot be branch-protected here.
- A direct `uv publish` from anywhere, by anyone holding a PyPI token for the
  `aweb` project. Scoping that credential is `aweb-aaun.2`.

Publishing off-CI is not a supported path. Use the tag.

## Flow

1. Determine the next version.
   Use `server/pyproject.toml` as the source of truth.

2. Verify the tree is ready.
   Run `git status` and make sure the intended release commit is on `main`.

3. Run release checks.
   Use `make release-server-check`.

4. Verify artifacts.
   Confirm `server/dist/` contains:
   - `aweb-<VERSION>.tar.gz`
   - `aweb-<VERSION>-py3-none-any.whl`

5. Commit and tag.
   Use `make release-server-tag`.

6. Push to trigger publishing.
   Use `make release-server-push`.

## Before you start: put the pinned Go toolchain first on PATH

`make ship` (and `release-all-check`) runs `check-go-vulnerability-audit`, which
sets `GOTOOLCHAIN=local` and **refuses to run under any Go other than the one
`cli/go/go.mod` declares** — currently `go 1.24.13`. It audits the stdlib that
actually ships, so a newer toolchain would report on a stdlib no user runs.

A machine whose default `go` has drifted ahead fails with:

```
Go vulnerability audit requires go1.24.13, but the runner is go1.26.4
```

That is the gate working, not an obstacle. Fix it by making the audit **run**:

```sh
# the SDK is usually already present under ~/sdk; this only puts it first
go install golang.org/dl/go1.24.13@latest && go1.24.13 download   # once, if missing
export PATH="$(go1.24.13 env GOROOT)/bin:$PATH"
bash scripts/check-go-vulnerability-audit.sh   # expect: passed: N reviewed reachable finding(s)
```

Confirm the audit passes standalone **before** committing to a full `make ship`
— the gate is ~20 minutes and this failure lands partway in.

**Never skip the audit or relax the version check to get green.** If bypassing
it is the only route, stop and hand the release back.

Related: `release-all-check` is the **first** target in `ship`, so when it fails
everything after it — `release-awid-check`, `test-federation-e2e`, `test-e2e`,
the CLI e2e — never runs. Those are **unobserved, not passing**. Re-run the
whole gate rather than resuming from the failure.

## Notes

- Keep the git tag format as `server-vX.Y.Z`.
- The workflow rejects tags that do not match `server/pyproject.toml`. That
  comparison is a string comparison of the tag name against the manifest, and
  apart from the gate it is the only automated check the workflow makes.
- `scripts/check-server-version-bump.sh` is not in the release gate. On the
  commit a `server-v*` tag points at it compares that tag against itself and
  always passes. It runs where its question is meaningful: `server-ci.yml` on
  every push and PR touching `server/`, and `make release-server-check` here.
- `server/uv.lock` should stay aligned with the package version metadata.
- CI requires every `server/` change to carry a version bump
  (`scripts/check-server-version-bump.sh`), so by release time
  `server/pyproject.toml` usually already holds the next version and the
  tag step tags it without a separate release commit.
