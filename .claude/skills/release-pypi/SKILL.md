---
name: release-pypi
description: Prepare an aweb server release for PyPI. Runs quality gates, bumps version, builds, verifies, commits, tags, and pushes. The CI workflow then publishes to PyPI.
argument-hint: [version]
---

# Release aweb server to PyPI

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
