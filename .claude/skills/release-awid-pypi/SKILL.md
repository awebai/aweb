---
name: release-awid-pypi
description: Prepare an awid-service release for PyPI. Runs quality gates, bumps version, builds, verifies, commits, tags, and pushes. The CI workflow then publishes to PyPI.
argument-hint: [version]
---

# Release awid-service to PyPI

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


The PyPI release is triggered by pushing an `awid-service-vX.Y.Z` git tag.
GitHub Actions then runs
[`.github/workflows/awid-pypi-release.yml`](../../../.github/workflows/awid-pypi-release.yml),
which runs `make release-awid-pypi-gate` against the tagged commit and publishes
with `uv publish` only if it passes.

## The publish refuses unless the suite passed on the tagged commit

PyPI never lets a version be re-uploaded, and awid has already burned two
versions this way. The workflow runs the awid suite in the same job as the
publish, against the tree the tag points at, and `uv publish` uploads the
`awid/dist` that gate produced — so the artifact tested and the artifact
published are the same build.

The gate is `make release-awid-pypi-gate`: `uv lock --check`, the awid suite
against that committed lock, then `uv build` and an assertion that both
artifacts exist. It **verifies** the lockfile rather than repairing it, which is
the difference between it and `make release-awid-check` below. Repair belongs to
preparation; at publish time a stale `awid/uv.lock` has to fail rather than be
resolved into dependencies the suite never ran against.

### What the gate does not cover

A tag push is the only trigger, and re-running the workflow re-runs the gate, so
this route is covered. Two routes are not, and neither can be closed from inside
this repository:

- An `awid-service-v*` tag cut at a commit where the gate step was edited out. A
  tag-triggered workflow runs the file as it exists at the tagged commit, and
  `main` cannot be branch-protected here.
- A direct `uv publish` from anywhere, by anyone holding a PyPI token for the
  `awid-service` project. Scoping that credential is `aweb-aaun.2`.

Publishing off-CI is not a supported path. Use the tag.

## Flow

1. Determine the next version.
   Use `awid/pyproject.toml` as the source of truth.

2. Verify the tree is ready.
   Run `git status` and make sure the intended release commit is on `main`.

3. Run release checks.
   ```bash
   make release-awid-check
   ```
   This repairs `awid/uv.lock` if it is stale. Commit the result — the release
   gate verifies that lock and will refuse the publish if it is out of date.

4. Verify artifacts.
   Confirm `awid/dist/` contains:
   - `awid_service-<VERSION>.tar.gz`
   - `awid_service-<VERSION>-py3-none-any.whl`

5. Bump version in `awid/pyproject.toml`.

6. Commit and tag.
   ```bash
   git add awid/pyproject.toml awid/uv.lock
   git commit -m "release: awid-service <VERSION>"
   git tag awid-service-v<VERSION>
   ```

7. Push to trigger publishing.
   ```bash
   git push origin main
   git push origin awid-service-v<VERSION>
   ```

## Notes

- Keep the git tag format as `awid-service-vX.Y.Z`.
- The workflow rejects tags that do not match `awid/pyproject.toml`.
- The GHCR Docker release (`awid-vX.Y.Z` tag) is separate and independent.
