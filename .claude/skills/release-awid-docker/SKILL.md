---
name: release-awid-docker
description: Release awid as a Docker image to GHCR. Tags awid-vX.Y.Z which triggers the Docker build workflow.
argument-hint: [version]
---

# Release awid Docker image

The Docker release is triggered by pushing an `awid-vX.Y.Z` tag.
GitHub Actions runs `.github/workflows/awid-release.yml`, which runs
`make release-awid-image-gate` against the tagged commit and only then
builds `Dockerfile.release` and pushes to GHCR.

## The push refuses unless the suite passed on the tagged commit

A tag can be moved, but a consumer that already pulled it cannot be reached. So
the workflow runs the awid suite in the same job as the push, against the tree
the tag points at.

The gate is `make release-awid-image-gate`: `uv lock --check` and the awid suite
against that committed lock. It deliberately does **not** build the image. The
publishing build already gates — `build-push-action` cannot push an image that
fails to build — and it is the only build covering both published platforms, so
a separate verification build would check `linux/amd64` while `linux/arm64`
shipped unverified.

`uv lock --check` verifies the lockfile rather than repairing it. Step 2 below
is where repair belongs; commit that result before you tag.

### What the gate does not cover

A tag push is the only trigger, and re-running the workflow re-runs the gate, so
this route is covered. Two routes are not, and neither can be closed from inside
this repository:

- An `awid-v*` tag cut at a commit where the gate step was edited out. A
  tag-triggered workflow runs the file as it exists at the tagged commit, and
  `main` cannot be branch-protected here.
- A direct `docker push` to `ghcr.io/awebai/awid` by anyone whose credential
  carries `packages: write` for the org.

Pushing the image off-CI is not a supported path. Use the tag.

## Flow

1. Determine the version.
   Use `awid/pyproject.toml` as the source of truth.

2. Sync uv.lock.
   The Docker build uses `uv sync --locked`. If uv.lock is stale
   the build fails with "The lockfile at uv.lock needs to be updated."
   ```bash
   cd awid && uv lock
   ```

3. Run tests.
   ```bash
   cd /path/to/aweb && uv run --project awid pytest awid/tests -q
   ```

4. Run Docker build check.
   ```bash
   make release-awid-check
   ```

5. Bump version, commit, tag.
   ```bash
   git add awid/pyproject.toml awid/uv.lock
   git commit -m "release: awid-service <VERSION>"
   git tag awid-v<VERSION>
   git tag awid-service-v<VERSION>
   ```

6. Push.
   ```bash
   git push origin main
   git push origin awid-v<VERSION>
   git push origin awid-service-v<VERSION>
   ```

## Critical: uv.lock must be in sync

If you bump the version in pyproject.toml without running `uv lock`,
the Docker build will fail. This happened with awid 0.2.5. Always
run `uv lock` after version bumps.

## Critical: do not retag on PyPI

PyPI is immutable. If you tag awid-service-vX.Y.Z, it publishes.
If you then force-push the tag to a different commit, PyPI rejects
the second publish (version already exists). Bump the version
instead (e.g., 0.2.5 -> 0.2.6). This happened with awid 0.2.5/0.2.6.

## Notes

- The Docker tag (`awid-vX.Y.Z`) and PyPI tag (`awid-service-vX.Y.Z`)
  are separate workflows but usually created together.
- `make release-awid-check` runs tests, builds the package, and does
  a local Docker build to verify.
