---
name: release-awid-docker
description: Release awid as a Docker image to GHCR. Tags awid-vX.Y.Z which triggers the Docker build workflow.
argument-hint: [version]
---

# Release awid Docker image

The Docker release is triggered by pushing an `awid-vX.Y.Z` tag.
GitHub Actions runs `.github/workflows/awid-release.yml`, which
builds `Dockerfile.release` and pushes to GHCR.

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
