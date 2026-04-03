---
name: release-pypi
description: Prepare an aweb server release for PyPI. Runs quality gates, bumps version, builds, verifies, commits, tags, and pushes. The CI workflow then publishes to PyPI.
argument-hint: [version]
---

# Release aweb server to PyPI

The PyPI release is triggered by pushing a `server-vX.Y.Z` git tag. GitHub
Actions then runs [`.github/workflows/server-release.yml`](../../../.github/workflows/server-release.yml),
which builds from `server/` and publishes with `uv publish`.

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

## Notes

- Keep the git tag format as `server-vX.Y.Z`.
- The workflow rejects tags that do not match `server/pyproject.toml`.
- `server/uv.lock` should stay aligned with the package version metadata.
