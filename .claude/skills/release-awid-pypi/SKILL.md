---
name: release-awid-pypi
description: Prepare an awid-service release for PyPI. Runs quality gates, bumps version, builds, verifies, commits, tags, and pushes. The CI workflow then publishes to PyPI.
argument-hint: [version]
---

# Release awid-service to PyPI

The PyPI release is triggered by pushing an `awid-service-vX.Y.Z` git tag.
GitHub Actions then runs
[`.github/workflows/awid-pypi-release.yml`](../../../.github/workflows/awid-pypi-release.yml),
which builds from `awid/` and publishes with `uv publish`.

## Flow

1. Determine the next version.
   Use `awid/pyproject.toml` as the source of truth.

2. Verify the tree is ready.
   Run `git status` and make sure the intended release commit is on `main`.

3. Run release checks.
   ```bash
   cd awid && uv sync && uv run pytest awid/tests -q
   uv build
   ```

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
