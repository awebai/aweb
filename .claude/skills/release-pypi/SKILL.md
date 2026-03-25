---
name: release-pypi
description: Prepare an aweb server release for PyPI. Runs quality gates, bumps version, builds, verifies, commits, tags, and pushes. The CI workflow then publishes to PyPI.
argument-hint: [version]
allowed-tools: Bash(uv run *), Bash(uv build *), Bash(git *), Bash(unzip *), Bash(ls *), Bash(rm -rf server/dist/*)
---

# Release aweb server to PyPI

## Steps

1. **Determine version.** If $ARGUMENTS is provided, use it. Otherwise read the current version from server/pyproject.toml and ask what the new version should be.

2. **Verify clean state:**
   git status
   git log origin/main..HEAD --oneline
   Working tree must be clean and up to date with origin. If there are unpushed commits, show them and ask whether to proceed.

3. **Run quality gates** (all must pass, run from server/):
   uv run pytest --tb=short -q

4. **Bump version** in server/pyproject.toml to the target version. This is the only place the package version lives.

5. **Clean old artifacts and build** (from server/):
   rm -rf server/dist/
   cd server && uv build

6. **Verify the package:**
   - Check that server/dist/ contains exactly one .tar.gz and one .whl, both with the correct version in the filename.
   - List the wheel contents: unzip -l server/dist/aweb-<VERSION>-py3-none-any.whl
   - Confirm migrations, defaults, and package data are included.
   - Confirm no unexpected files (credentials, .env, large binaries).
   - Report artifact filenames and sizes.

7. **Commit, tag, and push:**
   git add server/pyproject.toml
   git commit -m "release: aweb server <VERSION>"
   git tag server-v<VERSION>
   git push origin main
   git push origin server-v<VERSION>

   The tag push triggers .github/workflows/server-release.yml which runs uv build + uv publish with the PYPI_TOKEN secret.

8. **Report.** Tell the user the tag is pushed and the CI workflow will publish to PyPI. Link to the workflow run at https://github.com/awebai/aweb/actions

## Version Format

MAJOR.MINOR.PATCH (no v prefix in pyproject.toml — the git tag uses server-v prefix).
