---
name: release
description: Prepare an aweb release for PyPI. Runs quality gates, bumps version, builds, verifies, commits, and pushes.
argument-hint: [version]
allowed-tools: Bash(uv run *), Bash(uv build *), Bash(git *), Bash(unzip *), Bash(ls *), Bash(rm -rf dist/*)
---

# Release aweb to PyPI

## Steps

1. **Determine version.** If $ARGUMENTS is provided, use it. Otherwise read the current version from pyproject.toml and ask what the new version should be.

2. **Verify clean state:**
   git status
   git log origin/main..HEAD --oneline
   Working tree must be clean and up to date with origin. If there are unpushed commits, show them and ask whether to proceed.

3. **Run quality gates** (all must pass):
   uv run pytest --tb=short -q
   uv run black --check src/ tests/
   uv run isort --check-only src/ tests/
   uv run ruff check src/ tests/
   uv run mypy src/ tests/

4. **Bump version** in pyproject.toml to the target version.

5. **Clean old artifacts and build:**
   rm -rf dist/
   uv build

6. **Verify the package:**
   - Check that dist/ contains exactly one .tar.gz and one .whl, both with the correct version in the filename.
   - List the wheel contents: unzip -l dist/aweb-<VERSION>-py3-none-any.whl
   - Confirm no unexpected files (credentials, .env, large binaries).
   - Report artifact filenames and sizes.

7. **Commit and push:**
   git add pyproject.toml uv.lock
   git commit -m "release: aweb <VERSION>"
   git push

8. **Report ready.** Tell the user the build artifacts are verified and ready. They can publish with uv publish.

## Version Format

MAJOR.MINOR.PATCH (no v prefix — Python package, not a git tag).
