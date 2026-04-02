---
name: release-channel
description: Prepare an @awebai/claude-channel npm release. Runs quality gates, bumps version, builds, verifies, commits, tags, and pushes. The CI workflow then publishes to npm.
argument-hint: [version]
allowed-tools: Bash(npm *), Bash(node *), Bash(git *), Bash(ls *), Bash(cat *), Bash(rm -rf channel/dist/*)
---

# Release @awebai/claude-channel to npm

## Steps

1. **Determine version.** If $ARGUMENTS is provided, use it. Otherwise read the current version from channel/package.json and ask what the new version should be.

2. **Verify clean state:**
   git status
   git log origin/main..HEAD --oneline
   Working tree must be clean and up to date with origin. If there are unpushed commits, show them and ask whether to proceed.

3. **Run quality gates** (all must pass, run from channel/):
   npm test
   npm run build

4. **Bump version** in channel/package.json to the target version.
   cd channel && npm version <VERSION> --no-git-tag-version
   This updates both package.json and package-lock.json.

5. **Verify the package:**
   - cd channel && npm pack --dry-run
   - Confirm dist/ contains compiled JS files
   - Confirm package contents include dist/, README.md, package.json
   - Confirm no unexpected files (node_modules, test/, src/)
   - Report package name and size

6. **Commit, tag, and push:**
   git add channel/package.json channel/package-lock.json
   git commit -m "release: @awebai/claude-channel <VERSION>"
   git tag channel-v<VERSION>
   git push origin main
   git push origin channel-v<VERSION>

   The tag push triggers .github/workflows/channel-release.yml which runs npm publish with the NPM_TOKEN secret.

7. **Report.** Tell the user the tag is pushed and the CI workflow will publish to npm. Link to the workflow run at https://github.com/awebai/aweb/actions

## Version Format

MAJOR.MINOR.PATCH (no v prefix in package.json — the git tag uses channel-v prefix).
