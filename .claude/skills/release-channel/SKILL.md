---
name: release-channel
description: Prepare an @awebai/claude-channel npm release. Runs quality gates, bumps versions in both the channel package and the awebai/claude-plugins marketplace, commits, tags, and pushes. The CI workflow then publishes to npm.
argument-hint: [version]
allowed-tools: Bash(npm *), Bash(node *), Bash(git *), Bash(ls *), Bash(cat *), Bash(rm -rf channel/dist/*), Bash(gh run *)
---

# Release @awebai/claude-channel to npm

The release has two parts that **must** both happen for users to receive the upgrade:

1. **npm publish** — driven by tagging `channel-v<VERSION>` in the aweb repo. CI publishes the package.
2. **marketplace bump** — the sibling repo `awebai/claude-plugins` must have its `marketplace.json` `version` field bumped to the same `<VERSION>`. Without this, `claude plugin update` reports "already at the latest version" no matter what's published on npm.

The marketplace repo is expected to be cloned at `../claude-plugins` (sibling of the aweb repo).

## Steps

1. **Determine version.** If $ARGUMENTS is provided, use it. Otherwise read the current version from `channel/package.json` and ask what the new version should be.

2. **Verify clean state** in both repos:
   ```
   git -C . status
   git -C . log origin/main..HEAD --oneline
   git -C ../claude-plugins status
   git -C ../claude-plugins log origin/main..HEAD --oneline
   ```
   Both working trees must be clean and up to date with origin. If `../claude-plugins` is missing, ask the user to clone it first.

3. **Run quality gates** (all must pass, run from `channel/`):
   ```
   npm test
   npm run build
   ```

4. **Bump version** in `channel/package.json`:
   ```
   cd channel && npm version <VERSION> --no-git-tag-version
   npm run sync-plugin-version
   ```
   This updates `package.json`, `package-lock.json`, and `.claude-plugin/plugin.json`.

5. **Verify the package:**
   - `cd channel && npm pack --dry-run`
   - Confirm `dist/index.js` is present.
   - Confirm tarball contains `dist/`, `.claude-plugin/plugin.json`, `.mcp.json`, `README.md`, `package.json`, `skills/`.
   - Confirm `.mcp.json` has the `mcpServers` wrapper (not just `{"aweb": {...}}`) — this was a bug in 1.1.0–1.3.0.
   - Confirm no unexpected files (no `node_modules`, no `test/`, no `src/`).

6. **Commit, tag, and push the channel release:**
   ```
   git add channel/package.json channel/package-lock.json channel/.claude-plugin/plugin.json
   git commit -m "release: @awebai/claude-channel <VERSION>"
   git tag channel-v<VERSION>
   git push origin <current-branch>:main
   git push origin channel-v<VERSION>
   ```
   The tag push triggers `.github/workflows/channel-release.yml` which runs `npm publish`.

7. **Wait for npm publish to land.** Watch the workflow:
   ```
   gh run watch <run-id> --exit-status
   ```
   Then verify:
   ```
   npm view @awebai/claude-channel version
   ```
   should print `<VERSION>`.

8. **Bump the marketplace** in the sibling repo:
   ```
   # in ../claude-plugins
   # edit .claude-plugin/marketplace.json: set plugins[0].source.version = "<VERSION>"
   git add .claude-plugin/marketplace.json
   git commit -m "pin aweb-channel npm version to <VERSION>"
   git push origin main
   ```

9. **Report.** Tell the user:
   - The npm tag is published at `https://www.npmjs.com/package/@awebai/claude-channel/v/<VERSION>`.
   - The marketplace pin is pushed to `awebai/claude-plugins`.
   - Customer upgrade path: `/plugin marketplace update awebai-marketplace && /plugin update aweb-channel@awebai-marketplace`.

## Version Format

MAJOR.MINOR.PATCH (no `v` prefix in `package.json` — the git tag uses `channel-v` prefix).

## Why both bumps are required

Claude Code resolves a plugin's version from (1) `plugin.json` inside the published package, (2) the marketplace entry's `version` field, (3) git SHA, (4) `unknown` for npm sources without an explicit version (`https://code.claude.com/docs/en/plugins-reference.md#version-management`).

For `npm` sources, `claude plugin update` only re-resolves the npm registry when the marketplace entry advertises a version. Bumping the package alone is invisible to existing installs.
