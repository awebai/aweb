---
name: release-pi
description: Release @awebai/pi to npm, then deliver it to existing Pi caches and prove every affected runtime restarted on the published version.
argument-hint: [version]
allowed-tools: Bash(npm *), Bash(node *), Bash(git *), Bash(gh run *), Bash(pi *), Bash(aw *), Bash(pgrep *), Bash(ps *), Bash(lsof *)
---

# Release `@awebai/pi`

An npm publish is only half of this release. Pi loads user packages from its
own `~/.pi/agent/npm` tree, and a running process keeps extension code already
loaded in memory. Do not declare a runtime fix delivered until cache updates
and fresh-process evidence are recorded for every affected Pi host.

## Publish

1. Verify a clean branch based on current `origin/main` and determine the exact
   `MAJOR.MINOR.PATCH` version.
2. From `pi-extension/`, run:

   ```bash
   npm test
   npm run build
   npm run test:package
   npm pack --dry-run
   ```

   Confirm the tarball contains `dist/index.js`, `skills/`, `README.md`,
   `CHANGELOG.md`, and `package.json`, and excludes source, tests, and
   `node_modules`.
3. Bump `pi-extension/package.json`, its lockfile, and the changelog. Re-run the
   gates. Commit, obtain exact-SHA review, and merge through the coordinator.
4. Tag merged main as `pi-v<VERSION>` and push the tag. Watch
   `.github/workflows/pi-release.yml`, then verify the registry:

   ```bash
   gh run watch <run-id> --exit-status
   npm view @awebai/pi version
   ```

   The registry result proves publication only; it does not prove delivery.

## Deliver to every Pi host

1. Inventory active Pi processes before changing the cache:

   ```bash
   pgrep -x pi
   ps -p <pid> -o pid=,lstart=,command=
   lsof -a -p <pid> -d cwd -Fn
   ```

   Pi's process name is normally just `pi`; grepping for `@awebai/pi` misses
   it. Map each PID and cwd to its agent, coordinate a safe boundary with the
   owner, and preserve the session through that runtime's normal continuation
   path. Do not kill processes or manipulate tmux ad hoc.
2. On Pi 0.82 and newer, use Pi's narrow package update:

   ```bash
   pi update npm:@awebai/pi
   ```

   If `pi list` shows an exact semver-pinned source, replace it with
   `pi install npm:@awebai/pi@latest` first; exact pins are intentionally
   skipped by bulk updates. For pre-0.82 Pi without the update verb, use the
   cache fallback:

   ```bash
   npm install @awebai/pi@latest --prefix ~/.pi/agent/npm
   ```

   The native Pi command supersedes the raw npm command wherever it is
   available. Never substitute a global npm install; that updates the wrong
   tree.
3. Prove the resolved cache version from the package Pi actually loads:

   ```bash
   node -p "require(process.env.HOME + '/.pi/agent/npm/node_modules/@awebai/pi/package.json').version"
   ```

   It must equal `<VERSION>`. Do not accept `npm view`, a changelog, a package
   self-report, or a process grep as cache-version proof.
4. Fully stop and restart each affected Pi process. `/reload` can refresh
   resources in current Pi, but it is not release-cutover proof; only a fresh
   process proves no old extension code remains in memory.
5. Record the proof tuple for each runtime: host, agent/cwd, resolved
   package.json version, old PID, new PID/start time, and confirmation that the
   new process started after the cache update. The fresh process plus the
   resolved cache version is the loaded-version proof.

## Understand the startup warning

Pi 0.82+ checks unpinned packages asynchronously at startup. A stale install
shows a panel headed `Package Updates Available`, followed by `Package updates
are available. Run pi update --extensions` and the package list.

Seeing that warning means the running session loaded stale extension code at
startup. Updating `~/.pi/agent/npm` in another terminal can make package.json
current while that process remains stale. Fully restart it; do not mistake the
fresh cache for a fresh runtime.

## Launcher boundary

`aw team up` and `aw team add --start` install `@awebai/pi` when missing but
deliberately do not auto-update already-installed executable code. Silent
launcher-time updates add consent, latency, and offline-failure hazards and
would still not replace code in a process already running. The release owner,
not the launcher, owns the explicit cache update and restart cutover.
