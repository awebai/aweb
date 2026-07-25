import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const checker = path.join(repoRoot, "scripts", "check-node-build-provenance.mjs");

function runChecker(args = []) {
  return spawnSync(process.execPath, [checker, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
  });
}

function output(result) {
  return `${result.stdout}${result.stderr}`;
}

test("accepts bundled dependencies resolved through channel-core at their locked versions", () => {
  const result = runChecker();
  assert.equal(result.status, 0, output(result));

  const ownerLock = JSON.parse(
    readFileSync(path.join(repoRoot, "channel-core", "package-lock.json"), "utf8"),
  );
  const expectedVersion = ownerLock.packages["node_modules/js-yaml"].version;
  const expectedTransitiveVersion = ownerLock.packages["node_modules/tldts-core"].version;
  const coreRoot = realpathSync(path.join(repoRoot, "channel-core"));
  const checkerOutput = output(result);
  for (const bundledPackage of ["channel", "pi-extension"]) {
    assert.ok(checkerOutput.includes(`${bundledPackage}: @awebai/channel-core -> ${coreRoot}`));
    assert.ok(checkerOutput.includes(`${bundledPackage}: js-yaml@${expectedVersion} `));
    assert.ok(
      checkerOutput.includes(`${bundledPackage}: tldts-core@${expectedTransitiveVersion} `),
      `${bundledPackage} did not verify the production transitive closure`,
    );
  }
});

test("bundle builds and the Node audit invoke the provenance gate", () => {
  for (const bundledPackage of ["channel", "pi-extension"]) {
    const manifest = JSON.parse(
      readFileSync(path.join(repoRoot, bundledPackage, "package.json"), "utf8"),
    );
    assert.match(
      manifest.scripts.prebuild,
      /check-node-build-provenance\.mjs/,
      `${bundledPackage} build bypasses the provenance gate`,
    );
  }

  const auditGate = readFileSync(path.join(repoRoot, "scripts", "check-node-audit.sh"), "utf8");
  assert.match(auditGate, /check-node-build-provenance\.mjs/);
  assert.match(auditGate, /test-node-build-provenance\.mjs/);
});

test("artifact-producing install paths use the committed lockfiles", () => {
  const artifactProducers = [
    ".github/workflows/channel-release.yml",
    ".github/workflows/pi-release.yml",
    "Makefile",
    "scripts/e2e-oss-user-journey.sh",
  ];
  for (const filename of artifactProducers) {
    const source = readFileSync(path.join(repoRoot, filename), "utf8");
    assert.match(source, /npm ci/, `${filename} does not install from the lockfile`);
    assert.doesNotMatch(source, /npm install(?:\s|$)/, `${filename} can resolve outside the lockfile`);
  }
});

test("rejects a resolved dependency that differs from the owner lockfile for that reason", () => {
  const fixtureRoot = mkdtempSync(path.join(os.tmpdir(), "node-build-provenance-"));
  try {
    const sourceCore = path.join(repoRoot, "channel-core");
    const fixtureCore = path.join(fixtureRoot, "channel-core");
    mkdirSync(path.join(fixtureCore, "node_modules"), { recursive: true });
    cpSync(path.join(sourceCore, "package.json"), path.join(fixtureCore, "package.json"));

    const lock = JSON.parse(readFileSync(path.join(sourceCore, "package-lock.json"), "utf8"));
    const lockedTransitiveVersion = lock.packages["node_modules/tldts-core"].version;
    writeFileSync(path.join(fixtureCore, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);

    for (const [lockPath, record] of Object.entries(lock.packages)) {
      if (!lockPath.startsWith("node_modules/") || record.dev) continue;
      const source = path.join(sourceCore, ...lockPath.split("/"));
      if (!existsSync(source)) continue;
      const target = path.join(fixtureCore, ...lockPath.split("/"));
      mkdirSync(path.dirname(target), { recursive: true });
      cpSync(source, target, { recursive: true });
    }
    const transitiveManifest = path.join(
      fixtureCore,
      "node_modules",
      "tldts-core",
      "package.json",
    );
    const transitive = JSON.parse(readFileSync(transitiveManifest, "utf8"));
    transitive.version = "0.0.0-review-drift";
    writeFileSync(transitiveManifest, `${JSON.stringify(transitive, null, 2)}\n`);

    const fixtureBundle = path.join(fixtureRoot, "packages", "review-future");
    mkdirSync(path.join(fixtureBundle, "node_modules", "@awebai"), { recursive: true });
    const bundleManifest = JSON.parse(
      readFileSync(path.join(repoRoot, "channel", "package.json"), "utf8"),
    );
    bundleManifest.devDependencies["@awebai/channel-core"] = "file:../../channel-core";
    writeFileSync(
      path.join(fixtureBundle, "package.json"),
      `${JSON.stringify(bundleManifest, null, 2)}\n`,
    );
    const bundleLock = JSON.parse(
      readFileSync(path.join(repoRoot, "channel", "package-lock.json"), "utf8"),
    );
    bundleLock.packages[""].devDependencies["@awebai/channel-core"] = "file:../../channel-core";
    bundleLock.packages["node_modules/@awebai/channel-core"].resolved = "../../channel-core";
    writeFileSync(
      path.join(fixtureBundle, "package-lock.json"),
      `${JSON.stringify(bundleLock, null, 2)}\n`,
    );
    symlinkSync(
      fixtureCore,
      path.join(fixtureBundle, "node_modules", "@awebai", "channel-core"),
      "dir",
    );

    const result = runChecker(["--root", fixtureRoot]);
    assert.notEqual(result.status, 0, output(result));
    assert.ok(
      output(result).includes(
        `packages/review-future: tldts-core lockfile expects ${lockedTransitiveVersion} but the build resolves 0.0.0-review-drift`,
      ),
      output(result),
    );
  } finally {
    rmSync(fixtureRoot, { recursive: true, force: true });
  }
});
