import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  cpSync,
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

  const expectedVersion = JSON.parse(
    readFileSync(path.join(repoRoot, "channel-core", "package-lock.json"), "utf8"),
  ).packages["node_modules/js-yaml"].version;
  const coreRoot = realpathSync(path.join(repoRoot, "channel-core"));
  const checkerOutput = output(result);
  for (const bundledPackage of ["channel", "pi-extension"]) {
    assert.ok(checkerOutput.includes(`${bundledPackage}: @awebai/channel-core -> ${coreRoot}`));
    assert.ok(checkerOutput.includes(`${bundledPackage}: js-yaml@${expectedVersion} `));
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
    lock.packages["node_modules/js-yaml"].version = "0.0.0";
    writeFileSync(path.join(fixtureCore, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);

    const dependencies = Object.keys(
      JSON.parse(readFileSync(path.join(sourceCore, "package.json"), "utf8")).dependencies,
    );
    for (const dependency of dependencies) {
      const source = path.join(sourceCore, "node_modules", ...dependency.split("/"));
      const target = path.join(fixtureCore, "node_modules", ...dependency.split("/"));
      mkdirSync(path.dirname(target), { recursive: true });
      cpSync(source, target, { recursive: true });
    }

    const fixtureBundle = path.join(fixtureRoot, "future-bundle");
    mkdirSync(path.join(fixtureBundle, "node_modules", "@awebai"), { recursive: true });
    cpSync(path.join(repoRoot, "channel", "package.json"), path.join(fixtureBundle, "package.json"));
    cpSync(
      path.join(repoRoot, "channel", "package-lock.json"),
      path.join(fixtureBundle, "package-lock.json"),
    );
    symlinkSync(
      fixtureCore,
      path.join(fixtureBundle, "node_modules", "@awebai", "channel-core"),
      "dir",
    );

    const result = runChecker(["--root", fixtureRoot]);
    const resolvedVersion = JSON.parse(
      readFileSync(path.join(sourceCore, "node_modules", "js-yaml", "package.json"), "utf8"),
    ).version;
    assert.notEqual(result.status, 0, output(result));
    assert.ok(
      output(result).includes(
        `future-bundle: js-yaml lockfile expects 0.0.0 but the build resolves ${resolvedVersion}`,
      ),
      output(result),
    );
  } finally {
    rmSync(fixtureRoot, { recursive: true, force: true });
  }
});
