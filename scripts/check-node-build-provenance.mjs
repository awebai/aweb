#!/usr/bin/env node
// Prove that each shipped Node bundle resolves channel-core's production
// dependencies from the exact channel-core lockfile used by the build.
import { createRequire } from "node:module";
import { existsSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const defaultRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const channelCorePackageName = "@awebai/channel-core";

function fail(message) {
  throw new Error(message);
}

function parseArgs(args) {
  let root = defaultRoot;
  const bundledPackages = [];
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === "--root") {
      root = path.resolve(args[++index] || fail("--root requires a path"));
    } else if (args[index] === "--package") {
      bundledPackages.push(args[++index] || fail("--package requires a name"));
    } else {
      fail(`unknown argument: ${args[index]}`);
    }
  }
  return { root, bundledPackages };
}

function readJSON(filename) {
  return JSON.parse(readFileSync(filename, "utf8"));
}

function discoverBundledPackages(root) {
  return readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && existsSync(path.join(root, entry.name, "package.json")))
    .filter((entry) => {
      const manifest = readJSON(path.join(root, entry.name, "package.json"));
      const linkedCore = manifest.dependencies?.[channelCorePackageName]
        || manifest.devDependencies?.[channelCorePackageName];
      return linkedCore === "file:../channel-core" && manifest.scripts?.build?.includes("--bundle");
    })
    .map((entry) => entry.name)
    .sort();
}

function isInside(parent, child) {
  const relative = path.relative(parent, child);
  return relative !== "" && !relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative);
}

function packageRootForEntry(entry, packageName) {
  let current = path.dirname(realpathSync(entry));
  while (true) {
    const manifest = path.join(current, "package.json");
    if (existsSync(manifest) && readJSON(manifest).name === packageName) return current;
    const parent = path.dirname(current);
    if (parent === current) fail(`could not find package.json for ${packageName} from ${entry}`);
    current = parent;
  }
}

function checkBundle(root, bundledPackage) {
  const bundleRoot = path.join(root, bundledPackage);
  const bundleManifest = path.join(bundleRoot, "package.json");
  const bundleLock = readJSON(path.join(bundleRoot, "package-lock.json"));
  const linkRecord = bundleLock.packages?.[`node_modules/${channelCorePackageName}`];
  if (linkRecord?.link !== true || linkRecord.resolved !== "../channel-core") {
    fail(`${bundledPackage}: package-lock.json must link ${channelCorePackageName} to ../channel-core`);
  }

  const bundleRequire = createRequire(bundleManifest);
  const resolvedCoreManifest = realpathSync(bundleRequire.resolve(`${channelCorePackageName}/package.json`));
  const coreRoot = realpathSync(path.join(root, "channel-core"));
  if (path.dirname(resolvedCoreManifest) !== coreRoot) {
    fail(`${bundledPackage}: ${channelCorePackageName} resolves to ${resolvedCoreManifest}, not ${coreRoot}`);
  }
  console.log(`${bundledPackage}: ${channelCorePackageName} -> ${coreRoot}`);

  const coreManifest = readJSON(resolvedCoreManifest);
  const coreLock = readJSON(path.join(coreRoot, "package-lock.json"));
  const coreRequire = createRequire(resolvedCoreManifest);
  const dependencyRoot = path.join(coreRoot, "node_modules");

  for (const dependency of Object.keys(coreManifest.dependencies || {}).sort()) {
    const lockedVersion = coreLock.packages?.[`node_modules/${dependency}`]?.version;
    if (!lockedVersion) fail(`${bundledPackage}: ${dependency} has no version in channel-core/package-lock.json`);

    const resolvedEntry = coreRequire.resolve(dependency);
    const resolvedRoot = packageRootForEntry(resolvedEntry, dependency);
    if (!isInside(dependencyRoot, resolvedRoot)) {
      fail(`${bundledPackage}: ${dependency} resolves outside channel-core/node_modules at ${resolvedRoot}`);
    }
    const resolvedVersion = readJSON(path.join(resolvedRoot, "package.json")).version;
    if (resolvedVersion !== lockedVersion) {
      fail(
        `${bundledPackage}: ${dependency} lockfile expects ${lockedVersion} but the build resolves ${resolvedVersion}`,
      );
    }
    console.log(`${bundledPackage}: ${dependency}@${resolvedVersion} (${resolvedRoot})`);
  }
}

try {
  const { root, bundledPackages: requestedPackages } = parseArgs(process.argv.slice(2));
  const bundledPackages = requestedPackages.length > 0
    ? requestedPackages
    : discoverBundledPackages(root);
  if (bundledPackages.length === 0) fail("no channel-core bundles found");
  for (const bundledPackage of bundledPackages) checkBundle(root, bundledPackage);
  console.log("Node bundle inputs match channel-core/package-lock.json.");
} catch (error) {
  console.error(`FAIL: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}
