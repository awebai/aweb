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

function realFileDependencyTarget(packageRoot, specifier) {
  if (typeof specifier !== "string" || !specifier.startsWith("file:")) return undefined;
  return realpathSync(path.resolve(packageRoot, specifier.slice("file:".length)));
}

function discoverBundledPackages(root) {
  const coreRoot = realpathSync(path.join(root, "channel-core"));
  const bundledPackages = [];
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.name === "node_modules" || entry.name === ".git") continue;
      const directory = path.join(current, entry.name);
      pending.push(directory);
      const manifestPath = path.join(directory, "package.json");
      if (!existsSync(manifestPath)) continue;
      const manifest = readJSON(manifestPath);
      const linkedCore = manifest.dependencies?.[channelCorePackageName]
        || manifest.devDependencies?.[channelCorePackageName];
      if (realFileDependencyTarget(directory, linkedCore) === coreRoot) {
        bundledPackages.push(path.relative(root, directory).split(path.sep).join("/"));
      }
    }
  }
  return bundledPackages.sort();
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

function dependencyEdges(lockRecord) {
  const edges = Object.keys(lockRecord.dependencies || {}).map((name) => [name, false]);
  for (const name of Object.keys(lockRecord.optionalDependencies || {})) {
    if (!lockRecord.dependencies?.[name]) edges.push([name, true]);
  }
  return edges.sort(([left], [right]) => left.localeCompare(right));
}

function checkDependency(
  bundledPackage,
  coreRoot,
  coreLock,
  parentManifest,
  dependency,
  optional,
  visited,
) {
  const parentRequire = createRequire(parentManifest);
  let resolvedEntry;
  try {
    resolvedEntry = parentRequire.resolve(dependency);
  } catch (error) {
    if (optional) return;
    throw error;
  }
  const resolvedRoot = packageRootForEntry(resolvedEntry, dependency);
  const dependencyRoot = path.join(coreRoot, "node_modules");
  if (!isInside(dependencyRoot, resolvedRoot)) {
    fail(`${bundledPackage}: ${dependency} resolves outside channel-core/node_modules at ${resolvedRoot}`);
  }

  const lockPath = path.relative(coreRoot, resolvedRoot).split(path.sep).join("/");
  const lockRecord = coreLock.packages?.[lockPath];
  if (!lockRecord?.version) {
    fail(`${bundledPackage}: ${dependency} resolved at ${lockPath} but has no channel-core lock record`);
  }
  const resolvedManifest = path.join(resolvedRoot, "package.json");
  const resolvedVersion = readJSON(resolvedManifest).version;
  if (resolvedVersion !== lockRecord.version) {
    fail(
      `${bundledPackage}: ${dependency} lockfile expects ${lockRecord.version} but the build resolves ${resolvedVersion}`,
    );
  }
  if (visited.has(resolvedRoot)) return;
  visited.add(resolvedRoot);
  console.log(`${bundledPackage}: ${dependency}@${resolvedVersion} (${resolvedRoot})`);

  for (const [child, childIsOptional] of dependencyEdges(lockRecord)) {
    checkDependency(
      bundledPackage,
      coreRoot,
      coreLock,
      resolvedManifest,
      child,
      childIsOptional,
      visited,
    );
  }
}

function checkBundle(root, bundledPackage) {
  const bundleRoot = path.join(root, bundledPackage);
  const bundleManifest = path.join(bundleRoot, "package.json");
  const bundlePackage = readJSON(bundleManifest);
  const linkedCore = bundlePackage.dependencies?.[channelCorePackageName]
    || bundlePackage.devDependencies?.[channelCorePackageName];
  const coreRoot = realpathSync(path.join(root, "channel-core"));
  if (realFileDependencyTarget(bundleRoot, linkedCore) !== coreRoot) {
    fail(`${bundledPackage}: package.json must file-link ${channelCorePackageName} to ${coreRoot}`);
  }

  const bundleLock = readJSON(path.join(bundleRoot, "package-lock.json"));
  const lockRoot = bundleLock.packages?.[""];
  const lockedCore = lockRoot?.dependencies?.[channelCorePackageName]
    || lockRoot?.devDependencies?.[channelCorePackageName];
  const linkRecord = bundleLock.packages?.[`node_modules/${channelCorePackageName}`];
  if (
    realFileDependencyTarget(bundleRoot, lockedCore) !== coreRoot
    || linkRecord?.link !== true
    || realpathSync(path.resolve(bundleRoot, linkRecord.resolved || "")) !== coreRoot
  ) {
    fail(`${bundledPackage}: package-lock.json must file-link ${channelCorePackageName} to ${coreRoot}`);
  }

  const bundleRequire = createRequire(bundleManifest);
  const resolvedCoreManifest = realpathSync(bundleRequire.resolve(`${channelCorePackageName}/package.json`));
  if (path.dirname(resolvedCoreManifest) !== coreRoot) {
    fail(`${bundledPackage}: ${channelCorePackageName} resolves to ${resolvedCoreManifest}, not ${coreRoot}`);
  }
  console.log(`${bundledPackage}: ${channelCorePackageName} -> ${coreRoot}`);

  const coreLock = readJSON(path.join(coreRoot, "package-lock.json"));
  const rootRecord = coreLock.packages?.[""];
  if (!rootRecord) fail(`${bundledPackage}: channel-core/package-lock.json has no root package`);
  const visited = new Set();
  for (const [dependency, optional] of dependencyEdges(rootRecord)) {
    checkDependency(
      bundledPackage,
      coreRoot,
      coreLock,
      resolvedCoreManifest,
      dependency,
      optional,
      visited,
    );
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
