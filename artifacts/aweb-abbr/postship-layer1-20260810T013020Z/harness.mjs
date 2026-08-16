import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFile, realpath, writeFile } from "node:fs/promises";
import { basename, dirname, join, posix } from "node:path";
import { pathToFileURL } from "node:url";

const OBSERVABILITY_SUFFIX = Buffer.from(
  "\nexport { SenderTrustManager as __artifact_SenderTrustManager, PinStore as __artifact_PinStore, computeDIDKey as __artifact_computeDIDKey };\n"
  + "export const __artifact_url = import.meta.url;\n",
  "utf8",
);

function digest(algorithm, bytes, encoding = "hex") {
  return createHash(algorithm).update(bytes).digest(encoding);
}

function validateArchive(tarball) {
  const listing = execFileSync("tar", ["-tzf", tarball], { encoding: "utf8" });
  const seen = new Set();
  for (const rawEntry of listing.split("\n")) {
    if (!rawEntry) continue;
    assert(!rawEntry.includes("\\"), `archive entry uses backslash: ${rawEntry}`);
    assert(!rawEntry.startsWith("/"), `archive entry is absolute: ${rawEntry}`);
    const normalized = posix.normalize(rawEntry.replace(/\/$/, ""));
    assert(normalized !== "." && normalized !== ".." && !normalized.startsWith("../"), `unsafe archive entry: ${rawEntry}`);
    assert(!seen.has(normalized), `duplicate normalized archive entry: ${normalized}`);
    seen.add(normalized);
  }
  assert(seen.has("package/dist/index.js"), "archive lacks package/dist/index.js");
  assert(seen.has("package/package.json"), "archive lacks package/package.json");
}

function readTarEntry(tarball, entry) {
  return execFileSync("tar", ["-xOzf", tarball, entry], {
    encoding: "buffer",
    maxBuffer: 16 * 1024 * 1024,
  });
}

async function verifyPackage({ label, tarball, metadataPath, expectedVersion }) {
  const metadata = JSON.parse(await readFile(metadataPath, "utf8"));
  assert.equal(metadata.version, expectedVersion);
  const tarballBytes = await readFile(tarball);
  const [integrityAlgorithm, expectedIntegrity] = metadata.dist.integrity.split("-", 2);
  assert.equal(digest(integrityAlgorithm, tarballBytes, "base64"), expectedIntegrity, `${label}: dist.integrity mismatch`);
  assert.equal(digest("sha1", tarballBytes), metadata.dist.shasum, `${label}: dist.shasum mismatch`);

  validateArchive(tarball);
  const packageJSONBytes = readTarEntry(tarball, "package/package.json");
  const packageJSON = JSON.parse(packageJSONBytes.toString("utf8"));
  assert.equal(packageJSON.name, metadata.name);
  assert.equal(packageJSON.version, expectedVersion);

  const original = readTarEntry(tarball, "package/dist/index.js");
  const copy = Buffer.concat([original, OBSERVABILITY_SUFFIX]);
  const copyPath = join(dirname(tarball), `${label}-shipped-observable.mjs`);
  await writeFile(copyPath, copy, { mode: 0o600 });
  const readBack = await readFile(copyPath);
  assert.equal(readBack.length, original.length + OBSERVABILITY_SUFFIX.length, `${label}: copied length changed`);
  assert(readBack.subarray(0, original.length).equals(original), `${label}: shipped bundle prefix changed`);
  assert(readBack.subarray(original.length).equals(OBSERVABILITY_SUFFIX), `${label}: observability suffix changed`);

  const bundleURL = pathToFileURL(await realpath(copyPath)).href;
  const shipped = await import(bundleURL);
  assert.equal(shipped.__artifact_url, bundleURL, `${label}: loader did not import the observable shipped copy`);
  assert.equal(typeof shipped.__artifact_SenderTrustManager, "function");
  assert.equal(typeof shipped.__artifact_PinStore, "function");
  assert.equal(typeof shipped.__artifact_computeDIDKey, "function");

  const aliases = ["alice", "bob", "carol", "dave"];
  const dids = aliases.map((_alias, index) => shipped.__artifact_computeDIDKey(new Uint8Array(32).fill(index + 1)));
  const teamID = "artifact:aweb.test";
  let finishRoster;
  const rosterPending = new Promise((resolve) => { finishRoster = resolve; });
  const requests = [];
  const client = {
    hasTeamCertificateAuth: (candidateTeamID) => candidateTeamID === teamID,
    get: (path) => {
      requests.push(path);
      return rosterPending;
    },
  };
  const registry = {
    resolveIdentity: async () => { throw new Error("public registry must not be used for team aliases"); },
    verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }),
  };
  const trust = new shipped.__artifact_SenderTrustManager(client, registry, teamID, "");

  const resolutions = aliases.map((alias) => trust.resolveTrustMetadata("verified", alias, undefined, undefined, undefined));
  assert.deepEqual(requests, ["/v1/agents"], `${label}: concurrent aliases did not single-flight before response`);
  finishRoster({
    team_id: teamID,
    agents: aliases.map((alias, index) => ({
      alias,
      did_key: dids[index],
      identity_scope: "local",
      custody: "self",
    })),
  });
  const resolved = await Promise.all(resolutions);
  const decisions = await Promise.all(aliases.map((alias, index) => trust.normalizeTrust(
    new shipped.__artifact_PinStore(),
    "verified",
    alias,
    dids[index],
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    resolved[index],
  )));
  assert.equal(requests.length, 1, `${label}: trust decisions reissued the roster request`);
  assert(decisions.every((decision) => decision.status === "verified"), `${label}: a trust decision did not verify`);

  return {
    label,
    package_name: metadata.name,
    version: packageJSON.version,
    registry_tarball: metadata.dist.tarball,
    registry_integrity: metadata.dist.integrity,
    tarball_sha256: digest("sha256", tarballBytes),
    bundle_sha256: digest("sha256", original),
    loaded_bundle_url: shipped.__artifact_url,
    aliases: aliases.length,
    roster_request_path: requests[0],
    roster_request_count: requests.length,
    trust_statuses: decisions.map((decision) => decision.status),
  };
}

const runDir = process.argv[2];
assert(runDir, "usage: node layer1-harness.mjs RUN_DIR");
const results = [];
results.push(await verifyPackage({
  label: "channel-1.7.5",
  tarball: join(runDir, "channel.tgz"),
  metadataPath: join(runDir, "channel-metadata.json"),
  expectedVersion: "1.7.5",
}));
results.push(await verifyPackage({
  label: "pi-0.3.5",
  tarball: join(runDir, "pi.tgz"),
  metadataPath: join(runDir, "pi-metadata.json"),
  expectedVersion: "0.3.5",
}));
const output = {
  schema: "aweb.abbr.postship-layer1.v1",
  generated_at: new Date().toISOString(),
  harness_path: new URL(import.meta.url).pathname,
  results,
};
await writeFile(join(runDir, "results.json"), `${JSON.stringify(output, null, 2)}\n`, { mode: 0o600 });
process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
