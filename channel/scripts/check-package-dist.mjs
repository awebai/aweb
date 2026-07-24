#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url);
const distPath = join(root.pathname, "dist", "index.js");
const packagePath = join(root.pathname, "package.json");
const pluginPath = join(root.pathname, ".claude-plugin", "plugin.json");

const dist = readFileSync(distPath, "utf8");
const pkg = JSON.parse(readFileSync(packagePath, "utf8"));
const plugin = JSON.parse(readFileSync(pluginPath, "utf8"));

const certificateFirst = "const stableID = certificateStableID || identityStableID";
const staleIdentityFirst = "const stableID = (identity?.stable_id || \"\").trim() || (certificate.member_did_aw || \"\").trim()";
const appEventConsumer = 'case "app_event"';
const appAwakeningKind = 'kind: "app"';

if (pkg.version !== plugin.version) {
  throw new Error(`plugin version ${plugin.version} does not match package version ${pkg.version}`);
}

if (!dist.includes(certificateFirst)) {
  throw new Error(`channel dist is missing certificate-first stable_id resolution: ${certificateFirst}`);
}

if (dist.includes(staleIdentityFirst)) {
  throw new Error("channel dist still contains stale identity.yaml-first stable_id resolution");
}

if (!dist.includes(appEventConsumer) || !dist.includes(appAwakeningKind)) {
  throw new Error("channel dist is missing bundled app_event consumer wake dispatch");
}

// Freshness gate: the plugin bundle inlines channel-core via the file: symlink,
// so a stale channel-core/dist would silently ship the plugin WITHOUT merged
// security fixes. Each marker is a string that only exists once its fix is
// bundled from current channel-core src; a fresh build (prebuild rebuilds
// channel-core) contains them all. If any is missing, channel-core was bundled
// stale — rebuild it (npm run build in channel-core) and re-bundle.
const securityFixMarkers = [
  { task: "aajc.3 DID-log genesis/rotation authorization binding", marker: "not derived from genesis" },
  { task: "aajr TS full-log walk", marker: "audit log current did:key mismatch" },
  { task: "aajc.2 fail-closed trust pin store", marker: "refusing to start" },
];
for (const { task, marker } of securityFixMarkers) {
  if (!dist.includes(marker)) {
    throw new Error(
      `channel dist is missing ${task} (marker "${marker}") — channel-core was bundled stale; rebuild channel-core before packaging`,
    );
  }
}

console.log(`channel package dist is coherent for ${pkg.version}`);
