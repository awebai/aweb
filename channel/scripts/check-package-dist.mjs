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

if (pkg.version !== plugin.version) {
  throw new Error(`plugin version ${plugin.version} does not match package version ${pkg.version}`);
}

if (!dist.includes(certificateFirst)) {
  throw new Error(`channel dist is missing certificate-first stable_id resolution: ${certificateFirst}`);
}

if (dist.includes(staleIdentityFirst)) {
  throw new Error("channel dist still contains stale identity.yaml-first stable_id resolution");
}

console.log(`channel package dist is coherent for ${pkg.version}`);
