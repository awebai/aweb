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
// so a stale channel-core/dist would silently ship the plugin WITHOUT the
// hardened security surface. Assert the channel-core security-contract sentinel
// (a stable exported constant, re-exported by channel/src/index.ts so it is
// bundled) is present. Unlike matching error-message text, the sentinel changes
// only on an intentional contract revision, so this gate cannot silently weaken
// when unrelated error wording changes.
const securityContractSentinel =
  "aweb-channel-core-security/did-log-genesis-bound-v2+full-log-v1+pinstore-fail-closed-v1";
if (!dist.includes(securityContractSentinel)) {
  throw new Error(
    `channel dist is missing the channel-core security-contract sentinel (${securityContractSentinel}) — channel-core was bundled stale, or the contract changed without updating this gate. Rebuild channel-core; if the contract intentionally changed, update both channel-core/src/contract.ts and this sentinel.`,
  );
}

console.log(`channel package dist is coherent for ${pkg.version}`);
